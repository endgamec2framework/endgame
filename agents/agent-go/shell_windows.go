//go:build windows

package agent

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// makeShellCmd builds a cmd.exe invocation that survives pipes and quotes.
//
// Go's exec.Command escapes args using C-style rules (\" for embedded quotes),
// but cmd.exe uses its own rules (doubled "" inside quoted strings). When a
// user runs e.g. `netstat -ano | findstr "LISTENING"`, the default escaping
// breaks because cmd.exe doesn't recognise \". We bypass it by writing the
// raw command line ourselves and adding /S, which tells cmd.exe to always
// strip the outermost quote pair — anything between is passed through as-is.
func makeShellCmd(cmd string) *exec.Cmd {
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    `/S /C "` + cmd + `"`,
		HideWindow: true,
	}
	return c
}

// runShellSystemHook runs cmd as SYSTEM when gSystemToken is set.
// It locks the OS thread and impersonates SYSTEM before calling
// exec.Cmd.Start so that Go's internal CreateProcessAsUserW call
// sees the thread's SYSTEM token (which holds SeAssignPrimaryTokenPrivilege
// and SeIncreaseQuotaPrivilege) rather than the process's unprivileged token.
func runShellSystemHook(cmd string) (out string, handled bool, err error) {
	if gSystemToken == 0 {
		return "", false, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if r, _, e := procImpersonateLoggedOnUser.Call(uintptr(gSystemToken)); r == 0 {
		return fmt.Sprintf("[ImpersonateLoggedOnUser: %v]", e), true, nil
	}
	defer windows.RevertToSelf() //nolint:errcheck

	c := exec.Command("cmd.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    `/S /C "` + cmd + `" 2>&1`,
		HideWindow: true,
		Token:      syscall.Token(gSystemToken),
	}
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	if startErr := c.Start(); startErr != nil {
		return "", true, startErr
	}
	doneCh := make(chan error, 1)
	go func() { doneCh <- c.Wait() }()
	select {
	case waitErr := <-doneCh:
		return buf.String(), true, waitErr
	case <-time.After(60 * time.Second):
		_ = c.Process.Kill()
		return buf.String(), true, fmt.Errorf("command timed out")
	}
}
