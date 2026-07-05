//go:build windows

package agent

import (
	"os/exec"

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
