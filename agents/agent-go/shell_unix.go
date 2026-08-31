//go:build !windows

package agent

import "os/exec"

func makeShellCmd(cmd string) *exec.Cmd {
	return exec.Command("/bin/sh", "-c", cmd)
}

func makeInteractiveShellCmd(shell string) *exec.Cmd {
	if shell == "zsh" {
		return exec.Command("zsh", "--norc")
	}
	return exec.Command("/bin/bash", "--norc", "--noprofile")
}

// runShellOpsec has a Windows-specific WMI implementation. On POSIX systems
// there is no equivalent hook, so execute the command through the normal
// shell path instead of leaving the cross-platform dispatcher undefined.
func runShellOpsec(cmd string) string {
	out, err := runShell(cmd)
	if err != nil {
		return out + err.Error()
	}
	return out
}

func runShellSystemHook(_ string) (string, bool, error) { return "", false, nil }
