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

func runShellSystemHook(_ string) (string, bool, error) { return "", false, nil }
