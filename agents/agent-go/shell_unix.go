//go:build !windows

package agent

import "os/exec"

func makeShellCmd(cmd string) *exec.Cmd {
	return exec.Command("/bin/sh", "-c", cmd)
}
