//go:build !windows

package agent

import "fmt"

// forkRun on non-Windows runs shellcode in a subprocess via /proc/self/mem injection.
func forkRun(sc []byte, process string) (string, error) {
	return "", fmt.Errorf("fork-run only supported on Windows")
}

func forkRunAPC(sc []byte, process string) (string, error) {
	return "", fmt.Errorf("inject-apc only supported on Windows")
}
