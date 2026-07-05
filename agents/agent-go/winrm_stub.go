//go:build !windows

package agent

import "fmt"

func utf16LEBase64(_ string) string {
	return ""
}

func winrmExec(_, _, _, _ string) (string, error) {
	return "", fmt.Errorf("winrm requires Windows agent")
}

func winrmDeploy(_, _, _, _ string) (string, error) {
	return "", fmt.Errorf("winrm requires Windows agent")
}
