//go:build !windows

package agent

import "fmt"

func runLateral(method, host string, data []byte, svcName, user, pass string) (string, error) {
	return "", fmt.Errorf("lateral movement not supported on this platform")
}
