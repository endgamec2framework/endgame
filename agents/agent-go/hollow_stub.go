//go:build !windows

package agent

import "fmt"

func hollowProcess(target string, sc []byte) (string, error) {
	return "", fmt.Errorf("process hollowing not supported on this platform")
}
