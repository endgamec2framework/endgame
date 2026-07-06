//go:build !windows

package agent

import "fmt"

func findHostDLL() string { return "" }

func phantomLoad(_ []byte) (string, error) {
	return "", fmt.Errorf("phantom DLL loading not supported on this platform")
}
