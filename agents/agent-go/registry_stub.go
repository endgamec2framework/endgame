//go:build !windows

package agent

import "fmt"

func regQuery(fullPath, valName string) (string, error) {
	return "", fmt.Errorf("registry not supported on this platform")
}
func regSet(fullPath, valName, value string) (string, error) {
	return "", fmt.Errorf("registry not supported on this platform")
}
func regDelete(fullPath, valName string) (string, error) {
	return "", fmt.Errorf("registry not supported on this platform")
}
func regList(fullPath string) (string, error) {
	return "", fmt.Errorf("registry not supported on this platform")
}
