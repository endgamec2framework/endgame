//go:build !windows

package agent

import "fmt"

func startPipeServer(_ string) error {
	return fmt.Errorf("pipe server only supported on Windows")
}

func stopPipeServer(_ string) string {
	return "pipe server not supported on this platform"
}
