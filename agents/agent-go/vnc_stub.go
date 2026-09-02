//go:build !windows

package agent

import "fmt"

func vncStart(callbackPort string, quality int) error {
	return fmt.Errorf("VNC not supported on this platform")
}

func vncStop() string {
	return "[-] VNC not running"
}

func RunVNCMode(port, quality int) {}

func vncSpawnInject(callbackPort string, quality, targetPID int) (uint32, error) {
	return 0, fmt.Errorf("VNC injection not supported on this platform")
}
