//go:build !windows

package agent

import "fmt"

func vncStart(callbackPort string, quality int) error {
	return fmt.Errorf("VNC not supported on this platform")
}

func vncStop() string {
	return "[-] VNC not running"
}
