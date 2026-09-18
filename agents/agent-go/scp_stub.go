//go:build !windows

package agent

import "fmt"

func scpUploadAddr(addr, user, pass, remotePath string, data []byte) error {
	return fmt.Errorf("scp not supported on this platform")
}
