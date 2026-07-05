//go:build !windows

package agent

import "fmt"

func lsassDump(_ uint32) ([]byte, error) {
	return nil, fmt.Errorf("minidump not supported on this platform")
}
