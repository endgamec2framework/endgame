//go:build !windows

package agent

import "fmt"

func newSMBTransport(pipe string) (transport, error) {
	return nil, fmt.Errorf("SMB transport not supported on this platform")
}
