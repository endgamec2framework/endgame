//go:build !windows

package agent

import "fmt"

func stealSessionCreds() ([]BrowserCred, error) {
	return nil, fmt.Errorf("session creds not supported on this platform")
}
