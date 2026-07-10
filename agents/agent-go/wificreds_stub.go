//go:build !windows

package agent

import "fmt"

func stealWifiCreds() ([]BrowserCred, error) {
	return nil, fmt.Errorf("WiFi creds not supported on this platform")
}
