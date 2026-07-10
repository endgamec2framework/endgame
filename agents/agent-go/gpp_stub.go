//go:build !windows

package agent

import "fmt"

type GPPCred struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func huntGPPPasswords() ([]GPPCred, error) {
	return nil, fmt.Errorf("GPP passwords not supported on this platform")
}
