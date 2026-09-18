//go:build windows

package agent

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// scpUploadAddr dials addr (host:port) with user/pass and uploads data to remotePath via SCP.
func scpUploadAddr(addr, user, pass, remotePath string, data []byte) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer client.Close()
	return scpUpload(client, data, remotePath)
}
