package agent

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshExec connects to host:port via SSH and runs cmd, returning stdout+stderr.
// auth: password only (no key support for simplicity).
func sshExec(host string, port int, user, pass, cmd string) (string, error) {
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // accept any host key (operator-controlled environment)
		},
		Timeout: 15 * time.Second,
	}

	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	var buf strings.Builder
	sess.Stdout = &buf
	sess.Stderr = &buf

	if err := sess.Run(cmd); err != nil {
		// ExitError is normal (non-zero exit code); still return output
		if buf.Len() > 0 {
			return buf.String(), fmt.Errorf("exit: %w", err)
		}
		return "", err
	}
	return buf.String(), nil
}
