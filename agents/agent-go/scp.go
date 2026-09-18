package agent

import (
	"fmt"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// scpUpload copies data to dstPath on the SSH server at addr (host:port).
// Uses SCP protocol (OpenSSH scp -t) via a plain SSH session — no scp binary needed.
func scpUpload(addr, user, password, dstPath string, data []byte) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — red-team tool
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	// Open scp receive pipe.
	w, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	// Launch remote scp in sink mode.
	dir := filepath.ToSlash(filepath.Dir(dstPath))
	if err := sess.Start("scp -qt " + dir); err != nil {
		return fmt.Errorf("scp start: %w", err)
	}

	base := filepath.Base(dstPath)
	// SCP header: C0644 <size> <filename>\n
	fmt.Fprintf(w, "C0644 %s %s\n", strconv.Itoa(len(data)), base)
	w.Write(data)        //nolint:errcheck
	fmt.Fprint(w, "\x00") // trailing null byte
	w.Close()

	if err := sess.Wait(); err != nil {
		return fmt.Errorf("scp wait: %w", err)
	}
	return nil
}
