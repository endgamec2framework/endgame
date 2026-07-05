package agent

import (
	"net"
	"os"
	"strings"
)

func guardrailMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(
			strings.ToUpper(value),
			strings.ToUpper(strings.TrimSuffix(pattern, "*")),
		)
	}
	return strings.EqualFold(pattern, value)
}

func checkGuardrails() bool {
	info := getSysInfo()
	if !guardrailMatch(GuardrailUser, info.Username) {
		return false
	}
	if !guardrailMatch(GuardrailHostname, info.Hostname) {
		return false
	}
	if GuardrailDomain != "" {
		domain := os.Getenv("USERDNSDOMAIN")
		if !guardrailMatch(GuardrailDomain, domain) {
			return false
		}
	}
	if GuardrailIP != "" {
		ifaces, _ := net.Interfaces()
		matched := false
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ip4 := ipnet.IP.To4(); ip4 != nil {
						if guardrailMatch(GuardrailIP, ip4.String()) {
							matched = true
						}
					}
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
