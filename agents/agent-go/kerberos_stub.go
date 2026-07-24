//go:build !windows

package agent

import "fmt"

func kerberosListTickets() string {
	out, _ := runShell("klist 2>&1")
	return out
}

func kerberosPassTheTicket(_ string) string {
	return fmt.Sprintf("[error: Kerberos PTT not supported on %s]", "this platform")
}

func kerberosPurge() string {
	return "[error: Kerberos purge not supported on this platform]"
}
