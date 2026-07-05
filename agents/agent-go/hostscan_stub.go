//go:build !windows && !linux

package agent

import "net"

// arpProbe is not implemented on this platform; host discovery falls back to TCP.
func arpProbe(_ net.IP) (string, bool) { return "", false }
