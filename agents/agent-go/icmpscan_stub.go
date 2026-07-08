//go:build !linux && !windows

package agent

import "net"

func icmpProbe(ip4 net.IP, timeoutMs int) bool { return false }
