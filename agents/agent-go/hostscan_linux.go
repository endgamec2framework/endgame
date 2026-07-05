//go:build linux

package agent

import (
	"bufio"
	"net"
	"os"
	"strings"
	"time"
)

// arpProbe triggers a kernel ARP resolution by opening a UDP socket to the
// target (no data is sent; the kernel resolves the MAC to route the packet),
// then reads /proc/net/arp for the result.
// Works without elevated privileges — the kernel handles ARP transparently.
// Only effective for hosts on the same L2 segment; returns false for routed targets.
func arpProbe(ip4 net.IP) (string, bool) {
	if ip4 == nil {
		return "", false
	}
	target := ip4.String()

	// Opening a UDP "connection" makes the kernel send an ARP request for the
	// destination MAC.  We don't actually send any data.
	conn, err := net.DialTimeout("udp", net.JoinHostPort(target, "1"), 50*time.Millisecond)
	if err == nil {
		conn.Close()
	}

	// Give the kernel a moment to populate the ARP cache.
	time.Sleep(20 * time.Millisecond)

	return readArpCache(target)
}

// readArpCache parses /proc/net/arp for the given IP.
// Returns the MAC and true if the entry is complete (non-zero MAC, flags 0x2).
func readArpCache(ip string) (string, bool) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return "", false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Format: IP HWtype Flags HWaddr Mask Device
		if len(fields) < 4 {
			continue
		}
		if fields[0] != ip {
			continue
		}
		mac := fields[3]
		// Incomplete entry has all-zero MAC
		if mac == "00:00:00:00:00:00" {
			return "", false
		}
		return mac, true
	}
	return "", false
}
