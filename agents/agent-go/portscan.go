package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// hostDiscover probes a list of IPs for liveness.
// Tries ARP first (local subnet, stealthy, no privileges needed);
// falls back to TCP connect on common ports for remote/routed subnets.
func hostDiscover(hosts []string, timeoutMs int) string {
	if timeoutMs <= 0 {
		timeoutMs = 500
	}
	type liveHost struct {
		ip  string
		mac string
		via string
	}
	var (
		mu    sync.Mutex
		alive []liveHost
	)
	sem := make(chan struct{}, 256)
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer func() { <-sem; wg.Done() }()
			ip := net.ParseIP(host)
			if ip != nil {
				if mac, ok := arpProbe(ip.To4()); ok {
					mu.Lock()
					alive = append(alive, liveHost{host, mac, "arp"})
					mu.Unlock()
					return
				}
			}
			// ARP failed or not an IP — try TCP on common ports
			if probeHostTCP(host, timeoutMs) {
				mu.Lock()
				alive = append(alive, liveHost{host, "", "tcp"})
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()

	sort.Slice(alive, func(i, j int) bool { return alive[i].ip < alive[j].ip })

	if len(alive) == 0 {
		return fmt.Sprintf("no live hosts found (%d probed)", len(hosts))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Live hosts (%d/%d):\n", len(alive), len(hosts))
	for _, r := range alive {
		if r.mac != "" {
			fmt.Fprintf(&sb, "  %-18s  %s  [%s]\n", r.ip, r.mac, r.via)
		} else {
			fmt.Fprintf(&sb, "  %-18s  [%s]\n", r.ip, r.via)
		}
	}
	return sb.String()
}

// probeHostTCP attempts a TCP connect to common ports to detect liveness.
func probeHostTCP(host string, timeoutMs int) bool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	for _, p := range []int{80, 443, 22, 445, 3389, 135, 8080, 8443, 23, 25} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// portScan performs a TCP connect scan.
// target may be a single host/IP, a CIDR (192.168.1.0/24),
// or a dash range (192.168.1.1-20 or 192.168.1.1-192.168.1.20).
// portRange is comma-separated ports/ranges: "22,80,443,8000-9000".
// timeoutMs controls per-port dial timeout; global concurrency is capped at 512.
func portScan(target, portRange string, timeoutMs int) string {
	if timeoutMs <= 0 {
		timeoutMs = 500
	}
	ports := parsePortRange(portRange)
	if len(ports) == 0 {
		return "no valid ports in range: " + portRange
	}
	hosts := expandTargets(target)
	if len(hosts) == 0 {
		return "no valid targets: " + target
	}

	type result struct {
		host string
		port int
	}
	var (
		mu   sync.Mutex
		open []result
	)

	sem := make(chan struct{}, 512)
	var wg sync.WaitGroup
	timeout := time.Duration(timeoutMs) * time.Millisecond

	for _, host := range hosts {
		for _, port := range ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(h string, p int) {
				defer func() { <-sem; wg.Done() }()
				addr := net.JoinHostPort(h, strconv.Itoa(p))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					open = append(open, result{h, p})
					mu.Unlock()
				}
			}(host, port)
		}
	}
	wg.Wait()

	totalScanned := len(hosts) * len(ports)
	if len(open) == 0 {
		return fmt.Sprintf("no open ports (%d hosts × %d ports = %d probes)", len(hosts), len(ports), totalScanned)
	}

	sort.Slice(open, func(i, j int) bool {
		if open[i].host != open[j].host {
			return open[i].host < open[j].host
		}
		return open[i].port < open[j].port
	})

	var sb strings.Builder
	fmt.Fprintf(&sb, "Scan results (%d hosts, %d ports, %d open):\n", len(hosts), len(ports), len(open))

	prevHost := ""
	for _, r := range open {
		if r.host != prevHost {
			fmt.Fprintf(&sb, "\n  %s\n", r.host)
			prevHost = r.host
		}
		svc := knownService(r.port)
		if svc != "" {
			fmt.Fprintf(&sb, "    %5d/tcp  open  %s\n", r.port, svc)
		} else {
			fmt.Fprintf(&sb, "    %5d/tcp  open\n", r.port)
		}
	}
	return sb.String()
}

// expandTargets returns the list of IP/host strings to scan.
func expandTargets(target string) []string {
	target = strings.TrimSpace(target)

	// CIDR notation: 192.168.1.0/24
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil
		}
		var ips []string
		// iterate all addresses in the network
		for cur := cloneIP(ip.Mask(ipnet.Mask)); ipnet.Contains(cur); incrementIP(cur) {
			// skip network address and broadcast for IPv4
			if isNetworkOrBroadcast(cur, ipnet) {
				continue
			}
			ips = append(ips, cur.String())
		}
		return ips
	}

	// Dash range: two forms
	//   192.168.1.1-20        (last-octet range)
	//   192.168.1.1-192.168.1.20  (full IP range)
	if idx := strings.LastIndex(target, "-"); idx > 0 {
		left := target[:idx]
		right := target[idx+1:]
		startIP := net.ParseIP(left)
		endIP := net.ParseIP(right)
		if startIP != nil && endIP == nil {
			// last-octet shorthand: 192.168.1.1-20
			lastDot := strings.LastIndex(left, ".")
			if lastDot > 0 {
				prefix := left[:lastDot+1]
				endOctet, err := strconv.Atoi(right)
				if err == nil && endOctet >= 0 && endOctet <= 255 {
					endIP = net.ParseIP(prefix + strconv.Itoa(endOctet))
				}
			}
		}
		if startIP != nil && endIP != nil {
			start4 := startIP.To4()
			end4 := endIP.To4()
			if start4 != nil && end4 != nil {
				startN := binary.BigEndian.Uint32(start4)
				endN := binary.BigEndian.Uint32(end4)
				if startN <= endN && endN-startN <= 65535 {
					var ips []string
					for n := startN; n <= endN; n++ {
						b := make(net.IP, 4)
						binary.BigEndian.PutUint32(b, n)
						ips = append(ips, b.String())
					}
					return ips
				}
			}
		}
	}

	// Single host or IP
	return []string{target}
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isNetworkOrBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// network address: all host bits zero
	masked := ip4.Mask(ipnet.Mask)
	if ip4.Equal(masked) {
		return true
	}
	// broadcast: all host bits one
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = masked[i] | ^ipnet.Mask[i]
	}
	return ip4.Equal(bcast)
}

func parsePortRange(s string) []int {
	seen := make(map[int]bool)
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "-"); idx > 0 {
			start, e1 := strconv.Atoi(part[:idx])
			end, e2 := strconv.Atoi(part[idx+1:])
			if e1 != nil || e2 != nil || start < 1 || end > 65535 || start > end {
				continue
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func knownService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 389:
		return "ldap"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 636:
		return "ldaps"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgres"
	case 5985:
		return "winrm-http"
	case 5986:
		return "winrm-https"
	case 6379:
		return "redis"
	case 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	case 27017:
		return "mongodb"
	}
	return ""
}
