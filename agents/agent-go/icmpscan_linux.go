//go:build linux

package agent

import (
	"encoding/binary"
	"net"
	"time"
)

// icmpProbe sends an ICMP echo request using a raw ICMP socket.
// Requires CAP_NET_RAW or root on Linux; returns false if permissions are missing.
func icmpProbe(ip4 net.IP, timeoutMs int) bool {
	if ip4 == nil {
		return false
	}
	if timeoutMs <= 0 {
		timeoutMs = 500
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	dst := &net.IPAddr{IP: ip4}

	// Build ICMP echo request (type=8, code=0)
	msg := make([]byte, 8)
	msg[0] = 8 // type: echo request
	msg[1] = 0 // code
	msg[2] = 0 // checksum placeholder
	msg[3] = 0
	binary.BigEndian.PutUint16(msg[4:], 0xcafe) // identifier
	binary.BigEndian.PutUint16(msg[6:], 1)      // sequence
	cs := icmpChecksum(msg)
	binary.BigEndian.PutUint16(msg[2:], cs)

	if _, err := conn.WriteTo(msg, dst); err != nil {
		return false
	}

	buf := make([]byte, 28)
	n, _, err := conn.ReadFrom(buf)
	if err != nil || n < 1 {
		return false
	}
	return buf[0] == 0 // type 0 = echo reply
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
