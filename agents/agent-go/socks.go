package agent

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

var (
	socksListener net.Listener
	socksMu       sync.Mutex
	socksRunning  atomic.Bool
	socksUser     string
	socksPass     string
)

func startSOCKS5(port int, user, pass string) (string, error) {
	socksMu.Lock()
	defer socksMu.Unlock()

	if socksRunning.Load() {
		stopSOCKS5Locked()
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return "", err
	}
	socksListener = ln
	socksUser = user
	socksPass = pass
	socksRunning.Store(true)

	go func() {
		defer socksRunning.Store(false)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5(conn, user, pass)
		}
	}()

	return ln.Addr().String(), nil
}

func stopSOCKS5() {
	socksMu.Lock()
	defer socksMu.Unlock()
	stopSOCKS5Locked()
}

func stopSOCKS5Locked() {
	if socksListener != nil {
		socksListener.Close()
		socksListener = nil
	}
	socksRunning.Store(false)
}

// handleSOCKS5 implements SOCKS5 (RFC 1928) with optional RFC 1929 user/pass auth.
func handleSOCKS5(client net.Conn, user, pass string) {
	defer client.Close()

	// Auth negotiation
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	if user != "" {
		// Require method 0x02 (user/pass).
		offered := false
		for _, m := range methods {
			if m == 0x02 {
				offered = true
				break
			}
		}
		if !offered {
			client.Write([]byte{0x05, 0xFF}) // no acceptable method
			return
		}
		client.Write([]byte{0x05, 0x02})

		// RFC 1929 sub-negotiation: VER(1) ULEN(1) USER(N) PLEN(1) PASS(M)
		sub := make([]byte, 2)
		if _, err := io.ReadFull(client, sub); err != nil {
			return
		}
		if sub[0] != 0x01 {
			return
		}
		uBuf := make([]byte, sub[1])
		if _, err := io.ReadFull(client, uBuf); err != nil {
			return
		}
		pLen := make([]byte, 1)
		if _, err := io.ReadFull(client, pLen); err != nil {
			return
		}
		pBuf := make([]byte, pLen[0])
		if _, err := io.ReadFull(client, pBuf); err != nil {
			return
		}
		if string(uBuf) != user || string(pBuf) != pass {
			client.Write([]byte{0x01, 0xFF}) // auth failure
			return
		}
		client.Write([]byte{0x01, 0x00}) // auth success
	} else {
		// No auth required.
		client.Write([]byte{0x05, 0x00})
	}

	// Request
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 { // only CONNECT
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		io.ReadFull(client, addr)
		host = net.IP(addr).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		io.ReadFull(client, lenBuf)
		domain := make([]byte, lenBuf[0])
		io.ReadFull(client, domain)
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		io.ReadFull(client, addr)
		host = net.IP(addr).String()
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := fmt.Sprintf("%s:%d", host, port)

	// Connect to target
	remote, err := net.Dial("tcp", target)
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Success response
	localAddr := remote.LocalAddr().(*net.TCPAddr)
	resp := []byte{0x05, 0x00, 0x00, 0x01}
	resp = append(resp, localAddr.IP.To4()...)
	resp = append(resp, byte(localAddr.Port>>8), byte(localAddr.Port))
	client.Write(resp)

	// Bidirectional relay
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
}
