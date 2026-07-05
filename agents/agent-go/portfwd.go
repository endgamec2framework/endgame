package agent

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type portFwdEntry struct {
	lport    int
	rhost    string
	rport    int
	proto    string // "tcp" or "udp"
	listener net.Listener    // TCP only
	udpConn  *net.UDPConn    // UDP only
}

var (
	portFwdMu      sync.Mutex
	portFwdEntries = map[string]*portFwdEntry{} // key: "tcp:1234" or "udp:1234"
)

func addPortFwd(lport int, rhost string, rport int) error {
	return addPortFwdProto("tcp", lport, rhost, rport)
}

func addUDPPortFwd(lport int, rhost string, rport int) error {
	return addPortFwdProto("udp", lport, rhost, rport)
}

func addPortFwdProto(proto string, lport int, rhost string, rport int) error {
	portFwdMu.Lock()
	defer portFwdMu.Unlock()

	key := fmt.Sprintf("%s:%d", proto, lport)
	if _, exists := portFwdEntries[key]; exists {
		return fmt.Errorf("%s port %d already forwarded", proto, lport)
	}

	e := &portFwdEntry{lport: lport, rhost: rhost, rport: rport, proto: proto}

	if proto == "udp" {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", lport))
		if err != nil {
			return fmt.Errorf("resolve :%d: %w", lport, err)
		}
		uc, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("listen udp :%d: %w", lport, err)
		}
		e.udpConn = uc
		portFwdEntries[key] = e
		go runUDPPortFwd(uc, rhost, rport, key)
		return nil
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", lport))
	if err != nil {
		return fmt.Errorf("listen :%d: %w", lport, err)
	}
	e.listener = ln
	portFwdEntries[key] = e

	go func() {
		defer func() {
			portFwdMu.Lock()
			delete(portFwdEntries, key)
			portFwdMu.Unlock()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handlePortFwd(conn, rhost, rport)
		}
	}()

	return nil
}

// runUDPPortFwd handles UDP forwarding with per-source session tracking.
// Each distinct client UDP address gets its own upstream connection.
// Sessions expire after 60s of inactivity.
func runUDPPortFwd(local *net.UDPConn, rhost string, rport int, key string) {
	defer func() {
		portFwdMu.Lock()
		delete(portFwdEntries, key)
		portFwdMu.Unlock()
	}()

	type udpSession struct {
		remote *net.UDPConn
		timer  *time.Timer
	}
	var mu sync.Mutex
	sessions := map[string]*udpSession{}

	buf := make([]byte, 65536)
	for {
		n, clientAddr, err := local.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		clientKey := clientAddr.String()

		mu.Lock()
		sess, ok := sessions[clientKey]
		if !ok {
			raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", rhost, rport))
			if err != nil {
				mu.Unlock()
				continue
			}
			remote, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				mu.Unlock()
				continue
			}
			sess = &udpSession{
				remote: remote,
				timer:  time.AfterFunc(60*time.Second, func() {
					mu.Lock()
					if s, ok := sessions[clientKey]; ok {
						s.remote.Close()
						delete(sessions, clientKey)
					}
					mu.Unlock()
				}),
			}
			sessions[clientKey] = sess
			// Read responses from remote → forward back to client
			go func(r *net.UDPConn, ca *net.UDPAddr) {
				rbuf := make([]byte, 65536)
				for {
					rn, rerr := r.Read(rbuf)
					if rerr != nil {
						return
					}
					local.WriteToUDP(rbuf[:rn], ca)
				}
			}(remote, clientAddr)
		}
		sess.timer.Reset(60 * time.Second)
		mu.Unlock()
		sess.remote.Write(pkt)
	}
}

func delPortFwd(lport int) {
	delPortFwdProto("tcp", lport)
}

func delUDPPortFwd(lport int) {
	delPortFwdProto("udp", lport)
}

func delPortFwdProto(proto string, lport int) {
	portFwdMu.Lock()
	defer portFwdMu.Unlock()
	key := fmt.Sprintf("%s:%d", proto, lport)
	if e, ok := portFwdEntries[key]; ok {
		if e.listener != nil {
			e.listener.Close()
		}
		if e.udpConn != nil {
			e.udpConn.Close()
		}
		delete(portFwdEntries, key)
	}
}

func listPortFwds() string {
	portFwdMu.Lock()
	defer portFwdMu.Unlock()
	if len(portFwdEntries) == 0 {
		return "no active port forwards"
	}
	var s string
	for _, e := range portFwdEntries {
		s += fmt.Sprintf("  %s :%d → %s:%d\n", e.proto, e.lport, e.rhost, e.rport)
	}
	return s
}

func handlePortFwd(local net.Conn, rhost string, rport int) {
	defer local.Close()
	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", rhost, rport))
	if err != nil {
		return
	}
	defer remote.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, local); done <- struct{}{} }()
	go func() { io.Copy(local, remote); done <- struct{}{} }()
	<-done
}
