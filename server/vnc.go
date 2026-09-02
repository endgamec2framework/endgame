package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// VNC frame protocol constants — must match agents/agent-go/vnc_windows.go

const (
	// Agent → server
	vncFRAME byte = 0x01
	vncINFO  byte = 0x02
	vncPONG  byte = 0x03

	// Server → agent
	vncMOUSE_MOVE  byte = 0x10
	vncMOUSE_CLICK byte = 0x11
	vncMOUSE_WHEEL byte = 0x12
	vncKEY         byte = 0x13
	vncSTOP        byte = 0x14
	vncPING        byte = 0x15
	vncQUALITY     byte = 0x16
)

// vncSession manages one agent's desktop streaming session.
type vncSession struct {
	agentID    string
	callbackLn net.Listener
	agentConn  net.Conn
	writeMu    sync.Mutex
	clients    sync.Map // *websocket.Conn → struct{}
	done       chan struct{}
	once       sync.Once
	quality    int
}

func (s *vncSession) stop() {
	s.once.Do(func() {
		close(s.done)
		s.callbackLn.Close()
		if s.agentConn != nil {
			s.agentConn.Close()
		}
		// Close all viewers
		s.clients.Range(func(k, _ interface{}) bool {
			if ws, ok := k.(*websocket.Conn); ok {
				ws.Close()
			}
			return true
		})
	})
}

// writeAgent sends a framed message to the agent: [1B type][4B len LE][payload]
func (s *vncSession) writeAgent(typ byte, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.agentConn == nil {
		return fmt.Errorf("no agent connection")
	}
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.LittleEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := s.agentConn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := s.agentConn.Write(payload)
		return err
	}
	return nil
}

// broadcast sends a raw WS binary message to all connected operator clients.
func (s *vncSession) broadcast(data []byte) {
	s.clients.Range(func(k, _ interface{}) bool {
		if ws, ok := k.(*websocket.Conn); ok {
			if err := ws.WriteMessage(websocket.BinaryMessage, data); err != nil {
				s.clients.Delete(k)
				ws.Close()
			}
		}
		return true
	})
}

// ── Package-level registry ────────────────────────────────────────────────────

var (
	vncMu       sync.Mutex
	vncSessions = map[string]*vncSession{} // agentID → session
)

// ── Exported API ──────────────────────────────────────────────────────────────

// StartVNC opens a callback listener for the agent and returns the port number.
// The caller must queue VNC_START <port> [quality] on the agent.
func (s *Server) StartVNC(agentID string, quality int) (int, error) {
	vncMu.Lock()
	defer vncMu.Unlock()

	if _, exists := vncSessions[agentID]; exists {
		return 0, fmt.Errorf("vnc already running for agent %s", agentID)
	}

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return 0, fmt.Errorf("vnc callback listener: %w", err)
	}

	if quality <= 0 || quality > 100 {
		quality = 60
	}

	sess := &vncSession{
		agentID:    agentID,
		callbackLn: ln,
		done:       make(chan struct{}),
		quality:    quality,
	}
	vncSessions[agentID] = sess
	go sess.waitForAgent(s)

	port := ln.Addr().(*net.TCPAddr).Port
	s.printf("[vnc] agent=%s callback=:%d quality=%d\n", shortID(agentID), port, quality)
	return port, nil
}

// StopVNC tears down a running VNC session.
func (s *Server) StopVNC(agentID string) error {
	vncMu.Lock()
	sess, ok := vncSessions[agentID]
	if ok {
		delete(vncSessions, agentID)
	}
	vncMu.Unlock()
	if !ok {
		return fmt.Errorf("no vnc session for agent %s", agentID)
	}
	// Tell agent to stop then tear down
	_ = sess.writeAgent(vncSTOP, nil)
	time.Sleep(100 * time.Millisecond)
	sess.stop()
	s.printf("[vnc] stopped for agent %s\n", shortID(agentID))
	return nil
}

// ServeVNCWebSocket upgrades the HTTP connection to WebSocket and attaches
// the viewer to the VNC session for agentID. Blocks until the WS closes.
func (s *Server) ServeVNCWebSocket(w http.ResponseWriter, r *http.Request, agentID string) {
	vncMu.Lock()
	sess, ok := vncSessions[agentID]
	vncMu.Unlock()
	if !ok {
		http.Error(w, "no vnc session", http.StatusNotFound)
		return
	}

	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	sess.clients.Store(ws, struct{}{})
	defer sess.clients.Delete(ws)

	// Receive input events from this browser client and forward to agent
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		// msg is a raw VNC frame from the browser: [1B type][4B len LE][payload]
		if len(msg) < 5 {
			continue
		}
		typ := msg[0]
		plen := binary.LittleEndian.Uint32(msg[1:5])
		if int(plen) != len(msg)-5 {
			continue
		}
		// Forward to agent
		if err := sess.writeAgent(typ, msg[5:]); err != nil {
			return
		}
	}
}

// ── Internal goroutines ───────────────────────────────────────────────────────

func (sess *vncSession) waitForAgent(s *Server) {
	conn, err := sess.callbackLn.Accept()
	if err != nil {
		select {
		case <-sess.done:
		default:
			s.printf("[vnc] agent accept error: %v\n", err)
			sess.stop()
		}
		return
	}
	sess.callbackLn.Close()

	sess.writeMu.Lock()
	sess.agentConn = conn
	sess.writeMu.Unlock()

	s.printf("[vnc] agent %s connected from %s\n", shortID(sess.agentID), conn.RemoteAddr())
	go sess.readAgentFrames(s)
	go sess.heartbeat(s)
}

// readAgentFrames reads frames from the agent and broadcasts them to all WS clients.
func (sess *vncSession) readAgentFrames(s *Server) {
	defer sess.stop()
	hdr := make([]byte, 5)
	for {
		if _, err := io.ReadFull(sess.agentConn, hdr); err != nil {
			select {
			case <-sess.done:
			default:
				s.printf("[vnc] agent read error: %v\n", err)
			}
			return
		}
		typ := hdr[0]
		plen := binary.LittleEndian.Uint32(hdr[1:5])
		if plen > 8*1024*1024 {
			s.printf("[vnc] frame too large (%d), dropping\n", plen)
			return
		}
		payload := make([]byte, plen)
		if plen > 0 {
			if _, err := io.ReadFull(sess.agentConn, payload); err != nil {
				select {
				case <-sess.done:
				default:
					s.printf("[vnc] payload read error: %v\n", err)
				}
				return
			}
		}

		// Re-assemble the full frame and broadcast to all viewers
		frame := make([]byte, 5+len(payload))
		frame[0] = typ
		binary.LittleEndian.PutUint32(frame[1:5], plen)
		copy(frame[5:], payload)

		switch typ {
		case vncPONG:
			// heartbeat reply — don't broadcast
		default:
			sess.broadcast(frame)
		}
	}
}

// heartbeat sends periodic PINGs to the agent and stops the session if it
// fails to respond within two intervals.
func (sess *vncSession) heartbeat(s *Server) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sess.done:
			return
		case <-ticker.C:
			if err := sess.writeAgent(vncPING, nil); err != nil {
				s.printf("[vnc] heartbeat failed for %s: %v\n", shortID(sess.agentID), err)
				sess.stop()
				return
			}
		}
	}
}
