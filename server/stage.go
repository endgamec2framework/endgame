package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type stageEntry struct {
	filePath    string
	contentType string
	maxDL       int
	dlCount     int
	url         string // full public URL (set via SetStageURL after registration)
	addedAt     time.Time
	mu          sync.Mutex
}

var (
	stageMu      sync.RWMutex
	stageEntries = map[string]*stageEntry{}
)

// RegisterStage stores a file at a random 32-hex token path.
// maxDL caps downloads (0 = unlimited). Returns the token.
func RegisterStage(filePath, contentType string, maxDL int) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	stageMu.Lock()
	stageEntries[token] = &stageEntry{
		filePath:    filePath,
		contentType: contentType,
		maxDL:       maxDL,
		addedAt:     time.Now(),
	}
	stageMu.Unlock()
	return token, nil
}

// SetStageURL records the public URL for a registered stage token so it appears in the UI.
func SetStageURL(token, url string) {
	stageMu.Lock()
	if e, ok := stageEntries[token]; ok {
		e.url = url
	}
	stageMu.Unlock()
}

// ListStages returns all registered stage entries as StagedFile objects for the Stager UI.
func ListStages() []StagedFile {
	stageMu.RLock()
	defer stageMu.RUnlock()
	out := make([]StagedFile, 0, len(stageEntries))
	for token, e := range stageEntries {
		e.mu.Lock()
		var sz int64
		if fi, err := os.Stat(e.filePath); err == nil {
			sz = fi.Size()
		}
		out = append(out, StagedFile{
			Token:     token,
			Name:      filepath.Base(e.filePath),
			Size:      sz,
			MIME:      e.contentType,
			OneShot:   e.maxDL > 0,
			Downloads: e.dlCount,
			AddedAt:   e.addedAt,
			URL:       e.url,
		})
		e.mu.Unlock()
	}
	return out
}

// RemoveStage unregisters a build stage by token so it stops being served and
// disappears from the Stager UI. The underlying file on disk is left in place —
// it may be a payload the operator still needs. No-op if the token is unknown
// (e.g. it belonged to an uploaded file, handled separately).
func RemoveStage(token string) bool {
	stageMu.Lock()
	_, ok := stageEntries[token]
	delete(stageEntries, token)
	stageMu.Unlock()
	return ok
}

// handleStage serves GET /stage/<token>
func (s *Server) handleStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	token := filepath.Base(r.URL.Path)
	if len(token) < 32 {
		http.NotFound(w, r)
		return
	}

	stageMu.RLock()
	e, ok := stageEntries[token]
	stageMu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	e.mu.Lock()
	if e.maxDL > 0 && e.dlCount >= e.maxDL {
		e.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	e.dlCount++
	dlNum := e.dlCount
	e.mu.Unlock()

	data, err := os.ReadFile(e.filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ct := e.contentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Write(data)
	s.printf("[stage] token=%s served (#%d/%s)\n", token[:8], dlNum,
		func() string {
			if e.maxDL == 0 {
				return "∞"
			}
			return string(rune('0'+e.maxDL))
		}())
}
