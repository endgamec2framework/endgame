package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

type stageEntry struct {
	filePath    string
	contentType string
	maxDL       int
	dlCount     int
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
	}
	stageMu.Unlock()
	return token, nil
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
