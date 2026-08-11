package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// artifactMetadata is kept outside bin/payloads so the artifact directory
// remains a directory of downloadable payloads only. Older artifacts simply
// have empty metadata and are intentionally not eligible for SMB-pipe reuse.
type artifactMetadata struct {
	Transport string `json:"transport,omitempty"`
	SMBPipe   string `json:"smb_pipe,omitempty"`
	ParentID  string `json:"parent_id,omitempty"`
	ParentIP  string `json:"parent_ip,omitempty"`
	Lang      string `json:"lang,omitempty"`
	Format    string `json:"format,omitempty"`
	OPSEC     bool   `json:"opsec,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

var artifactMetadataMu sync.Mutex

func (s *Server) artifactMetadataPath() string {
	return filepath.Join(s.cfg.DataDir, "artifact_metadata.json")
}

func (s *Server) loadArtifactMetadata() map[string]artifactMetadata {
	metadata := map[string]artifactMetadata{}
	b, err := os.ReadFile(s.artifactMetadataPath())
	if err != nil {
		return metadata
	}
	if err := json.Unmarshal(b, &metadata); err != nil {
		return map[string]artifactMetadata{}
	}
	return metadata
}

func (s *Server) saveArtifactMetadata(metadata map[string]artifactMetadata) error {
	path := s.artifactMetadataPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".artifact_metadata-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	b, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// artifactNameFromResult accepts only files that actually exist directly in
// the payload directory. This prevents URLs, delivery files, and arbitrary
// result strings from becoming selectable payload artifacts.
func artifactNameFromResult(payloadsDir, value string) string {
	name := filepath.Base(strings.TrimSpace(value))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return ""
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".bin", ".elf", ".dll":
	default:
		return ""
	}
	// Accept files in payloadsDir or at their absolute path (e.g. deliveryDir).
	if _, err := os.Stat(filepath.Join(payloadsDir, name)); err == nil {
		return name
	}
	if filepath.IsAbs(value) {
		if _, err := os.Stat(value); err == nil {
			return name
		}
	}
	return ""
}

func (s *Server) recordArtifactMetadata(payloadsDir string, result map[string]string, cfg BuildConfig) {
	metadata := map[string]artifactMetadata{}
	artifactMetadataMu.Lock()
	defer artifactMetadataMu.Unlock()
	metadata = s.loadArtifactMetadata()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, value := range result {
		name := artifactNameFromResult(payloadsDir, value)
		if name == "" {
			continue
		}
		metadata[name] = artifactMetadata{
			Transport: cfg.Transport,
			SMBPipe:   cfg.SMBPipe,
			ParentID:  cfg.ParentID,
			ParentIP:  cfg.ParentIP,
			Lang:      cfg.Lang,
			Format:    cfg.Format,
			OPSEC:     cfg.OPSEC,
			CreatedAt: now,
		}
	}
	_ = s.saveArtifactMetadata(metadata)
}

func (s *Server) removeArtifactMetadata(name string) {
	artifactMetadataMu.Lock()
	defer artifactMetadataMu.Unlock()
	metadata := s.loadArtifactMetadata()
	if _, ok := metadata[name]; !ok {
		return
	}
	delete(metadata, name)
	_ = s.saveArtifactMetadata(metadata)
}
