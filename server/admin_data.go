package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	snapshotFormat  = "endgame.c2.snapshot"
	snapshotVersion = 1
	resetPhrase     = "RESET C2"
)

// SnapshotInclude describes the portable parts of a C2 project. Runtime
// identity (agents, listeners, certificates and payloads) is intentionally
// outside this format because it is installation-specific.
type SnapshotInclude struct {
	Credentials bool `json:"credentials"`
	Targets     bool `json:"targets"`
	BloodHound  bool `json:"bloodhound"`
	Automations bool `json:"automations"`
}

type c2Snapshot struct {
	Format     string          `json:"format"`
	Version    int             `json:"version"`
	CreatedAt  time.Time       `json:"created_at"`
	Includes   SnapshotInclude `json:"includes"`
	Credentials []*Credential  `json:"credentials,omitempty"`
	Targets     []*Target      `json:"targets,omitempty"`
	Reactions   []*Reaction    `json:"reactions,omitempty"`
	Webhooks    []*WebhookConfig `json:"webhooks,omitempty"`
	BHNodes     []*BHNode      `json:"bh_nodes,omitempty"`
	BHEdges     []*BHEdge      `json:"bh_edges,omitempty"`
	BHUploads   []*BHUpload    `json:"bh_uploads,omitempty"`
}

type snapshotEnvelope struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func normalizeSnapshotInclude(in SnapshotInclude) SnapshotInclude {
	if !in.Credentials && !in.Targets && !in.BloodHound && !in.Automations {
		// A direct API caller that omits include gets the safe portable default.
		in.Credentials = true
		in.Targets = true
		in.BloodHound = true
	}
	return in
}

func (d *DB) BuildSnapshot(in SnapshotInclude) (*c2Snapshot, error) {
	in = normalizeSnapshotInclude(in)
	s := &c2Snapshot{
		Format:    snapshotFormat,
		Version:   snapshotVersion,
		CreatedAt: time.Now().UTC(),
		Includes:  in,
	}
	var err error
	if in.Credentials {
		s.Credentials, err = d.ListCreds("")
		if err != nil {
			return nil, err
		}
	}
	if in.Targets {
		s.Targets, err = d.ListTargets()
		if err != nil {
			return nil, err
		}
	}
	if in.Automations {
		s.Reactions, err = d.ListReactions()
		if err != nil {
			return nil, err
		}
		s.Webhooks, err = d.ListWebhooks()
		if err != nil {
			return nil, err
		}
	}
	if in.BloodHound {
		s.BHNodes, s.BHEdges, err = d.BHGetGraph()
		if err != nil {
			return nil, err
		}
		s.BHUploads, err = d.BHListUploads()
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func snapshotCounts(s *c2Snapshot) map[string]int {
	return map[string]int{
		"credentials": len(s.Credentials),
		"targets":     len(s.Targets),
		"reactions":   len(s.Reactions),
		"webhooks":    len(s.Webhooks),
		"bh_nodes":    len(s.BHNodes),
		"bh_edges":    len(s.BHEdges),
		"bh_uploads":  len(s.BHUploads),
	}
}

func validateSnapshot(s *c2Snapshot) error {
	if s == nil || s.Format != snapshotFormat || s.Version != snapshotVersion {
		return fmt.Errorf("unsupported snapshot payload")
	}
	if !s.Includes.Credentials && len(s.Credentials) > 0 {
		return fmt.Errorf("snapshot credentials are not declared in includes")
	}
	if !s.Includes.Targets && len(s.Targets) > 0 {
		return fmt.Errorf("snapshot targets are not declared in includes")
	}
	if !s.Includes.Automations && (len(s.Reactions) > 0 || len(s.Webhooks) > 0) {
		return fmt.Errorf("snapshot automations are not declared in includes")
	}
	if !s.Includes.BloodHound && (len(s.BHNodes) > 0 || len(s.BHEdges) > 0 || len(s.BHUploads) > 0) {
		return fmt.Errorf("snapshot BloodHound data is not declared in includes")
	}
	for i, c := range s.Credentials {
		if c == nil { return fmt.Errorf("snapshot credentials[%d] is null", i) }
	}
	for i, t := range s.Targets {
		if t == nil { return fmt.Errorf("snapshot targets[%d] is null", i) }
	}
	for i, r := range s.Reactions {
		if r == nil { return fmt.Errorf("snapshot reactions[%d] is null", i) }
	}
	for i, w := range s.Webhooks {
		if w == nil { return fmt.Errorf("snapshot webhooks[%d] is null", i) }
	}
	for i, n := range s.BHNodes {
		if n == nil { return fmt.Errorf("snapshot bh_nodes[%d] is null", i) }
	}
	for i, e := range s.BHEdges {
		if e == nil { return fmt.Errorf("snapshot bh_edges[%d] is null", i) }
	}
	for i, u := range s.BHUploads {
		if u == nil { return fmt.Errorf("snapshot bh_uploads[%d] is null", i) }
	}
	return nil
}

func validatePassphrase(passphrase string) error {
	if len([]byte(passphrase)) < 8 {
		return fmt.Errorf("passphrase must be at least 8 characters")
	}
	return nil
}

func deriveSnapshotKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

func encryptSnapshot(s *c2Snapshot, passphrase string) ([]byte, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := validateSnapshot(s); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveSnapshotKey(passphrase, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, []byte(snapshotFormat))
	env := snapshotEnvelope{
		Format:     snapshotFormat,
		Version:    snapshotVersion,
		KDF:        "argon2id",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
	}
	return json.MarshalIndent(env, "", "  ")
}

func decryptSnapshot(blob []byte, passphrase string) (*c2Snapshot, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	var env snapshotEnvelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, fmt.Errorf("invalid snapshot file: %w", err)
	}
	if env.Format != snapshotFormat || env.Version != snapshotVersion || env.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported snapshot format or version")
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) < 16 {
		return nil, fmt.Errorf("invalid snapshot salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid snapshot nonce")
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid snapshot ciphertext")
	}
	block, err := aes.NewCipher(deriveSnapshotKey(passphrase, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, sealed, []byte(snapshotFormat))
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase or corrupted snapshot")
	}
	var s c2Snapshot
	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, fmt.Errorf("invalid snapshot payload: %w", err)
	}
	if s.Format != snapshotFormat || s.Version != snapshotVersion {
		return nil, fmt.Errorf("unsupported snapshot payload")
	}
	s.Includes = normalizeSnapshotInclude(s.Includes)
	if err := validateSnapshot(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ApplySnapshot imports only the categories present in the snapshot. Replace
// means replace those categories, not the whole C2 database; agents, tasks,
// results, roles, certificates and listeners are deliberately untouched.
func (d *DB) ApplySnapshot(s *c2Snapshot, mode string) (map[string]int, error) {
	if mode != "merge" && mode != "replace" {
		return nil, fmt.Errorf("mode must be merge or replace")
	}
	if err := validateSnapshot(s); err != nil {
		return nil, err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	inc := s.Includes
	if mode == "replace" {
		if inc.BloodHound {
			if _, err := tx.Exec(`DELETE FROM bh_edges`); err != nil { return nil, err }
			if _, err := tx.Exec(`DELETE FROM bh_nodes`); err != nil { return nil, err }
			if _, err := tx.Exec(`DELETE FROM bh_uploads`); err != nil { return nil, err }
		}
		if inc.Credentials {
			if _, err := tx.Exec(`DELETE FROM credentials`); err != nil { return nil, err }
		}
		if inc.Targets {
			if _, err := tx.Exec(`DELETE FROM targets`); err != nil { return nil, err }
		}
		if inc.Automations {
			if _, err := tx.Exec(`DELETE FROM reactions`); err != nil { return nil, err }
			if _, err := tx.Exec(`DELETE FROM webhook_configs`); err != nil { return nil, err }
		}
	}
	counts := snapshotCounts(s)

	for _, c := range s.Credentials {
		if mode == "merge" {
			var exists int
			err := tx.QueryRow(`SELECT 1 FROM credentials WHERE type=? AND domain=? AND username=? AND secret=? AND host=? LIMIT 1`, c.Type, c.Domain, c.Username, c.Secret, c.Host).Scan(&exists)
			if err == nil { continue }
			if err != sql.ErrNoRows { return nil, err }
		}
		if _, err := tx.Exec(`INSERT INTO credentials (type, domain, username, secret, host, source, operator, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, c.Type, c.Domain, c.Username, c.Secret, c.Host, c.Source, c.Operator, c.CapturedAt); err != nil { return nil, err }
	}
	for _, t := range s.Targets {
		if mode == "merge" && (t.IP != "" || t.Hostname != "") {
			var exists int
			err := tx.QueryRow(`SELECT 1 FROM targets WHERE ip=? AND hostname=? LIMIT 1`, t.IP, t.Hostname).Scan(&exists)
			if err == nil { continue }
			if err != sql.ErrNoRows { return nil, err }
		}
		if _, err := tx.Exec(`INSERT INTO targets (ip, hostname, os, notes, status, tags, source, agent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, t.IP, t.Hostname, t.OS, t.Notes, t.Status, t.Tags, t.Source, t.AgentID, t.CreatedAt, t.UpdatedAt); err != nil { return nil, err }
	}
	for _, r := range s.Reactions {
		if mode == "merge" {
			var exists int
			err := tx.QueryRow(`SELECT 1 FROM reactions WHERE name=? AND event=? AND task_type=? AND task_args=? LIMIT 1`, r.Name, r.Event, r.TaskType, r.TaskArgs).Scan(&exists)
			if err == nil { continue }
			if err != sql.ErrNoRows { return nil, err }
		}
		enabled := 0
		if r.Enabled { enabled = 1 }
		if _, err := tx.Exec(`INSERT INTO reactions (name, event, task_type, task_args, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`, r.Name, r.Event, r.TaskType, r.TaskArgs, enabled, r.CreatedAt); err != nil { return nil, err }
	}
	for _, w := range s.Webhooks {
		if mode == "merge" {
			var exists int
			err := tx.QueryRow(`SELECT 1 FROM webhook_configs WHERE name=? AND type=? AND url=? AND events=? LIMIT 1`, w.Name, w.Type, w.URL, w.Events).Scan(&exists)
			if err == nil { continue }
			if err != sql.ErrNoRows { return nil, err }
		}
		enabled := 0
		if w.Enabled { enabled = 1 }
		if _, err := tx.Exec(`INSERT INTO webhook_configs (name, type, url, events, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`, w.Name, w.Type, w.URL, w.Events, enabled, w.CreatedAt); err != nil { return nil, err }
	}
	for _, n := range s.BHNodes {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO bh_nodes (sid, name, type, domain, props) VALUES (?, ?, ?, ?, ?)`, n.SID, n.Name, n.Type, n.Domain, n.Props); err != nil { return nil, err }
	}
	for _, e := range s.BHEdges {
		if _, err := tx.Exec(`
			INSERT INTO bh_edges (source_sid, target_sid, edge_type)
			SELECT ?, ?, ?
			WHERE NOT EXISTS (
				SELECT 1 FROM bh_edges WHERE source_sid=? AND target_sid=? AND edge_type=?
			)`, e.SourceSID, e.TargetSID, e.EdgeType, e.SourceSID, e.TargetSID, e.EdgeType); err != nil {
			return nil, err
		}
	}
	for _, u := range s.BHUploads {
		if mode == "merge" {
			var exists int
			err := tx.QueryRow(`SELECT 1 FROM bh_uploads WHERE filename=? AND node_count=? AND edge_count=? LIMIT 1`, u.Filename, u.NodeCount, u.EdgeCount).Scan(&exists)
			if err == nil { continue }
			if err != sql.ErrNoRows { return nil, err }
		}
		if _, err := tx.Exec(`INSERT INTO bh_uploads (filename, node_count, edge_count, uploaded_at) VALUES (?, ?, ?, ?)`, u.Filename, u.NodeCount, u.EdgeCount, u.UploadedAt); err != nil { return nil, err }
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return counts, nil
}

func (d *DB) ResetOperationalData() error {
	tx, err := d.db.Begin()
	if err != nil { return err }
	defer tx.Rollback() //nolint:errcheck
	// Keep operator_roles so the administrator is not locked out after reset.
	for _, table := range []string{
		"results", "tasks", "agents", "credentials", "reactions",
		"webhook_configs", "targets", "bh_edges", "bh_nodes", "bh_uploads", "canaries",
	} {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil { return err }
	}
	return tx.Commit()
}

func backupSQLite(db *sql.DB, source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil { return err }
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil { return err }
	in, err := os.Open(source)
	if err != nil { return err }
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { return err }
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil { return err }
	return out.Sync()
}

func clearDirectoryContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) { return nil }
	if err != nil { return err }
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil { return err }
	}
	return nil
}

func (s *Server) apiAdminData(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/api/admin/data")
	sub = strings.TrimPrefix(sub, "/")
	switch {
	case r.Method == http.MethodPost && sub == "snapshot/export":
		var req struct {
			Passphrase string          `json:"passphrase"`
			Include    SnapshotInclude `json:"include"`
		}
		if err := jsonBody(r, &req); err != nil { jsonErr(w, err.Error(), http.StatusBadRequest); return }
		snap, err := s.db.BuildSnapshot(req.Include)
		if err != nil { jsonErr(w, err.Error(), http.StatusInternalServerError); return }
		blob, err := encryptSnapshot(snap, req.Passphrase)
		if err != nil { jsonErr(w, err.Error(), http.StatusBadRequest); return }
		name := "endgame-snapshot-" + time.Now().UTC().Format("20060102-150405") + ".endgame.json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(blob)

	case r.Method == http.MethodPost && (sub == "snapshot/preview" || sub == "snapshot/import"):
		snap, err := readSnapshotMultipart(r)
		if err != nil { jsonErr(w, err.Error(), http.StatusBadRequest); return }
		if sub == "snapshot/preview" || r.FormValue("dry_run") == "1" {
			jsonOK(w, map[string]any{"format": snap.Format, "version": snap.Version, "created_at": snap.CreatedAt, "includes": snap.Includes, "counts": snapshotCounts(snap)})
			return
		}
		mode := r.FormValue("mode")
		counts, err := s.db.ApplySnapshot(snap, mode)
		if err != nil { jsonErr(w, err.Error(), http.StatusBadRequest); return }
		jsonOK(w, map[string]any{
			"mode": mode, "format": snap.Format, "version": snap.Version,
			"created_at": snap.CreatedAt, "includes": snap.Includes, "counts": counts,
		})

	case r.Method == http.MethodPost && sub == "reset":
		var req struct {
			Confirmation string `json:"confirmation"`
			PurgeFiles   bool   `json:"purge_files"`
		}
		if err := jsonBody(r, &req); err != nil { jsonErr(w, err.Error(), http.StatusBadRequest); return }
		if req.Confirmation != resetPhrase { jsonErr(w, "type RESET C2 to confirm", http.StatusBadRequest); return }
		backupName := "c2-reset-" + time.Now().UTC().Format("20060102-150405") + ".db"
		backupPath := filepath.Join(s.cfg.DataDir, "backups", backupName)
		if err := backupSQLite(s.db.db, s.cfg.DBPath, backupPath); err != nil { jsonErr(w, "backup failed: "+err.Error(), http.StatusInternalServerError); return }
		if err := s.db.ResetOperationalData(); err != nil { jsonErr(w, "reset failed: "+err.Error(), http.StatusInternalServerError); return }
		if req.PurgeFiles {
			if err := clearDirectoryContents(filepath.Join(s.cfg.DataDir, "uploads")); err != nil { jsonErr(w, "uploads cleanup failed: "+err.Error(), http.StatusInternalServerError); return }
			if err := clearDirectoryContents(filepath.Join(s.cfg.DataDir, "downloads")); err != nil { jsonErr(w, "downloads cleanup failed: "+err.Error(), http.StatusInternalServerError); return }
		}
		s.ghostMu.Lock()
		s.ghostAgents = make(map[string][]byte)
		s.ghostMu.Unlock()
		s.meshMu.Lock()
		s.meshPeers = make(map[string]meshPeer)
		s.meshMu.Unlock()
		jsonOK(w, map[string]any{"status": "reset", "backup": filepath.ToSlash(backupPath), "purge_files": req.PurgeFiles, "roles_preserved": true})

	default:
		jsonErr(w, "not found", http.StatusNotFound)
	}
}

func readSnapshotMultipart(r *http.Request) (*c2Snapshot, error) {
	if err := r.ParseMultipartForm(128 << 20); err != nil { return nil, fmt.Errorf("parse multipart: %w", err) }
	passphrase := r.FormValue("passphrase")
	file, _, err := r.FormFile("file")
	if err != nil { return nil, fmt.Errorf("snapshot file required: %w", err) }
	defer file.Close()
	blob, err := io.ReadAll(io.LimitReader(file, 128<<20))
	if err != nil { return nil, err }
	return decryptSnapshot(blob, passphrase)
}
