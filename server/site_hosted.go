package server

// site_hosted.go implements the Cobalt Strike-style "Host File" resource
// manager. Hosted files are independent from a particular clone, so the same
// resource can be selected as the attack for multiple authorized lab sites.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	hostedManifestName = "hosted.json"
	hostedIDLength     = 32
)

type hostedFile struct {
	ID         string    `json:"id"`
	Filename   string    `json:"filename"`
	LocalURI   string    `json:"local_uri"`
	LocalHost  string    `json:"local_host,omitempty"`
	LocalPort  int       `json:"local_port,omitempty"`
	MimeType   string    `json:"mime_type"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	PublicPath string    `json:"public_path"`
	PublicURL  string    `json:"public_url"`
}

type hostedManifest struct {
	Files []hostedFile `json:"files"`
}

type hostedArtifactRequest struct {
	Artifact  string `json:"artifact"`
	LocalURI  string `json:"local_uri"`
	LocalHost string `json:"local_host"`
	LocalPort int    `json:"local_port"`
	MimeType  string `json:"mime_type"`
}

func (s *Server) hostedDir() string {
	return filepath.Join(s.sitesDir(), "hosted")
}

func (s *Server) hostedFilesDir() string {
	return filepath.Join(s.hostedDir(), "files")
}

func validateHostedID(id string) error {
	if len(id) != hostedIDLength {
		return fmt.Errorf("invalid hosted file id")
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'f') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("invalid hosted file id")
		}
	}
	return nil
}

func normalizeHostedURI(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "/"
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	if strings.ContainsAny(raw, "\\?#\r\n") {
		return "", fmt.Errorf("local URI must be a path without query or fragment")
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("invalid local URI")
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == ".." || strings.IndexFunc(segment, unicode.IsControl) >= 0 {
			return "", fmt.Errorf("invalid local URI")
		}
	}
	trailingSlash := strings.HasSuffix(decoded, "/")
	clean := path.Clean(decoded)
	if clean == "." {
		clean = "/"
	}
	if !strings.HasPrefix(clean, "/") || len(clean) > 512 {
		return "", fmt.Errorf("invalid local URI")
	}
	if trailingSlash && clean != "/" {
		clean += "/"
	}
	return clean, nil
}

func normalizeHostedHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 253 || strings.ContainsAny(raw, "/?#\\\r\n") {
		return "", fmt.Errorf("invalid local host")
	}
	u, err := url.Parse("//" + raw)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Hostname() == "" {
		return "", fmt.Errorf("invalid local host")
	}
	if u.Port() != "" {
		return "", fmt.Errorf("local host must not include a port")
	}
	return u.Hostname(), nil
}

func normalizeHostedPort(raw string, fallback int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("local port must be between 1 and 65535")
	}
	return port, nil
}

func normalizeHostedMime(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "auto") {
		return "auto", nil
	}
	if len(raw) > 128 || strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("invalid MIME type")
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil || mediaType == "" {
		return "", fmt.Errorf("invalid MIME type")
	}
	return raw, nil
}

func newHostedID() (string, error) {
	buf := make([]byte, hostedIDLength/2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *Server) readHosted() (hostedManifest, error) {
	data, err := os.ReadFile(filepath.Join(s.sitesDir(), hostedManifestName))
	if os.IsNotExist(err) {
		return hostedManifest{Files: []hostedFile{}}, nil
	}
	if err != nil {
		return hostedManifest{}, err
	}
	var manifest hostedManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return hostedManifest{}, fmt.Errorf("invalid hosted manifest: %w", err)
	}
	if manifest.Files == nil {
		manifest.Files = []hostedFile{}
	}
	return manifest, nil
}

func (s *Server) writeHosted(manifest hostedManifest) error {
	if err := os.MkdirAll(s.hostedFilesDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.sitesDir(), hostedManifestName+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.sitesDir(), hostedManifestName))
}

func (s *Server) publicHTTPPort() int {
	if s.cfg.HTTPPort > 0 {
		return s.cfg.HTTPPort
	}
	return 8080
}

func (s *Server) publicHTTPHost() string {
	for _, ip := range localIPs() {
		if !ip.IsLoopback() {
			return ip.String()
		}
	}
	return "127.0.0.1"
}

func httpURL(host string, port int, requestPath string) string {
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + requestPath
}

func (s *Server) hostedPublicPath(file hostedFile) string {
	uri := file.LocalURI
	if uri == "" {
		uri = "/"
	}
	return "/hosted/" + url.PathEscape(file.ID) + uri
}

func (s *Server) publicHosted(file hostedFile) hostedFile {
	file.PublicPath = s.hostedPublicPath(file)
	host := file.LocalHost
	if host == "" {
		host = s.publicHTTPHost()
	}
	port := file.LocalPort
	if port == 0 {
		port = s.publicHTTPPort()
	}
	file.PublicURL = httpURL(host, port, file.PublicPath)
	return file
}

func (s *Server) findHosted(id string) (hostedFile, error) {
	if err := validateHostedID(id); err != nil {
		return hostedFile{}, err
	}
	manifest, err := s.readHosted()
	if err != nil {
		return hostedFile{}, err
	}
	for _, file := range manifest.Files {
		if file.ID == id {
			return s.publicHosted(file), nil
		}
	}
	return hostedFile{}, os.ErrNotExist
}

func (s *Server) apiHosted(w http.ResponseWriter, r *http.Request) {
	sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/hosted"), "/")
	if sub == "" {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			manifest, err := s.readHosted()
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			out := make([]hostedFile, 0, len(manifest.Files))
			for _, file := range manifest.Files {
				out = append(out, s.publicHosted(file))
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Filename < out[j].Filename })
			jsonOK(w, out)
			return
		}
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			s.apiHostedArtifact(w, r)
		} else {
			s.apiHostedUpload(w, r)
		}
		return
	}
	parts := strings.Split(sub, "/")
	if len(parts) != 1 {
		jsonErr(w, "unknown hosted file endpoint", http.StatusNotFound)
		return
	}
	id := parts[0]
	if r.Method != http.MethodDelete {
		jsonErr(w, "DELETE required", http.StatusMethodNotAllowed)
		return
	}
	s.apiHostedDelete(w, id)
}

func artifactFileForHosting(name string) (string, error) {
	clean, err := sanitizeSiteFilename(name)
	if err != nil || clean != strings.TrimSpace(name) {
		return "", fmt.Errorf("invalid artifact filename")
	}
	root := projectRoot()
	for _, dir := range []string{filepath.Join(root, "bin", "payloads"), filepath.Join(root, "bin", "delivery")} {
		candidate := filepath.Join(dir, clean)
		if filepath.Dir(candidate) != dir {
			continue
		}
		info, statErr := os.Stat(candidate)
		if statErr == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

func (s *Server) saveHostedFile(name string, data []byte, uri, host string, port int, mimeType string) (hostedFile, error) {
	id, err := newHostedID()
	if err != nil {
		return hostedFile{}, err
	}
	now := time.Now().UTC()
	entry := hostedFile{ID: id, Filename: name, LocalURI: uri, LocalHost: host, LocalPort: port, MimeType: mimeType, Size: int64(len(data)), CreatedAt: now, UpdatedAt: now}
	if err := os.MkdirAll(s.hostedFilesDir(), 0700); err != nil {
		return hostedFile{}, err
	}
	filePath := filepath.Join(s.hostedFilesDir(), id)
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return hostedFile{}, err
	}
	manifest, err := s.readHosted()
	if err != nil {
		_ = os.Remove(filePath)
		return hostedFile{}, err
	}
	manifest.Files = append(manifest.Files, entry)
	if err := s.writeHosted(manifest); err != nil {
		_ = os.Remove(filePath)
		return hostedFile{}, err
	}
	return entry, nil
}

func (s *Server) hostedOptions(w http.ResponseWriter, r *http.Request, localURI, localHost string, localPort int, mimeType string) (string, string, int, string, bool) {
	uri, err := normalizeHostedURI(localURI)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return "", "", 0, "", false
	}
	host, err := normalizeHostedHost(localHost)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return "", "", 0, "", false
	}
	portText := ""
	if localPort != 0 {
		portText = strconv.Itoa(localPort)
	}
	port, err := normalizeHostedPort(portText, s.publicHTTPPort())
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return "", "", 0, "", false
	}
	mimeValue, err := normalizeHostedMime(mimeType)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return "", "", 0, "", false
	}
	return uri, host, port, mimeValue, true
}

func (s *Server) apiHostedArtifact(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req hostedArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	artifactPath, err := artifactFileForHosting(req.Artifact)
	if err != nil {
		if os.IsNotExist(err) {
			jsonErr(w, "generated artifact not found", http.StatusNotFound)
		} else {
			jsonErr(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	info, err := os.Stat(artifactPath)
	if err != nil {
		jsonErr(w, "stat artifact: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info.Size() > maxSiteFile {
		jsonErr(w, "artifact exceeds 256 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		jsonErr(w, "read artifact: "+err.Error(), http.StatusInternalServerError)
		return
	}
	uri, host, port, mimeType, ok := s.hostedOptions(w, r, req.LocalURI, req.LocalHost, req.LocalPort, req.MimeType)
	if !ok {
		return
	}
	s.sitesMu.Lock()
	entry, err := s.saveHostedFile(filepath.Base(artifactPath), data, uri, host, port, mimeType)
	s.sitesMu.Unlock()
	if err != nil {
		jsonErr(w, "save hosted artifact: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, s.publicHosted(entry))
}

func (s *Server) apiHostedUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSiteFile+1)
	if err := r.ParseMultipartForm(maxSiteFile); err != nil {
		jsonErr(w, "parse upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, "file field required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	name, err := sanitizeSiteFilename(header.Filename)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	portValue := 0
	if strings.TrimSpace(r.FormValue("local_port")) != "" {
		portValue, err = strconv.Atoi(strings.TrimSpace(r.FormValue("local_port")))
		if err != nil {
			jsonErr(w, "local port must be numeric", http.StatusBadRequest)
			return
		}
	}
	uri, host, port, mimeType, ok := s.hostedOptions(w, r, r.FormValue("local_uri"), r.FormValue("local_host"), portValue, r.FormValue("mime_type"))
	if !ok {
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSiteFile+1))
	if err != nil {
		jsonErr(w, "read upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(data) > maxSiteFile {
		jsonErr(w, "file exceeds 256 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}
	s.sitesMu.Lock()
	defer s.sitesMu.Unlock()
	entry, err := s.saveHostedFile(name, data, uri, host, port, mimeType)
	if err != nil {
		jsonErr(w, "save hosted file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, s.publicHosted(entry))
}

func (s *Server) apiHostedDelete(w http.ResponseWriter, id string) {
	if err := validateHostedID(id); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.sitesMu.Lock()
	defer s.sitesMu.Unlock()
	manifest, err := s.readHosted()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	filtered := make([]hostedFile, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		if file.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, file)
	}
	if !found {
		jsonErr(w, "hosted file not found", http.StatusNotFound)
		return
	}
	// Removing a resource also removes any clone injection that references it.
	if entries, readErr := os.ReadDir(s.sitesDir()); readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == "hosted" {
				continue
			}
			clone, readCloneErr := s.readSite(entry.Name())
			if readCloneErr == nil && clone.AttackID == id {
				if updateErr := s.updateSiteInjection(entry.Name(), clone, "", "", false); updateErr != nil {
					jsonErr(w, "remove clone injection: "+updateErr.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}
	if err := os.Remove(filepath.Join(s.hostedFilesDir(), id)); err != nil && !os.IsNotExist(err) {
		jsonErr(w, "delete hosted file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	manifest.Files = filtered
	if err := s.writeHosted(manifest); err != nil {
		jsonErr(w, "write hosted manifest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"id": id, "status": "deleted"})
}

func (s *Server) handleHostedPublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sub := strings.TrimPrefix(r.URL.Path, "/hosted/")
	parts := strings.SplitN(sub, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	file, err := s.findHosted(parts[0])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	requestURI, err := normalizeHostedURI("/" + parts[1])
	if err != nil || requestURI != file.LocalURI {
		http.NotFound(w, r)
		return
	}
	filePath := filepath.Join(s.hostedFilesDir(), file.ID)
	if _, err := os.Stat(filePath); err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := file.MimeType
	if contentType == "" || contentType == "auto" {
		contentType = mime.TypeByExtension(filepath.Ext(file.Filename))
		if contentType == "" {
			if data, readErr := os.ReadFile(filePath); readErr == nil {
				contentType = http.DetectContentType(data)
			}
		}
	}
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": file.Filename}); disposition != "" {
		w.Header().Set("Content-Disposition", disposition)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, filePath)
}
