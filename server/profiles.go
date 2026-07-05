package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// MalleableProfile holds parsed C2 profile metadata.
type MalleableProfile struct {
	Name      string `json:"name"`
	Source    string `json:"source"`    // URL or "manual"
	UserAgent string `json:"user_agent"`
	URIs      string `json:"uris"`      // comma-separated
	Headers   string `json:"headers"`   // semicolon-separated key:value
	CreatedAt string `json:"created_at"`
	RawText   string `json:"raw_text,omitempty"`
}

// profilesDir returns the path to the profiles storage directory.
func (s *Server) profilesDir() string {
	return filepath.Join(s.cfg.DataDir, "profiles")
}

// sanitizeProfileName strips unsafe characters and validates length.
// Returns error if the name is empty, too long, or contains "..".
func sanitizeProfileName(name string) (string, error) {
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid profile name")
	}
	// keep alphanumeric + dash/dot/underscore
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	clean := b.String()
	if clean == "" {
		return "", fmt.Errorf("profile name must not be empty")
	}
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean, nil
}

// parseProfile parses a Cobalt Strike Malleable C2 .profile text and extracts
// UserAgent, URIs (from http-get set uri), and Headers (from http-get client header).
func parseProfile(text string) (ua, uris, headers string) {
	reUA := regexp.MustCompile(`(?i)^\s*set\s+useragent\s+"([^"]+)"\s*;`)
	reURI := regexp.MustCompile(`(?i)^\s*set\s+uri\s+"([^"]+)"\s*;`)
	reHdr := regexp.MustCompile(`(?i)^\s*header\s+"([^"]+)"\s+"([^"]+)"\s*;`)

	// Track brace depth to detect http-get and client blocks
	inHTTPGet := false
	inClient := false
	depth := 0         // overall brace depth
	httpGetDepth := 0  // depth at which http-get was opened
	clientDepth := 0   // depth at which client was opened

	var hdrParts []string

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)

		// Strip C-style line comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Count brace opens/closes
		opens := strings.Count(line, "{")
		closes := strings.Count(line, "}")

		// Detect block entry before incrementing depth
		if opens > 0 {
			lower := strings.ToLower(line)
			if !inHTTPGet && strings.HasPrefix(lower, "http-get") {
				inHTTPGet = true
				httpGetDepth = depth
			}
			if inHTTPGet && !inClient && strings.HasPrefix(lower, "client") {
				inClient = true
				clientDepth = depth
			}
		}

		depth += opens - closes

		// Detect block exit
		if inClient && depth <= clientDepth {
			inClient = false
		}
		if inHTTPGet && depth <= httpGetDepth {
			inHTTPGet = false
		}

		// Top-level useragent
		if !inHTTPGet {
			if m := reUA.FindStringSubmatch(line); m != nil {
				ua = m[1]
			}
		}

		// uri inside http-get block (any depth within it)
		if inHTTPGet {
			if m := reURI.FindStringSubmatch(line); m != nil {
				// Space-separated URIs → comma-separated
				parts := strings.Fields(m[1])
				uris = strings.Join(parts, ",")
			}
		}

		// headers inside http-get > client block
		if inClient {
			if m := reHdr.FindStringSubmatch(line); m != nil {
				hdrParts = append(hdrParts, m[1]+":"+m[2])
			}
		}
	}

	headers = strings.Join(hdrParts, ";")
	return
}

// loadProfile reads a single profile JSON file by name (no extension needed).
func (s *Server) loadProfile(name string) (*MalleableProfile, error) {
	path := filepath.Join(s.profilesDir(), name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p MalleableProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// saveProfile writes a profile to disk as JSON.
func (s *Server) saveProfile(p *MalleableProfile) error {
	if err := os.MkdirAll(s.profilesDir(), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.profilesDir(), p.Name+".json")
	return os.WriteFile(path, data, 0644)
}

// listProfiles returns all saved profiles without RawText.
func (s *Server) listProfiles() ([]*MalleableProfile, error) {
	if err := os.MkdirAll(s.profilesDir(), 0755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.profilesDir())
	if err != nil {
		return nil, err
	}
	var out []*MalleableProfile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		p, err := s.loadProfile(name)
		if err != nil {
			continue
		}
		// Strip raw text from list response
		stripped := *p
		stripped.RawText = ""
		out = append(out, &stripped)
	}
	return out, nil
}

// ── API handlers ──────────────────────────────────────────────────────────────

// apiProfiles handles GET/POST /api/profiles and DELETE /api/profiles/{name}.
func (s *Server) apiProfiles(w http.ResponseWriter, r *http.Request) {
	// Ensure storage directory exists
	if err := os.MkdirAll(s.profilesDir(), 0755); err != nil {
		jsonErr(w, "profiles dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Determine if this is a sub-resource request: /api/profiles/{name}
	suffix := strings.TrimPrefix(r.URL.Path, "/api/profiles")
	suffix = strings.TrimPrefix(suffix, "/")

	// Route: /api/profiles/fetch?url=...
	if suffix == "fetch" {
		s.apiProfileFetch(w, r)
		return
	}

	switch {
	case suffix == "" || suffix == "/":
		// Collection endpoint
		switch r.Method {
		case http.MethodGet:
			profiles, err := s.listProfiles()
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if profiles == nil {
				profiles = []*MalleableProfile{}
			}
			jsonOK(w, profiles)

		case http.MethodPost:
			var req struct {
				Name    string `json:"name"`
				Source  string `json:"source"`
				RawText string `json:"raw_text"`
			}
			if err := jsonBody(r, &req); err != nil {
				jsonErr(w, err.Error(), http.StatusBadRequest)
				return
			}
			name, err := sanitizeProfileName(req.Name)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusBadRequest)
				return
			}
			source := req.Source
			if source == "" {
				source = "manual"
			}
			ua, uris, hdrs := parseProfile(req.RawText)
			p := &MalleableProfile{
				Name:      name,
				Source:    source,
				UserAgent: ua,
				URIs:      uris,
				Headers:   hdrs,
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
				RawText:   req.RawText,
			}
			if err := s.saveProfile(p); err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			op := operatorFromCert(r)
			s.printf("[%s] profile saved: %s\n", op, name)
			jsonOK(w, p)

		default:
			jsonErr(w, "GET or POST required", http.StatusMethodNotAllowed)
		}

	default:
		// /api/profiles/{name} — resource endpoint
		// Check if it's the fetch sub-path
		if suffix == "fetch" {
			s.apiProfileFetch(w, r)
			return
		}

		name, err := sanitizeProfileName(suffix)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodDelete:
			path := filepath.Join(s.profilesDir(), name+".json")
			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					jsonErr(w, "profile not found", http.StatusNotFound)
				} else {
					jsonErr(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
			op := operatorFromCert(r)
			s.printf("[%s] profile deleted: %s\n", op, name)
			jsonOK(w, map[string]string{"status": "deleted"})

		case http.MethodGet:
			p, err := s.loadProfile(name)
			if err != nil {
				jsonErr(w, "profile not found", http.StatusNotFound)
				return
			}
			jsonOK(w, p)

		default:
			jsonErr(w, "GET or DELETE required", http.StatusMethodNotAllowed)
		}
	}
}

// apiProfileFetch fetches a .profile file from a remote URL server-side
// and returns its text content (avoids browser CORS restrictions).
// GET /api/profiles/fetch?url=<encoded-url>
func (s *Server) apiProfileFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		jsonErr(w, "url parameter required", http.StatusBadRequest)
		return
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		jsonErr(w, "only http/https URLs are allowed", http.StatusBadRequest)
		return
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		jsonErr(w, "fetch failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512 KB max
	if err != nil {
		jsonErr(w, "read failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]string{"text": string(body)})
}
