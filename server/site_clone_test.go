package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeSiteSlug(t *testing.T) {
	if got := sanitizeSiteSlug("  GPU-Z / Download  "); got != "gpu-z-download" {
		t.Fatalf("sanitizeSiteSlug() = %q", got)
	}
	if err := validateSiteSlug("gpu-z-download"); err != nil {
		t.Fatalf("valid slug rejected: %v", err)
	}
	if err := validateSiteSlug("../bad"); err == nil {
		t.Fatal("path traversal slug accepted")
	}
}

func TestRewriteSiteHTMLRewritesAssets(t *testing.T) {
	base, _ := url.Parse("https://example.test/download/index.html")
	allowed := map[string]bool{siteHostKey(base): true}
	input := []byte(`<html><head><base href="https://example.test/"><link rel="stylesheet" href="/css/site.css"></head><body><img src="images/logo.png" srcset="images/logo.png 1x, images/logo@2x.png 2x"><a href="/next">next</a></body></html>`)
	out, err := rewriteSiteHTML(input, "demo", base, allowed)
	if err != nil {
		t.Fatalf("rewriteSiteHTML() error = %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `/site/demo/asset?u=`) {
		t.Fatalf("asset was not rewritten: %s", text)
	}
	if strings.Contains(text, `srcset="images/`) {
		t.Fatalf("srcset asset was not rewritten: %s", text)
	}
	if strings.Contains(text, `<base`) {
		t.Fatalf("base tag was not removed: %s", text)
	}
	if !strings.Contains(text, `href="/next"`) {
		t.Fatalf("navigation link was unexpectedly rewritten: %s", text)
	}
}

func TestInjectSiteDownloadIsIdempotent(t *testing.T) {
	input := []byte(`<html><body><h1>GOAD</h1></body></html>`)
	out, err := injectSiteDownload(input, "/site/demo/download/test.txt")
	if err != nil {
		t.Fatalf("first injection error = %v", err)
	}
	out, err = injectSiteDownload(out, "/site/demo/download/test.txt")
	if err != nil {
		t.Fatalf("second injection error = %v", err)
	}
	if got := strings.Count(string(out), `data-endgame-site-download="1"`); got != 1 {
		t.Fatalf("injected iframe count = %d, want 1", got)
	}
	if !strings.Contains(string(out), `src="/site/demo/download/test.txt"`) {
		t.Fatalf("download path missing: %s", out)
	}
}

func TestRewriteSiteCSSRewritesAllowedURLs(t *testing.T) {
	base, _ := url.Parse("https://example.test/css/site.css")
	allowed := map[string]bool{"example.test": true, "cdn.example.test": true}
	input := []byte(`body{background:url("../img/bg.png")} .x{background:url(data:image/png;base64,abc)}`)
	out := rewriteSiteCSS(input, "demo", base, allowed)
	text := string(out)
	if !strings.Contains(text, `/site/demo/asset?u=`) {
		t.Fatalf("CSS asset was not rewritten: %s", text)
	}
	if !strings.Contains(text, "data:image/png;base64,abc") {
		t.Fatalf("data URL was changed: %s", text)
	}
}

func TestFetchSiteHTMLRejectsNonHTML(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("binary"))
	}))
	defer ts.Close()
	if _, _, err := fetchSiteHTML(ts.URL); err == nil {
		t.Fatal("binary upstream was accepted as HTML")
	}
}

func TestSiteManagementHTTPFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<html><head><title>GOAD</title></head><body><img src="/logo.svg"><a href="/next">next</a></body></html>`)
		case "/logo.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			_, _ = io.WriteString(w, `<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="5"/></svg>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	s := &Server{cfg: Config{DataDir: t.TempDir(), HTTPPort: 18080}}
	if err := os.MkdirAll(s.sitesDir(), 0700); err != nil {
		t.Fatal(err)
	}

	cloneReq := httptest.NewRequest(http.MethodPost, "/api/sites/clone", strings.NewReader(`{"name":"GOAD","slug":"goad","url":"`+upstream.URL+`/"}`))
	cloneReq.Header.Set("Content-Type", "application/json")
	cloneRec := httptest.NewRecorder()
	s.apiSites(cloneRec, cloneReq)
	if cloneRec.Code != http.StatusOK {
		t.Fatalf("clone status = %d: %s", cloneRec.Code, cloneRec.Body.String())
	}
	var cloneResp struct {
		OK   bool `json:"ok"`
		Data Site `json:"data"`
	}
	if err := json.Unmarshal(cloneRec.Body.Bytes(), &cloneResp); err != nil {
		t.Fatal(err)
	}
	if !cloneResp.OK || cloneResp.Data.Slug != "goad" {
		t.Fatalf("unexpected clone response: %+v", cloneResp)
	}
	if !strings.Contains(cloneResp.Data.PublicURL, ":18080/site/goad/") {
		t.Fatalf("unexpected public URL: %q", cloneResp.Data.PublicURL)
	}

	publicRec := httptest.NewRecorder()
	s.handleSitePublic(publicRec, httptest.NewRequest(http.MethodGet, "/site/goad/", nil))
	if publicRec.Code != http.StatusOK || !strings.Contains(publicRec.Body.String(), "/site/goad/asset?u=") {
		t.Fatalf("public clone not served correctly: status=%d body=%s", publicRec.Code, publicRec.Body.String())
	}

	var upload bytes.Buffer
	form := multipart.NewWriter(&upload)
	part, err := form.CreateFormFile("file", "payload.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("lab-payload"))
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	uploadReq := httptest.NewRequest(http.MethodPost, "/api/sites/goad/files", &upload)
	uploadReq.Header.Set("Content-Type", form.FormDataContentType())
	uploadRec := httptest.NewRecorder()
	s.apiSites(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusOK {
		t.Fatalf("upload status = %d: %s", uploadRec.Code, uploadRec.Body.String())
	}

	injectReq := httptest.NewRequest(http.MethodPost, "/api/sites/goad/inject", strings.NewReader(`{"filename":"payload.bin","download_name":"update.bin","auto_download":true}`))
	injectReq.Header.Set("Content-Type", "application/json")
	injectRec := httptest.NewRecorder()
	s.apiSites(injectRec, injectReq)
	if injectRec.Code != http.StatusOK {
		t.Fatalf("inject status = %d: %s", injectRec.Code, injectRec.Body.String())
	}

	downloadRec := httptest.NewRecorder()
	s.handleSitePublic(downloadRec, httptest.NewRequest(http.MethodGet, "/site/goad/download/update.bin", nil))
	if downloadRec.Code != http.StatusOK || downloadRec.Body.String() != "lab-payload" {
		t.Fatalf("download failed: status=%d body=%q", downloadRec.Code, downloadRec.Body.String())
	}
	if got := downloadRec.Header().Get("Content-Disposition"); !strings.Contains(got, "update.bin") {
		t.Fatalf("download disposition = %q", got)
	}

	disableReq := httptest.NewRequest(http.MethodPost, "/api/sites/goad/inject", strings.NewReader(`{"enabled":false}`))
	disableReq.Header.Set("Content-Type", "application/json")
	disableRec := httptest.NewRecorder()
	s.apiSites(disableRec, disableReq)
	if disableRec.Code != http.StatusOK {
		t.Fatalf("disable status = %d: %s", disableRec.Code, disableRec.Body.String())
	}
	cloneAfterDisable, err := os.ReadFile(filepath.Join(s.sitesDir(), "goad", siteIndexName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cloneAfterDisable), "data-endgame-site-download") {
		t.Fatal("download iframe remained after disabling injection")
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/sites/goad", nil)
	deleteRec := httptest.NewRecorder()
	s.apiSites(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
	missingRec := httptest.NewRecorder()
	s.handleSitePublic(missingRec, httptest.NewRequest(http.MethodGet, "/site/goad/", nil))
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("deleted site status = %d", missingRec.Code)
	}
}

func TestHostedFileAndAttackFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html><body><h1>GOAD</h1></body></html>`)
	}))
	defer upstream.Close()

	s := &Server{cfg: Config{DataDir: t.TempDir(), HTTPPort: 18080}}
	if err := os.MkdirAll(s.sitesDir(), 0700); err != nil {
		t.Fatal(err)
	}

	var upload bytes.Buffer
	form := multipart.NewWriter(&upload)
	_ = form.WriteField("local_uri", "/dl/tools/agent.exe")
	_ = form.WriteField("local_host", "lab.example")
	_ = form.WriteField("local_port", "8088")
	_ = form.WriteField("mime_type", "application/octet-stream")
	part, err := form.CreateFormFile("file", "agent.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("authorized-lab-agent"))
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	hostReq := httptest.NewRequest(http.MethodPost, "/api/hosted", &upload)
	hostReq.Header.Set("Content-Type", form.FormDataContentType())
	hostRec := httptest.NewRecorder()
	s.apiHosted(hostRec, hostReq)
	if hostRec.Code != http.StatusOK {
		t.Fatalf("host file status = %d: %s", hostRec.Code, hostRec.Body.String())
	}
	var hostResp struct {
		OK   bool       `json:"ok"`
		Data hostedFile `json:"data"`
	}
	if err := json.Unmarshal(hostRec.Body.Bytes(), &hostResp); err != nil {
		t.Fatal(err)
	}
	if !hostResp.OK || hostResp.Data.ID == "" || hostResp.Data.LocalURI != "/dl/tools/agent.exe" {
		t.Fatalf("unexpected hosted file: %+v", hostResp)
	}
	if got := hostResp.Data.PublicURL; got != "http://lab.example:8088/hosted/"+hostResp.Data.ID+"/dl/tools/agent.exe" {
		t.Fatalf("hosted URL = %q", got)
	}

	publicRec := httptest.NewRecorder()
	s.handleHostedPublic(publicRec, httptest.NewRequest(http.MethodGet, "/hosted/"+hostResp.Data.ID+"/dl/tools/agent.exe", nil))
	if publicRec.Code != http.StatusOK || publicRec.Body.String() != "authorized-lab-agent" {
		t.Fatalf("hosted file failed: status=%d body=%q", publicRec.Code, publicRec.Body.String())
	}
	if got := publicRec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("hosted content type = %q", got)
	}

	cloneBody, _ := json.Marshal(map[string]interface{}{
		"name":          "GOAD",
		"slug":          "goad",
		"url":           upstream.URL + "/",
		"clone_uri":     "/download/gpu-z/",
		"local_host":    "lab.example",
		"local_port":    8088,
		"attack_id":     hostResp.Data.ID,
		"download_name": "agent.exe",
	})
	cloneReq := httptest.NewRequest(http.MethodPost, "/api/sites/clone", bytes.NewReader(cloneBody))
	cloneReq.Header.Set("Content-Type", "application/json")
	cloneRec := httptest.NewRecorder()
	s.apiSites(cloneRec, cloneReq)
	if cloneRec.Code != http.StatusOK {
		t.Fatalf("clone with attack status = %d: %s", cloneRec.Code, cloneRec.Body.String())
	}
	var cloneResp struct {
		OK   bool `json:"ok"`
		Data Site `json:"data"`
	}
	if err := json.Unmarshal(cloneRec.Body.Bytes(), &cloneResp); err != nil {
		t.Fatal(err)
	}
	if !cloneResp.OK || cloneResp.Data.AttackID != hostResp.Data.ID || cloneResp.Data.CloneURI != "/download/gpu-z/" {
		t.Fatalf("unexpected clone attack state: %+v", cloneResp.Data)
	}
	if got := cloneResp.Data.CloneURL; got != "http://lab.example:8088/site/goad/download/gpu-z/" {
		t.Fatalf("clone URL = %q", got)
	}
	clonePublicRec := httptest.NewRecorder()
	s.handleSitePublic(clonePublicRec, httptest.NewRequest(http.MethodGet, "/site/goad/download/gpu-z/", nil))
	if clonePublicRec.Code != http.StatusOK || !strings.Contains(clonePublicRec.Body.String(), "/hosted/"+hostResp.Data.ID+"/dl/tools/agent.exe") {
		t.Fatalf("clone page with attack failed: status=%d body=%s", clonePublicRec.Code, clonePublicRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/hosted/"+hostResp.Data.ID, nil)
	deleteRec := httptest.NewRecorder()
	s.apiHosted(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("host file delete status = %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
	updated, err := s.readSite("goad")
	if err != nil {
		t.Fatal(err)
	}
	if updated.AttackID != "" || updated.AutoDownload {
		t.Fatalf("hosted file deletion left injection active: %+v", updated.Site)
	}
}
