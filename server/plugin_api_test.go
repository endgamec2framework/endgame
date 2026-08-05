package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"redteam/plugins"
)

func TestPluginHostContextIsScopedAndSanitized(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	if err := db.RegisterAgent(&Agent{
		ID: "agent-1", Hostname: "dc01", Username: "alice", OS: "linux/amd64",
		IP: "10.0.0.5", AESKey: []byte("secret-agent-key"), Language: "go",
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{db: db}
	module := plugins.Module{Manifest: plugins.Manifest{
		ID: "context-reader", Permissions: []string{"data.read", "agent.context.read"},
	}}
	raw, err := s.buildPluginHostContext(module, "alice", json.RawMessage(`{"agent_id":"agent-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, hex.EncodeToString([]byte("secret-agent-key"))) || strings.Contains(text, "aes_key") {
		t.Fatalf("host context leaked agent key: %s", text)
	}
	var context struct {
		Agents []*pluginAgentContext `json:"agents"`
		Agent  *pluginAgentContext  `json:"agent"`
	}
	if err := json.Unmarshal(raw, &context); err != nil {
		t.Fatal(err)
	}
	if len(context.Agents) != 1 || context.Agent == nil || context.Agent.ID != "agent-1" {
		t.Fatalf("unexpected sanitized context: %#v", context)
	}
}

func TestPluginHostContextIncludesBloodHoundOnlyWithPermission(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	if err := db.BHUpsertGraph(&BHGraph{
		Nodes: []*BHNode{{SID: "S-1", Name: "DC01", Type: "computer"}},
		Edges: []*BHEdge{{SourceSID: "S-1", TargetSID: "S-2", EdgeType: "AdminTo"}},
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	without := plugins.Module{Manifest: plugins.Manifest{ID: "no-graph"}}
	raw, err := s.buildPluginHostContext(without, "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"graph"`) {
		t.Fatalf("graph was exposed without permission: %s", raw)
	}
	with := plugins.Module{Manifest: plugins.Manifest{ID: "graph-reader", Permissions: []string{"graph.read"}}}
	raw, err = s.buildPluginHostContext(with, "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "DC01") || !strings.Contains(string(raw), "AdminTo") {
		t.Fatalf("graph context missing: %s", raw)
	}
}

func TestPluginListEndpointIsViewerReadable(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	registry := plugins.NewRegistry(filepath.Join(t.TempDir(), "plugins"))
	if err := registry.Discover(); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, plugins: registry}
	req := httptest.NewRequest(http.MethodGet, "/api/plugins", nil)
	rec := httptest.NewRecorder()
	s.requirePluginRole(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin list returned status %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK   bool `json:"ok"`
		Data struct {
			APIVersion int `json:"api_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Data.APIVersion != plugins.APIVersion {
		t.Fatalf("unexpected plugin list response: %s", rec.Body.String())
	}
}

func TestPluginMutationRequiresOperatorRole(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	if err := db.SetOperatorRole("unknown", RoleViewer); err != nil {
		t.Fatal(err)
	}
	registry := plugins.NewRegistry(filepath.Join(t.TempDir(), "plugins"))
	if err := registry.Discover(); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, plugins: registry}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/reload", nil)
	rec := httptest.NewRecorder()
	s.requirePluginRole(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer was allowed to mutate plugins: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
