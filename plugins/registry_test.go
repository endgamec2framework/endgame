package plugins

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir string, manifest Manifest) {
	t.Helper()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFilename), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestManifestValidationRequiresLicenseAndEntrypoint(t *testing.T) {
	m := Manifest{ID: "example", Name: "Example", Version: "1.0.0", APIVersion: APIVersion, Type: TypeAnalyzer}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "license") {
		t.Fatalf("expected license validation error, got %v", err)
	}
	m.License = "MIT"
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "entrypoint") {
		t.Fatalf("expected entrypoint validation error, got %v", err)
	}
}

func TestRegistryBlocksUnknownPermissions(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "blocked")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, dir, Manifest{
		ID: "blocked", Name: "Blocked", Version: "1.0.0", APIVersion: APIVersion,
		Type: TypeAnalyzer, License: "MIT", Entrypoint: "run", Permissions: []string{"agent.task"},
	})
	registry := NewRegistry(root)
	if err := registry.Discover(); err != nil {
		t.Fatal(err)
	}
	module, ok := registry.Get("blocked")
	if !ok || module.Status != "blocked" {
		t.Fatalf("expected blocked module, got %#v", module)
	}
	if _, ok := AllowedPermissions["agent.task"]; ok {
		t.Fatal("agent.task must not be in the initial safe permission set")
	}
}

func TestRegistryRunsExternalModule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell helper is POSIX-specific")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "example-analyzer")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(dir, "run.sh")
	script := `#!/bin/sh
request=$(cat)
run_id=$(printf '%s' "$request" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
module_id=$(printf '%s' "$request" | sed -n 's/.*"module_id":"\([^"]*\)".*/\1/p')
printf '{"protocol_version":1,"run_id":"%s","module_id":"%s","ok":true,"result":{"schema_version":1,"module_id":"%s","summary":"ok"}}\n' "$run_id" "$module_id" "$module_id"
`
	if err := os.WriteFile(entry, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, dir, Manifest{
		ID: "example-analyzer", Name: "Example", Version: "1.0.0", APIVersion: APIVersion,
		Type: TypeAnalyzer, License: "MIT", Entrypoint: "run.sh", Permissions: []string{"data.read"},
	})
	registry := NewRegistry(root)
	if err := registry.Discover(); err != nil {
		t.Fatal(err)
	}
	response := registry.Run(context.Background(), "example-analyzer", "operator", json.RawMessage(`{"scope":"test"}`))
	if !response.OK || response.Result == nil || response.Result.Summary != "ok" {
		t.Fatalf("unexpected plugin response: %#v", response)
	}
}

func TestRegistryBlocksInsecureModuleDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission check")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "insecure")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, dir, Manifest{
		ID: "insecure", Name: "Insecure", Version: "1.0.0", APIVersion: APIVersion,
		Type: TypeAnalyzer, License: "MIT", Entrypoint: "run", Permissions: []string{"data.read"},
	})
	registry := NewRegistry(root)
	if err := registry.Discover(); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Get("insecure"); ok {
		t.Fatal("insecure module directory must not be loaded")
	}
	if len(registry.Issues()) != 1 {
		t.Fatalf("expected one discovery issue, got %#v", registry.Issues())
	}
}

func TestRegistryRejectsOversizedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell helper is POSIX-specific")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "large-output")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\nprintf '%s' 'this output is too large'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, dir, Manifest{
		ID: "large-output", Name: "Large output", Version: "1.0.0", APIVersion: APIVersion,
		Type: TypeAnalyzer, License: "MIT", Entrypoint: "run.sh", MaxOutputBytes: 8,
	})
	registry := NewRegistry(root)
	if err := registry.Discover(); err != nil {
		t.Fatal(err)
	}
	response := registry.Run(context.Background(), "large-output", "operator", json.RawMessage(`{}`))
	if response.OK || !strings.Contains(response.Error, "output exceeded") {
		t.Fatalf("expected output limit failure, got %#v", response)
	}
}
