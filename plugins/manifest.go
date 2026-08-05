// Package plugins defines the stable contract between ENDGAME and community
// modules.  Modules are external processes; they never receive agent keys,
// transport handles, or a direct database connection.
package plugins

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	APIVersion          = 1
	ManifestFilename    = "plugin.json"
	ProtocolVersion     = 1
	ResultSchemaVersion = 1
	DefaultMaxInput     = 1 << 20
	DefaultMaxOutput    = 4 << 20
	DefaultMaxHostContext = 8 << 20
	DefaultRunTimeout   = 2 * 60
)

var moduleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$`)

// Type describes the kind of contribution a module provides.
type Type string

const (
	TypeCollector Type = "collector"
	TypeAnalyzer  Type = "analyzer"
	TypeReporter  Type = "reporter"
	TypeConnector Type = "connector"
	TypeUI        Type = "ui"
)

// Manifest is intentionally declarative.  The host decides which declared
// permissions are acceptable for the current installation and operator.
type Manifest struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	APIVersion     int      `json:"api_version"`
	Type           Type     `json:"type"`
	Description    string   `json:"description,omitempty"`
	License        string   `json:"license"`
	Entrypoint     string   `json:"entrypoint,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	MaxRuntimeSecs int      `json:"max_runtime_seconds,omitempty"`
	MaxInputBytes  int      `json:"max_input_bytes,omitempty"`
	MaxOutputBytes int      `json:"max_output_bytes,omitempty"`
	UI             *UI      `json:"ui,omitempty"`
}

type UI struct {
	Tab     string   `json:"tab,omitempty"`
	Actions []Action `json:"actions,omitempty"`
	Menu    string   `json:"menu,omitempty"`
}

type Action struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Confirmation string `json:"confirmation,omitempty"`
}

// Module is a validated manifest together with its private installation dir.
type Module struct {
	Manifest   Manifest `json:"manifest"`
	Dir        string   `json:"dir"`
	Entrypoint string   `json:"entrypoint,omitempty"`
	Status     string   `json:"status"`
	Error      string   `json:"error,omitempty"`
}

// DiscoveryIssue is retained so a bad community module does not prevent the
// C2 from starting.  It is exposed by the API for operator visibility.
type DiscoveryIssue struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// AllowedPermissions is the initial safe module surface.  Write access,
// credential access, and arbitrary agent tasking are deliberately absent.
var AllowedPermissions = map[string]struct{}{
	"data.read":          {},
	"tenant.read":        {},
	"graph.read":         {},
	"report.write":       {},
	"agent.context.read": {},
}

func (m Manifest) Validate() error {
	if !moduleIDPattern.MatchString(m.ID) {
		return fmt.Errorf("invalid id %q", m.ID)
	}
	if strings.TrimSpace(m.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(m.Version) == "" {
		return errors.New("version is required")
	}
	if m.APIVersion != APIVersion {
		return fmt.Errorf("unsupported api_version %d (expected %d)", m.APIVersion, APIVersion)
	}
	switch m.Type {
	case TypeCollector, TypeAnalyzer, TypeReporter, TypeConnector, TypeUI:
	default:
		return fmt.Errorf("unsupported type %q", m.Type)
	}
	if strings.TrimSpace(m.License) == "" {
		return errors.New("license is required")
	}
	if m.Type != TypeUI && strings.TrimSpace(m.EntryPoint()) == "" {
		return errors.New("entrypoint is required for runnable modules")
	}
	if m.MaxRuntimeSecs < 0 || m.MaxRuntimeSecs > 15*60 {
		return errors.New("max_runtime_seconds must be between 0 and 900")
	}
	if m.MaxInputBytes < 0 || m.MaxInputBytes > 8<<20 {
		return errors.New("max_input_bytes must be between 0 and 8388608")
	}
	if m.MaxOutputBytes < 0 || m.MaxOutputBytes > 16<<20 {
		return errors.New("max_output_bytes must be between 0 and 16777216")
	}
	seen := make(map[string]struct{}, len(m.Permissions))
	for _, p := range m.Permissions {
		p = strings.TrimSpace(p)
		if p == "" {
			return errors.New("permissions cannot contain empty values")
		}
		if _, ok := seen[p]; ok {
			return fmt.Errorf("duplicate permission %q", p)
		}
		seen[p] = struct{}{}
	}
	return nil
}

func (m Manifest) EntryPoint() string { return m.Entrypoint }

func (m Manifest) UnknownPermissions() []string {
	var out []string
	for _, p := range m.Permissions {
		if _, ok := AllowedPermissions[p]; !ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func (m Manifest) RuntimeSeconds() int {
	if m.MaxRuntimeSecs > 0 {
		return m.MaxRuntimeSecs
	}
	return DefaultRunTimeout
}

func (m Manifest) InputLimit() int {
	if m.MaxInputBytes > 0 {
		return m.MaxInputBytes
	}
	return DefaultMaxInput
}

func (m Manifest) OutputLimit() int {
	if m.MaxOutputBytes > 0 {
		return m.MaxOutputBytes
	}
	return DefaultMaxOutput
}

func (m Manifest) HostContextLimit() int { return DefaultMaxHostContext }

func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	if len(data) > 64<<10 {
		return Manifest{}, errors.New("manifest exceeds 64 KiB")
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func resolveEntrypoint(moduleDir string, entrypoint string) (string, error) {
	if filepath.IsAbs(entrypoint) {
		return "", errors.New("entrypoint must be relative to the module directory")
	}
	base, err := filepath.EvalSymlinks(moduleDir)
	if err != nil {
		return "", err
	}
	candidate, err := filepath.EvalSymlinks(filepath.Join(base, filepath.Clean(entrypoint)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("entrypoint escapes module directory")
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("entrypoint is a directory")
	}
	return candidate, nil
}
