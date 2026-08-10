package plugins

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Registry struct {
	root    string
	mu      sync.RWMutex
	modules map[string]Module
	issues  []DiscoveryIssue
}

func NewRegistry(root string) *Registry {
	return &Registry{root: root, modules: make(map[string]Module)}
}

func (r *Registry) Root() string { return r.root }

type moduleState struct {
	Disabled map[string]bool `json:"disabled"`
}

func (r *Registry) stateFile() string { return filepath.Join(r.root, ".state.json") }

func (r *Registry) loadState() moduleState {
	s := moduleState{Disabled: make(map[string]bool)}
	data, err := os.ReadFile(r.stateFile())
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s)
	if s.Disabled == nil {
		s.Disabled = make(map[string]bool)
	}
	return s
}

func (r *Registry) saveState(s moduleState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.stateFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.stateFile())
}

// Enable marks a module as loaded and re-discovers all modules.
func (r *Registry) Enable(id string) error {
	s := r.loadState()
	delete(s.Disabled, id)
	if err := r.saveState(s); err != nil {
		return err
	}
	return r.Discover()
}

// Disable marks a module as unloaded and re-discovers all modules.
func (r *Registry) Disable(id string) error {
	s := r.loadState()
	s.Disabled[id] = true
	if err := r.saveState(s); err != nil {
		return err
	}
	return r.Discover()
}

func (r *Registry) Discover() error {
	entries, err := os.ReadDir(r.root)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(r.root, 0700); err != nil {
			return err
		}
		entries = nil
	} else if err != nil {
		return err
	}

	state := r.loadState()
	modules := make(map[string]Module)
	var issues []DiscoveryIssue
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(r.root, entry.Name())
		if runtime.GOOS != "windows" {
			info, statErr := os.Stat(dir)
			if statErr != nil {
				issues = append(issues, DiscoveryIssue{Path: dir, Error: statErr.Error()})
				continue
			}
			if info.Mode().Perm()&0077 != 0 {
				issues = append(issues, DiscoveryIssue{Path: dir, Error: "module directory must not be accessible by group or other users"})
				continue
			}
		}
		manifestPath := filepath.Join(dir, ManifestFilename)
		m, err := LoadManifest(manifestPath)
		if err != nil {
			issues = append(issues, DiscoveryIssue{Path: manifestPath, Error: err.Error()})
			continue
		}
		module := Module{Manifest: m, Dir: dir, Status: "ready"}
		if unknown := m.UnknownPermissions(); len(unknown) > 0 {
			module.Status = "blocked"
			module.Error = "unsupported permissions: " + strings.Join(unknown, ", ")
		} else if m.Type == TypeUI {
			module.Status = "ui-only"
		} else if _, err := resolveEntrypoint(dir, m.EntryPoint()); err != nil {
			module.Status = "blocked"
			module.Error = "entrypoint: " + err.Error()
		} else {
			module.Entrypoint, _ = resolveEntrypoint(dir, m.EntryPoint())
			if runtime.GOOS != "windows" {
				if info, err := os.Stat(module.Entrypoint); err != nil {
					module.Status = "blocked"
					module.Error = "entrypoint: " + err.Error()
				} else if info.Mode().Perm()&0111 == 0 {
					module.Status = "blocked"
					module.Error = "entrypoint is not executable"
				}
			}
		}
		if state.Disabled[m.ID] && module.Status != "blocked" {
			module.Status = "disabled"
			module.Entrypoint = ""
		}
		if _, exists := modules[m.ID]; exists {
			issues = append(issues, DiscoveryIssue{Path: manifestPath, Error: "duplicate module id"})
			continue
		}
		modules[m.ID] = module
	}

	r.mu.Lock()
	r.modules = modules
	r.issues = issues
	r.mu.Unlock()
	return nil
}

func (r *Registry) List() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		copy := m
		copy.Manifest.Permissions = append([]string(nil), m.Manifest.Permissions...)
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	return out
}

func (r *Registry) Issues() []DiscoveryIssue {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]DiscoveryIssue(nil), r.issues...)
}

func (r *Registry) Get(id string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[id]
	return m, ok
}

func newRunID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return b.buf.String() }

func (r *Registry) Run(parent context.Context, moduleID, operator string, input json.RawMessage) RunResponse {
	return r.RunWithContext(parent, moduleID, operator, input, nil)
}

func (r *Registry) RunWithContext(parent context.Context, moduleID, operator string, input, hostContext json.RawMessage) RunResponse {
	started := time.Now().UTC()
	runID, err := newRunID()
	if err != nil {
		return failedResponse("", moduleID, started, err)
	}
	response := RunResponse{ProtocolVersion: ProtocolVersion, RunID: runID, ModuleID: moduleID, StartedAt: started}
	module, ok := r.Get(moduleID)
	if !ok {
		return finishFailure(response, errors.New("module not found"))
	}
	if module.Status != "ready" {
		return finishFailure(response, fmt.Errorf("module is %s: %s", module.Status, module.Error))
	}
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	if len(input) > module.Manifest.InputLimit() {
		return finishFailure(response, fmt.Errorf("input exceeds module limit of %d bytes", module.Manifest.InputLimit()))
	}
	if !json.Valid(input) {
		return finishFailure(response, errors.New("input must be valid JSON"))
	}
	if len(hostContext) > module.Manifest.HostContextLimit() {
		return finishFailure(response, fmt.Errorf("host context exceeds module limit of %d bytes", module.Manifest.HostContextLimit()))
	}
	if len(hostContext) > 0 && !json.Valid(hostContext) {
		return finishFailure(response, errors.New("host context must be valid JSON"))
	}

	request := RunRequest{
		ProtocolVersion: ProtocolVersion,
		RunID:           runID,
		ModuleID:        moduleID,
		Operator:        operator,
		Input:           input,
		HostContext:     hostContext,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return finishFailure(response, err)
	}

	ctx, cancel := context.WithTimeout(parent, time.Duration(module.Manifest.RuntimeSeconds())*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, module.Entrypoint, "--endgame-plugin-stdio")
	cmd.Dir = module.Dir
	// Do not inherit the C2's environment. In particular, no cloud tokens,
	// SSH agent settings, proxy secrets, or operator credentials are exposed.
	cmd.Env = []string{
		"ENDGAME_PLUGIN=1",
		fmt.Sprintf("ENDGAME_PLUGIN_API_VERSION=%d", APIVersion),
		"LANG=C",
	}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, `SystemRoot=C:\Windows`)
	} else {
		cmd.Env = append(cmd.Env, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	cmd.Stdin = bytes.NewReader(append(payload, '\n'))
	stdout := &limitedBuffer{limit: module.Manifest.OutputLimit()}
	stderr := &limitedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if stdout.truncated {
		err = errors.New("plugin output exceeded the configured limit")
	}
	if err != nil {
		if stderr.String() != "" {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		response.Stderr = stderr.String()
		return finishFailure(response, err)
	}

	decoder := json.NewDecoder(bufio.NewReader(strings.NewReader(stdout.String())))
	var pluginResponse RunResponse
	if err := decoder.Decode(&pluginResponse); err != nil {
		return finishFailure(response, fmt.Errorf("decode plugin response: %w", err))
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return finishFailure(response, errors.New("plugin emitted more than one response"))
		}
		return finishFailure(response, fmt.Errorf("decode trailing plugin output: %w", err))
	}
	if pluginResponse.ProtocolVersion != ProtocolVersion {
		return finishFailure(response, fmt.Errorf("unsupported plugin protocol version %d", pluginResponse.ProtocolVersion))
	}
	if pluginResponse.RunID != runID || pluginResponse.ModuleID != moduleID {
		return finishFailure(response, errors.New("plugin response identity does not match request"))
	}
	if !pluginResponse.OK {
		message := strings.TrimSpace(pluginResponse.Error)
		if message == "" {
			message = "plugin returned failure without an error"
		}
		return finishFailure(response, errors.New(message))
	}
	if pluginResponse.Result == nil {
		return finishFailure(response, errors.New("plugin response has no result"))
	}
	if pluginResponse.Result.SchemaVersion != ResultSchemaVersion {
		return finishFailure(response, fmt.Errorf("unsupported result schema version %d", pluginResponse.Result.SchemaVersion))
	}
	if pluginResponse.Result.ModuleID != "" && pluginResponse.Result.ModuleID != moduleID {
		return finishFailure(response, errors.New("plugin result module_id does not match request"))
	}
	if pluginResponse.Result.ModuleID == "" {
		pluginResponse.Result.ModuleID = moduleID
	}
	response.Result = pluginResponse.Result
	response.OK = true
	response.Stderr = stderr.String()
	return finishResponse(response)
}

func failedResponse(runID, moduleID string, started time.Time, err error) RunResponse {
	return finishFailure(RunResponse{ProtocolVersion: ProtocolVersion, RunID: runID, ModuleID: moduleID, StartedAt: started}, err)
}

func finishFailure(r RunResponse, err error) RunResponse {
	r.OK = false
	r.Error = err.Error()
	return finishResponse(r)
}

func finishResponse(r RunResponse) RunResponse {
	r.FinishedAt = time.Now().UTC()
	if !r.StartedAt.IsZero() {
		r.DurationMS = r.FinishedAt.Sub(r.StartedAt).Milliseconds()
	}
	return r
}
