package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"redteam/plugins"
)

type pluginSummary struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	APIVersion  int         `json:"api_version"`
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	License     string      `json:"license"`
	Permissions []string    `json:"permissions,omitempty"`
	Status      string      `json:"status"`
	Error       string      `json:"error,omitempty"`
	UI          *plugins.UI `json:"ui,omitempty"`
}

// pluginAgentContext deliberately omits AESKey, task payloads, credentials and
// raw task results. It is the only agent data exposed through the initial host
// API.
type pluginAgentContext struct {
	ID           string             `json:"id"`
	Hostname     string             `json:"hostname"`
	Username     string             `json:"username"`
	OS           string             `json:"os"`
	IP           string             `json:"ip"`
	PID          int                `json:"pid"`
	FirstSeen    time.Time          `json:"first_seen"`
	LastSeen     time.Time          `json:"last_seen"`
	SleepSec     int                `json:"sleep_sec"`
	JitterPct    int                `json:"jitter_pct"`
	Transport    string             `json:"transport"`
	Active       bool               `json:"active"`
	ProcessName  string             `json:"process_name,omitempty"`
	IsAdmin      bool               `json:"is_admin"`
	ParentID     string             `json:"parent_id,omitempty"`
	Language     string             `json:"language,omitempty"`
	Capabilities *AgentCapabilities `json:"capabilities,omitempty"`
}

type pluginGraphContext struct {
	Nodes []*BHNode `json:"nodes"`
	Edges []*BHEdge `json:"edges"`
}

type pluginHostContext struct {
	APIVersion  int                    `json:"api_version"`
	ModuleID    string                 `json:"module_id"`
	Operator    string                 `json:"operator,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Tenant      map[string]string      `json:"tenant,omitempty"`
	Agents      []*pluginAgentContext  `json:"agents,omitempty"`
	Agent       *pluginAgentContext    `json:"agent,omitempty"`
	Graph       *pluginGraphContext    `json:"graph,omitempty"`
}

func sanitizePluginAgent(a *Agent) *pluginAgentContext {
	if a == nil {
		return nil
	}
	return &pluginAgentContext{
		ID: a.ID, Hostname: a.Hostname, Username: a.Username, OS: a.OS,
		IP: a.IP, PID: a.PID, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen,
		SleepSec: a.SleepSec, JitterPct: a.JitterPct, Transport: a.Transport,
		Active: a.Active, ProcessName: a.ProcessName, IsAdmin: a.IsAdmin,
		ParentID: a.ParentID, Language: a.Language,
		Capabilities: a.Capabilities,
	}
}

func pluginHasPermission(m plugins.Module, permission string) bool {
	for _, declared := range m.Manifest.Permissions {
		if declared == permission {
			return true
		}
	}
	return false
}

func pluginInputAgentID(input json.RawMessage) string {
	var request struct {
		AgentID string `json:"agent_id"`
	}
	if json.Unmarshal(input, &request) != nil {
		return ""
	}
	return strings.TrimSpace(request.AgentID)
}

// buildPluginHostContext is intentionally assembled by the server rather than
// by the plugin package. This keeps modules from receiving a DB handle and
// makes each new permission an explicit, reviewable server-side decision.
func (s *Server) buildPluginHostContext(module plugins.Module, operator string, input json.RawMessage) (json.RawMessage, error) {
	needsHostContext := false
	for _, permission := range []string{"tenant.read", "data.read", "agent.context.read", "graph.read"} {
		if pluginHasPermission(module, permission) {
			needsHostContext = true
			break
		}
	}
	if !needsHostContext {
		return nil, nil
	}
	context := pluginHostContext{
		APIVersion: plugins.APIVersion,
		ModuleID: module.Manifest.ID,
		Operator: operator,
		Permissions: append([]string(nil), module.Manifest.Permissions...),
	}
	if pluginHasPermission(module, "tenant.read") {
		context.Tenant = map[string]string{"scope": "local"}
	}
	if pluginHasPermission(module, "data.read") {
		agents, err := s.db.ListAgents()
		if err != nil {
			return nil, err
		}
		context.Agents = make([]*pluginAgentContext, 0, len(agents))
		for _, agent := range agents {
			context.Agents = append(context.Agents, sanitizePluginAgent(agent))
		}
	}
	if pluginHasPermission(module, "agent.context.read") {
		if agentID := pluginInputAgentID(input); agentID != "" {
			agent, err := s.db.GetAgent(agentID)
			if err != nil {
				return nil, err
			}
			context.Agent = sanitizePluginAgent(agent)
		}
	}
	if pluginHasPermission(module, "graph.read") {
		nodes, edges, err := s.db.BHGetGraph()
		if err != nil {
			return nil, err
		}
		context.Graph = &pluginGraphContext{Nodes: nodes, Edges: edges}
	}
	return json.Marshal(context)
}

func summarizePlugin(m plugins.Module) pluginSummary {
	return pluginSummary{
		ID: m.Manifest.ID, Name: m.Manifest.Name, Version: m.Manifest.Version,
		APIVersion: m.Manifest.APIVersion, Type: string(m.Manifest.Type),
		Description: m.Manifest.Description, License: m.Manifest.License,
		Permissions: append([]string(nil), m.Manifest.Permissions...),
		Status:      m.Status, Error: m.Error, UI: m.Manifest.UI,
	}
}

func (s *Server) requirePluginRole(w http.ResponseWriter, r *http.Request) {
	minRole := RoleViewer
	if r.Method != http.MethodGet {
		minRole = RoleOperator
	}
	s.requireRole(minRole, s.apiPlugins)(w, r)
}

// apiPlugins exposes the versioned community-module surface. Installation is
// intentionally filesystem/manual for now; the API only discovers, runs, and
// reports modules.
func (s *Server) apiPlugins(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/plugins")
	if path == "" || path == "/" {
		if r.Method != http.MethodGet {
			jsonErr(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		modules := s.plugins.List()
		out := make([]pluginSummary, 0, len(modules))
		for _, m := range modules {
			out = append(out, summarizePlugin(m))
		}
		jsonOK(w, map[string]any{
			"api_version": plugins.APIVersion,
			"modules":     out,
			"issues":      s.plugins.Issues(),
		})
		return
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if parts[0] == "reload" {
		if len(parts) != 1 {
			jsonErr(w, "invalid plugin reload path", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if err := s.plugins.Discover(); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{
			"status":  "reloaded",
			"modules": len(s.plugins.List()),
			"issues":  s.plugins.Issues(),
		})
		return
	}

	moduleID := parts[0]
	module, ok := s.plugins.Get(moduleID)
	if !ok {
		jsonErr(w, "module not found", http.StatusNotFound)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			jsonErr(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		jsonOK(w, summarizePlugin(module))
		return
	}
	if len(parts) != 2 {
		jsonErr(w, "invalid plugin path", http.StatusNotFound)
		return
	}

	switch parts[1] {
	case "run":
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Input json.RawMessage `json:"input,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(module.Manifest.InputLimit()+64))
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		operator := operatorFromCert(r)
		hostContext, err := s.buildPluginHostContext(module, operator, req.Input)
		if err != nil {
			jsonErr(w, "build plugin host context: "+err.Error(), http.StatusInternalServerError)
			return
		}
		response := s.plugins.RunWithContext(r.Context(), moduleID, operator, req.Input, hostContext)
		if err := s.db.RecordPluginRun(response, operator); err != nil {
			jsonErr(w, "record plugin run: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if response.OK {
			BroadcastGUI("PLUGIN_RESULT", "", moduleID+" completed")
			jsonOK(w, response)
			return
		}
		BroadcastGUI("PLUGIN_ERROR", "", moduleID+": "+response.Error)
		jsonErr(w, response.Error, http.StatusBadGateway)

	case "runs":
		if r.Method != http.MethodGet {
			jsonErr(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		runs, err := s.db.RecentPluginRuns(moduleID, limit)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, runs)

	default:
		jsonErr(w, "unknown plugin action", http.StatusNotFound)
	}
}
