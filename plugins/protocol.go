package plugins

import (
	"encoding/json"
	"time"
)

type RunRequest struct {
	ProtocolVersion int             `json:"protocol_version"`
	RunID           string          `json:"run_id"`
	ModuleID        string          `json:"module_id"`
	Operator        string          `json:"operator,omitempty"`
	Input           json.RawMessage `json:"input,omitempty"`
	HostContext     json.RawMessage `json:"host_context,omitempty"`
}

type RunResponse struct {
	ProtocolVersion int       `json:"protocol_version"`
	RunID           string    `json:"run_id"`
	ModuleID        string    `json:"module_id"`
	OK              bool      `json:"ok"`
	Result          *Result   `json:"result,omitempty"`
	Error           string    `json:"error,omitempty"`
	Stderr          string    `json:"stderr,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	DurationMS      int64     `json:"duration_ms"`
}

// Result is the common interchange format exposed to the UI and future graph,
// report, and AI integrations.
type Result struct {
	SchemaVersion int               `json:"schema_version"`
	ModuleID      string            `json:"module_id"`
	Summary       string            `json:"summary,omitempty"`
	Findings      []Finding         `json:"findings,omitempty"`
	Entities      []Entity          `json:"entities,omitempty"`
	Relationships []Relationship    `json:"relationships,omitempty"`
	Artifacts     []Artifact        `json:"artifacts,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    string            `json:"severity"`
	Description string            `json:"description,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	EntityIDs   []string          `json:"entity_ids,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Entity struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Name     string            `json:"name,omitempty"`
	Provider string            `json:"provider,omitempty"`
	Props    map[string]string `json:"props,omitempty"`
}

type Relationship struct {
	ID     string            `json:"id,omitempty"`
	Source string            `json:"source"`
	Target string            `json:"target"`
	Type   string            `json:"type"`
	Props  map[string]string `json:"props,omitempty"`
}

type Artifact struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type,omitempty"`
	Path      string `json:"path,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}
