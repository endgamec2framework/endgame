package server

import (
	"encoding/json"
	"time"

	"redteam/plugins"
)

type PluginRun struct {
	RunID      string          `json:"run_id"`
	ModuleID   string          `json:"module_id"`
	Operator   string          `json:"operator"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	DurationMS int64           `json:"duration_ms"`
}

func (d *DB) RecordPluginRun(response plugins.RunResponse, operator string) error {
	status := "error"
	if response.OK {
		status = "completed"
	}
	var result []byte
	if response.Result != nil {
		var err error
		result, err = json.Marshal(response.Result)
		if err != nil {
			return err
		}
	}
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO plugin_runs
		(run_id, module_id, operator, status, error, result_json, started_at, finished_at, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		response.RunID, response.ModuleID, operator, status, response.Error,
		string(result), response.StartedAt, response.FinishedAt, response.DurationMS)
	return err
}

func (d *DB) GetPluginRun(runID string) (*PluginRun, error) {
	var p PluginRun
	var result string
	err := d.db.QueryRow(`
		SELECT run_id, module_id, operator, status, error, result_json,
		       started_at, finished_at, duration_ms
		FROM plugin_runs WHERE run_id = ?`, runID).Scan(
		&p.RunID, &p.ModuleID, &p.Operator, &p.Status, &p.Error, &result,
		&p.StartedAt, &p.FinishedAt, &p.DurationMS)
	if err != nil {
		return nil, err
	}
	if result != "" {
		p.Result = json.RawMessage(result)
	}
	return &p, nil
}

func (d *DB) RecentPluginRuns(moduleID string, limit int) ([]*PluginRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	query := `SELECT run_id, module_id, operator, status, error, result_json,
		started_at, finished_at, duration_ms FROM plugin_runs`
	args := []any{}
	if moduleID != "" {
		query += ` WHERE module_id = ?`
		args = append(args, moduleID)
	}
	query += ` ORDER BY started_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PluginRun
	for rows.Next() {
		var p PluginRun
		var result string
		if err := rows.Scan(&p.RunID, &p.ModuleID, &p.Operator, &p.Status, &p.Error, &result,
			&p.StartedAt, &p.FinishedAt, &p.DurationMS); err != nil {
			return nil, err
		}
		if result != "" {
			p.Result = json.RawMessage(result)
		}
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []*PluginRun{}
	}
	return out, nil
}
