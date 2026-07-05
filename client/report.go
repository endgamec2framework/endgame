package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"redteam/server"
)

// ── MITRE ATT&CK mapping ──────────────────────────────────────────────────

type mitreTech struct {
	ID       string
	Name     string
	TacticID string
	Tactic   string
}

var techByCmd = map[string][]mitreTech{
	// Agent task types
	"shell": {
		{ID: "T1059.003", Name: "Windows Command Shell", TacticID: "TA0002", Tactic: "Execution"},
	},
	"ls": {
		{ID: "T1083", Name: "File and Directory Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"pwd": {
		{ID: "T1083", Name: "File and Directory Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"cd": {
		{ID: "T1083", Name: "File and Directory Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"cat": {
		{ID: "T1005", Name: "Data from Local System", TacticID: "TA0009", Tactic: "Collection"},
	},
	"ps": {
		{ID: "T1057", Name: "Process Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"env": {
		{ID: "T1082", Name: "System Information Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"mkdir": {
		{ID: "T1222.001", Name: "Windows File and Directory Permissions Modification", TacticID: "TA0005", Tactic: "Defense Evasion"},
	},
	"rm": {
		{ID: "T1222.001", Name: "Windows File and Directory Permissions Modification", TacticID: "TA0005", Tactic: "Defense Evasion"},
	},
	"download": {
		{ID: "T1041", Name: "Exfiltration Over C2 Channel", TacticID: "TA0010", Tactic: "Exfiltration"},
	},
	"upload": {
		{ID: "T1105", Name: "Ingress Tool Transfer", TacticID: "TA0011", Tactic: "Command and Control"},
	},
	"screenshot": {
		{ID: "T1113", Name: "Screen Capture", TacticID: "TA0009", Tactic: "Collection"},
	},
	"inject_remote": {
		{ID: "T1055.001", Name: "Dynamic-link Library Injection", TacticID: "TA0005", Tactic: "Defense Evasion"},
	},
	"bof": {
		{ID: "T1106", Name: "Native API", TacticID: "TA0002", Tactic: "Execution"},
	},
	"stage2": {
		{ID: "T1055", Name: "Process Injection", TacticID: "TA0004", Tactic: "Privilege Escalation"},
	},
	"token_whoami": {
		{ID: "T1033", Name: "System Owner/User Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"token_steal": {
		{ID: "T1134.001", Name: "Token Impersonation/Theft", TacticID: "TA0004", Tactic: "Privilege Escalation"},
	},
	"token_make": {
		{ID: "T1134.003", Name: "Make and Impersonate Token", TacticID: "TA0004", Tactic: "Privilege Escalation"},
	},
	"token_drop": {
		{ID: "T1134", Name: "Access Token Manipulation", TacticID: "TA0004", Tactic: "Privilege Escalation"},
	},
	"socks_start": {
		{ID: "T1090", Name: "Proxy", TacticID: "TA0011", Tactic: "Command and Control"},
	},
	"portfwd_add": {
		{ID: "T1090.001", Name: "Internal Proxy", TacticID: "TA0011", Tactic: "Command and Control"},
	},
	"sleep": {
		{ID: "T1029", Name: "Scheduled Transfer", TacticID: "TA0010", Tactic: "Exfiltration"},
	},
	"cleanup": {
		{ID: "T1070", Name: "Indicator Removal", TacticID: "TA0005", Tactic: "Defense Evasion"},
	},
	// Local commands
	"scan": {
		{ID: "T1046", Name: "Network Service Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"enum": {
		{ID: "T1135", Name: "Network Share Discovery", TacticID: "TA0007", Tactic: "Discovery"},
		{ID: "T1018", Name: "Remote System Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"spray": {
		{ID: "T1110.003", Name: "Password Spraying", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"asrep": {
		{ID: "T1558.004", Name: "AS-REP Roasting", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"kerberoast": {
		{ID: "T1558.003", Name: "Kerberoasting", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"secretsdump": {
		{ID: "T1003.003", Name: "NTDS", TacticID: "TA0006", Tactic: "Credential Access"},
		{ID: "T1003.002", Name: "Security Account Manager", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"bloodhound": {
		{ID: "T1482", Name: "Domain Trust Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"lookupsid": {
		{ID: "T1087.002", Name: "Domain Account", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"samrdump": {
		{ID: "T1087.001", Name: "Local Account", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"rpcdump": {
		{ID: "T1135", Name: "Network Share Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"getadusers": {
		{ID: "T1087.002", Name: "Domain Account", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"getadcomputers": {
		{ID: "T1018", Name: "Remote System Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"finddelegation": {
		{ID: "T1482", Name: "Domain Trust Discovery", TacticID: "TA0007", Tactic: "Discovery"},
	},
	"getlaps": {
		{ID: "T1552.006", Name: "Group Policy Preferences", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"getgpp": {
		{ID: "T1552.006", Name: "Group Policy Preferences", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"dumpntlminfo": {
		{ID: "T1590.001", Name: "IP Addresses", TacticID: "TA0043", Tactic: "Reconnaissance"},
	},
	"wmiexec": {
		{ID: "T1047", Name: "Windows Management Instrumentation", TacticID: "TA0002", Tactic: "Execution"},
	},
	"psexec": {
		{ID: "T1569.002", Name: "Service Execution", TacticID: "TA0002", Tactic: "Execution"},
	},
	"smbexec": {
		{ID: "T1021.002", Name: "SMB/Windows Admin Shares", TacticID: "TA0008", Tactic: "Lateral Movement"},
	},
	"dcomexec": {
		{ID: "T1021.003", Name: "Distributed Component Object Model", TacticID: "TA0008", Tactic: "Lateral Movement"},
	},
	"atexec": {
		{ID: "T1053.005", Name: "Scheduled Task", TacticID: "TA0002", Tactic: "Execution"},
	},
	"mssqlclient": {
		{ID: "T1505.001", Name: "SQL Stored Procedures", TacticID: "TA0003", Tactic: "Persistence"},
	},
	"smbclient": {
		{ID: "T1021.002", Name: "SMB/Windows Admin Shares", TacticID: "TA0008", Tactic: "Lateral Movement"},
	},
	"ntlmrelayx": {
		{ID: "T1557.001", Name: "LLMNR/NBT-NS Poisoning and SMB Relay", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"dacledit": {
		{ID: "T1222.001", Name: "Windows File and Directory Permissions Modification", TacticID: "TA0005", Tactic: "Defense Evasion"},
	},
	"rbcd": {
		{ID: "T1098", Name: "Account Manipulation", TacticID: "TA0003", Tactic: "Persistence"},
	},
	"addcomputer": {
		{ID: "T1136.002", Name: "Domain Account", TacticID: "TA0003", Tactic: "Persistence"},
	},
	"changepasswd": {
		{ID: "T1098.001", Name: "Additional Cloud Credentials", TacticID: "TA0003", Tactic: "Persistence"},
	},
	"dpapi": {
		{ID: "T1555", Name: "Credentials from Password Stores", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"gettgt": {
		{ID: "T1558", Name: "Steal or Forge Kerberos Tickets", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"getst": {
		{ID: "T1558.003", Name: "Kerberoasting", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"certipy": {
		{ID: "T1649", Name: "Steal or Forge Authentication Certificates", TacticID: "TA0006", Tactic: "Credential Access"},
	},
	"kerbrute": {
		{ID: "T1110.003", Name: "Password Spraying", TacticID: "TA0006", Tactic: "Credential Access"},
	},
}

var tacticColor = map[string]string{
	"TA0043": "#457b9d",
	"TA0001": "#e63946",
	"TA0002": "#f4a261",
	"TA0003": "#2a9d8f",
	"TA0004": "#8338ec",
	"TA0005": "#3a86ff",
	"TA0006": "#e76f51",
	"TA0007": "#06d6a0",
	"TA0008": "#fb8500",
	"TA0009": "#8ecae6",
	"TA0011": "#264653",
	"TA0010": "#e9c46a",
	"TA0040": "#d62828",
}

var tacticOrder = []struct {
	ID   string
	Name string
}{
	{"TA0043", "Reconnaissance"},
	{"TA0001", "Initial Access"},
	{"TA0002", "Execution"},
	{"TA0003", "Persistence"},
	{"TA0004", "Privilege Escalation"},
	{"TA0005", "Defense Evasion"},
	{"TA0006", "Credential Access"},
	{"TA0007", "Discovery"},
	{"TA0008", "Lateral Movement"},
	{"TA0009", "Collection"},
	{"TA0011", "Command and Control"},
	{"TA0010", "Exfiltration"},
	{"TA0040", "Impact"},
}

// ── Local activity log ────────────────────────────────────────────────────

type LocalEvent struct {
	Ts       time.Time `json:"ts"`
	Operator string    `json:"operator"`
	CmdType  string    `json:"cmd"`
	FullLine string    `json:"full"`
}

var activityLogPath = "activity.jsonl"

func AppendLocalEvent(operator, cmdType, fullLine string) {
	f, err := os.OpenFile(activityLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	e := LocalEvent{Ts: time.Now(), Operator: operator, CmdType: cmdType, FullLine: fullLine}
	b, _ := json.Marshal(e)
	f.Write(append(b, '\n'))
}

func ReadLocalEvents() []LocalEvent {
	data, err := os.ReadFile(activityLogPath)
	if err != nil {
		return nil
	}
	var events []LocalEvent
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e LocalEvent
		if json.Unmarshal([]byte(line), &e) == nil {
			events = append(events, e)
		}
	}
	return events
}

// ── MITRE helpers ─────────────────────────────────────────────────────────

func getTechsFor(cmdType string) []mitreTech {
	if cmdType == "" {
		return nil
	}
	key := strings.ToLower(strings.Fields(cmdType)[0])
	return techByCmd[key]
}

// ── report view model ─────────────────────────────────────────────────────

type reportTechEntry struct {
	Tech  mitreTech
	Count int
	Color string
}

type reportTacticCol struct {
	TacticID   string
	TacticName string
	Color      string
	Techs      []reportTechEntry
}

type reportEventRow struct {
	Ts        string
	IsLocal   bool
	AgentInfo string
	Operator  string
	CmdType   string
	Args      string
	Status    string
	Techs     []mitreTech
	Output    string
	ErrMsg    string
	HasOutput bool
	RowIdx    int
}

type reportViewModel struct {
	GeneratedAt  string
	TotalEvents  int
	TotalAgents  int
	TechCount    int
	TacticCount  int
	TacticMatrix []reportTacticCol
	Agents       []*server.Agent
	Events       []reportEventRow
	ExecSummary  string
	HasSummary   bool
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func buildViewModel(data server.ReportData, local []LocalEvent, execSummary string) reportViewModel {
	// Collect all MITRE techniques used (deduplicated by ID)
	usedTechs := map[string]int{}   // techID -> count
	techInfo := map[string]mitreTech{}

	var rows []reportEventRow
	rowIdx := 0

	// Server events
	for _, e := range data.Events {
		techs := getTechsFor(e.Type)
		for _, t := range techs {
			usedTechs[t.ID]++
			techInfo[t.ID] = t
		}
		ts := e.QueuedAt.Format("2006-01-02 15:04:05")
		agent := fmt.Sprintf("%s@%s (%s)", e.Username, e.Hostname, e.IP)
		out := sanitize(e.Output)
		errMsg := sanitize(e.Error)
		rows = append(rows, reportEventRow{
			Ts:        ts,
			IsLocal:   false,
			AgentInfo: agent,
			Operator:  e.Operator,
			CmdType:   e.Type,
			Args:      sanitize(e.Args),
			Status:    e.Status,
			Techs:     techs,
			Output:    out,
			ErrMsg:    errMsg,
			HasOutput: out != "" || errMsg != "",
			RowIdx:    rowIdx,
		})
		rowIdx++
	}

	// Local events
	for _, e := range local {
		techs := getTechsFor(e.CmdType)
		for _, t := range techs {
			usedTechs[t.ID]++
			techInfo[t.ID] = t
		}
		rows = append(rows, reportEventRow{
			Ts:        e.Ts.Format("2006-01-02 15:04:05"),
			IsLocal:   true,
			AgentInfo: "local",
			Operator:  e.Operator,
			CmdType:   e.CmdType,
			Args:      sanitize(e.FullLine),
			Status:    "local",
			Techs:     techs,
			Output:    "",
			ErrMsg:    "",
			HasOutput: false,
			RowIdx:    rowIdx,
		})
		rowIdx++
	}

	// Build tactic matrix
	// Group used techs by tactic
	tacticTechs := map[string]map[string]reportTechEntry{}
	for _, tac := range tacticOrder {
		tacticTechs[tac.ID] = map[string]reportTechEntry{}
	}
	for id, count := range usedTechs {
		t := techInfo[id]
		col, ok := tacticTechs[t.TacticID]
		if !ok {
			col = map[string]reportTechEntry{}
			tacticTechs[t.TacticID] = col
		}
		col[id] = reportTechEntry{Tech: t, Count: count, Color: tacticColor[t.TacticID]}
	}

	var matrix []reportTacticCol
	usedTactics := map[string]bool{}
	for _, tac := range tacticOrder {
		entries := tacticTechs[tac.ID]
		if len(entries) == 0 {
			continue
		}
		usedTactics[tac.ID] = true
		col := reportTacticCol{
			TacticID:   tac.ID,
			TacticName: tac.Name,
			Color:      tacticColor[tac.ID],
		}
		for _, e := range entries {
			col.Techs = append(col.Techs, e)
		}
		matrix = append(matrix, col)
	}

	return reportViewModel{
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05 UTC"),
		TotalEvents:  len(data.Events) + len(local),
		TotalAgents:  len(data.Agents),
		TechCount:    len(usedTechs),
		TacticCount:  len(usedTactics),
		TacticMatrix: matrix,
		Agents:       data.Agents,
		Events:       rows,
		ExecSummary:  execSummary,
		HasSummary:   execSummary != "",
	}
}

// ── cmdReport ─────────────────────────────────────────────────────────────

func (cl *CLI) cmdReport(args []string) {
	useAI := false
	ollamaURL := resolveOllamaURL("")
	aiModel := ""
	for i, a := range args {
		if a == "--ai" {
			useAI = true
		}
		if a == "-m" && i+1 < len(args) {
			aiModel = args[i+1]
		}
		if a == "-url" && i+1 < len(args) {
			ollamaURL = args[i+1]
		}
	}

	fmt.Println("[*] Generando reporte...")

	// Fetch server-side data
	var reportData server.ReportData
	raw, err := cl.c.GetReport()
	if err == nil && raw != nil {
		json.Unmarshal(*raw, &reportData)
	}

	// Read local activity log
	localEvents := ReadLocalEvents()

	// Generate report filename
	fname := fmt.Sprintf("report_%s.html", time.Now().Format("2006-01-02_150405"))

	// Generate AI executive summary if requested
	execSummary := ""
	if useAI {
		execSummary = cl.generateAISummary(reportData, localEvents, ollamaURL, aiModel)
	}

	// Generate HTML
	html := generateReportHTML(reportData, localEvents, execSummary)
	if err := os.WriteFile(fname, []byte(html), 0644); err != nil {
		fmt.Println("[!] Error escribiendo reporte:", err)
		return
	}
	fmt.Printf("[+] Reporte generado: %s\n", fname)
	fmt.Printf("[*] Abre con: firefox %s\n", fname)
}

// ── generateAISummary ─────────────────────────────────────────────────────

func (cl *CLI) generateAISummary(data server.ReportData, local []LocalEvent, ollamaURL, model string) string {
	if model == "" {
		models := ollamaListModels(ollamaURL)
		if len(models) == 0 {
			return ""
		}
		model = models[0]
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "You are writing the Executive Summary of a professional red team pentest report.\n")
	fmt.Fprintf(&sb, "Write 3-5 paragraphs in English, professional tone, suitable for a CISO audience.\n")
	fmt.Fprintf(&sb, "Include: attack path overview, key vulnerabilities exploited, impact achieved, critical recommendations.\n\n")
	fmt.Fprintf(&sb, "DATA:\nAgents compromised: %d\nTotal commands: %d\nLocal commands: %d\n\n",
		len(data.Agents), len(data.Events), len(local))

	fmt.Fprintf(&sb, "Key operations:\n")
	for _, e := range data.Events {
		if e.Output != "" {
			fmt.Fprintf(&sb, "- [%s@%s] %s: %s\n", e.Username, e.Hostname, e.Type, e.Args)
		}
	}
	for _, e := range local {
		fmt.Fprintf(&sb, "- [local] %s\n", e.FullLine)
	}

	fmt.Println("[*] Generando executive summary con IA...")
	response, err := ollamaChat(ollamaURL, model, []ollamaMsg{
		{Role: "user", Content: sb.String()},
	})
	if err != nil {
		fmt.Println("[!] AI summary error:", err)
		return ""
	}
	return response
}

// ── generateReportHTML ────────────────────────────────────────────────────

func generateReportHTML(data server.ReportData, local []LocalEvent, execSummary string) string {
	vm := buildViewModel(data, local, execSummary)

	funcMap := template.FuncMap{
		"tacticColor": func(id string) string {
			if c, ok := tacticColor[id]; ok {
				return c
			}
			return "#555"
		},
		"hasOutput": func(s string) bool { return s != "" },
		"agentActive": func(a *server.Agent) string {
			if !a.Active {
				return "dead"
			}
			return "active"
		},
		"agentLastSeen": func(a *server.Agent) string {
			return a.LastSeen.Format("2006-01-02 15:04")
		},
		"statusClass": func(status string) string {
			switch status {
			case "done":
				return "status-done"
			case "error":
				return "status-error"
			case "pending", "fetched":
				return "status-pending"
			default:
				return "status-local"
			}
		},
		"nl2br": func(s string) string {
			return strings.ReplaceAll(s, "\n", "<br>")
		},
		"shortID": func(s string) string {
			if len(s) > 8 {
				return s[:8]
			}
			return s
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportHTMLTemplate)
	if err != nil {
		return "<html><body>Template error: " + err.Error() + "</body></html>"
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vm); err != nil {
		return "<html><body>Render error: " + err.Error() + "</body></html>"
	}
	return buf.String()
}

// ── HTML template ─────────────────────────────────────────────────────────

const reportHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Red Team Report</title>
<style>
:root {
  --bg: #0d1117;
  --bg2: #161b22;
  --bg3: #21262d;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --accent: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --purple: #bc8cff;
  --TA0043: #457b9d;
  --TA0001: #e63946;
  --TA0002: #f4a261;
  --TA0003: #2a9d8f;
  --TA0004: #8338ec;
  --TA0005: #3a86ff;
  --TA0006: #e76f51;
  --TA0007: #06d6a0;
  --TA0008: #fb8500;
  --TA0009: #8ecae6;
  --TA0011: #264653;
  --TA0010: #e9c46a;
  --TA0040: #d62828;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
  font-size: 14px;
  line-height: 1.6;
}
.container { max-width: 1400px; margin: 0 auto; padding: 0 24px; }
header {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
  border-bottom: 1px solid var(--border);
  padding: 32px 0;
  margin-bottom: 32px;
}
.header-inner {
  display: flex; align-items: center; gap: 24px;
}
.logo {
  font-family: monospace;
  font-size: 13px;
  color: var(--red);
  white-space: pre;
  line-height: 1.2;
}
.header-text h1 {
  font-size: 28px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: -0.5px;
}
.header-text p {
  color: var(--text-muted);
  font-size: 13px;
  margin-top: 4px;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.badge-red { background: rgba(248,81,73,0.15); color: var(--red); border: 1px solid rgba(248,81,73,0.3); }
.badge-green { background: rgba(63,185,80,0.15); color: var(--green); border: 1px solid rgba(63,185,80,0.3); }
.badge-yellow { background: rgba(210,153,34,0.15); color: var(--yellow); border: 1px solid rgba(210,153,34,0.3); }
.badge-blue { background: rgba(88,166,255,0.15); color: var(--accent); border: 1px solid rgba(88,166,255,0.3); }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 32px;
}
.stat-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}
.stat-card .value {
  font-size: 36px;
  font-weight: 700;
  color: var(--accent);
  line-height: 1;
  margin-bottom: 4px;
}
.stat-card .label {
  font-size: 12px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
section {
  margin-bottom: 40px;
}
section h2 {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 8px;
}
.matrix-container {
  display: flex;
  gap: 8px;
  overflow-x: auto;
  padding-bottom: 8px;
}
.tactic-col {
  min-width: 140px;
  flex: 1;
}
.tactic-header {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 6px 8px;
  border-radius: 6px 6px 0 0;
  text-align: center;
  margin-bottom: 4px;
}
.tech-card {
  padding: 6px 8px;
  border-radius: 4px;
  margin-bottom: 3px;
  font-size: 11px;
  cursor: default;
  border: 1px solid transparent;
  transition: opacity 0.15s;
}
.tech-card.used {
  opacity: 1;
}
.tech-card.unused {
  background: #1c2128 !important;
  color: #444c56 !important;
  border-color: #2d333b;
}
.tech-id {
  font-weight: 700;
  font-size: 10px;
  display: block;
}
.tech-name {
  display: block;
  font-size: 10px;
  line-height: 1.3;
  margin-top: 1px;
}
.tech-count {
  float: right;
  background: rgba(0,0,0,0.3);
  border-radius: 8px;
  padding: 0 4px;
  font-size: 9px;
  font-weight: 700;
}
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
th {
  background: var(--bg3);
  padding: 10px 12px;
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}
td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  font-size: 13px;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.02); }
.mono { font-family: monospace; font-size: 12px; }
.status-done { color: var(--green); }
.status-error { color: var(--red); }
.status-pending { color: var(--yellow); }
.status-local { color: var(--purple); }
.tech-badge {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: 600;
  margin: 1px 2px;
  color: #fff;
  white-space: nowrap;
}
.output-toggle {
  background: none;
  border: 1px solid var(--border);
  color: var(--text-muted);
  padding: 2px 8px;
  border-radius: 3px;
  cursor: pointer;
  font-size: 11px;
  margin-top: 4px;
}
.output-toggle:hover { border-color: var(--accent); color: var(--accent); }
.output-box {
  display: none;
  background: #010409;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 8px;
  margin-top: 6px;
  font-family: monospace;
  font-size: 11px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 300px;
  overflow-y: auto;
  color: #7ee787;
}
.output-box.error-box { color: var(--red); }
.filter-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  align-items: center;
}
.filter-bar input {
  flex: 1;
  background: var(--bg2);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  outline: none;
}
.filter-bar input:focus { border-color: var(--accent); }
.filter-bar input::placeholder { color: var(--text-muted); }
.exec-summary {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  line-height: 1.8;
  white-space: pre-wrap;
}
.ai-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(188,140,255,0.1);
  border: 1px solid rgba(188,140,255,0.3);
  color: var(--purple);
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  margin-bottom: 12px;
}
.timeline-row td { padding: 10px 12px; }
.local-row td:first-child { border-left: 3px solid var(--purple); }
.agent-row td:first-child { border-left: 3px solid var(--accent); }
.empty-state {
  text-align: center;
  padding: 60px;
  color: var(--text-muted);
}
.empty-state .icon { font-size: 48px; margin-bottom: 12px; }
.section-icon { font-size: 16px; }
footer {
  border-top: 1px solid var(--border);
  padding: 24px 0;
  margin-top: 40px;
  text-align: center;
  color: var(--text-muted);
  font-size: 12px;
}
@media (max-width: 768px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<body>
<header>
  <div class="container">
    <div class="header-inner">
      <pre class="logo">  _ __ ___  __| |
 | '__/ _ \/ _' |
 | | |  __/ (_| |
 |_|  \___|\__,_|
  redteam</pre>
      <div class="header-text">
        <h1>Red Team Engagement Report</h1>
        <p>Generated: {{.GeneratedAt}} &nbsp;&bull;&nbsp; <span class="badge badge-red">CONFIDENTIAL</span></p>
      </div>
    </div>
  </div>
</header>

<div class="container">

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="value">{{.TotalEvents}}</div>
      <div class="label">Total Events</div>
    </div>
    <div class="stat-card">
      <div class="value">{{.TotalAgents}}</div>
      <div class="label">Agents Compromised</div>
    </div>
    <div class="stat-card">
      <div class="value">{{.TechCount}}</div>
      <div class="label">Techniques Used</div>
    </div>
    <div class="stat-card">
      <div class="value">{{.TacticCount}}</div>
      <div class="label">Tactics Covered</div>
    </div>
  </div>

  {{if .HasSummary}}
  <!-- Executive Summary -->
  <section>
    <h2><span class="section-icon">&#128196;</span> Executive Summary</h2>
    <div class="ai-label">&#129302; AI Generated</div>
    <div class="exec-summary">{{.ExecSummary}}</div>
  </section>
  {{end}}

  <!-- MITRE ATT&CK Matrix -->
  <section>
    <h2><span class="section-icon">&#127919;</span> MITRE ATT&CK Coverage</h2>
    {{if .TacticMatrix}}
    <div class="matrix-container">
      {{range .TacticMatrix}}
      <div class="tactic-col">
        <div class="tactic-header" style="background:{{.Color}};color:#fff;">
          {{.TacticID}}<br>{{.TacticName}}
        </div>
        {{range .Techs}}
        <div class="tech-card used" style="background:{{.Color}}22;border-color:{{.Color}}55;color:{{.Color}};">
          <span class="tech-count">{{.Count}}x</span>
          <span class="tech-id">{{.Tech.ID}}</span>
          <span class="tech-name">{{.Tech.Name}}</span>
        </div>
        {{end}}
      </div>
      {{end}}
    </div>
    {{else}}
    <div class="empty-state">
      <div class="icon">&#127919;</div>
      <p>No MITRE techniques mapped yet.</p>
    </div>
    {{end}}
  </section>

  <!-- Agent Inventory -->
  <section>
    <h2><span class="section-icon">&#128187;</span> Agent Inventory</h2>
    {{if .Agents}}
    <table id="agents-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Hostname</th>
          <th>User</th>
          <th>OS</th>
          <th>IP</th>
          <th>Transport</th>
          <th>First Seen</th>
          <th>Last Seen</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {{range .Agents}}
        <tr>
          <td class="mono">{{shortID .ID}}</td>
          <td>{{.Hostname}}</td>
          <td>{{.Username}}</td>
          <td>{{.OS}}</td>
          <td class="mono">{{.IP}}</td>
          <td>{{.Transport}}</td>
          <td class="mono">{{.FirstSeen.Format "2006-01-02 15:04"}}</td>
          <td class="mono">{{.LastSeen.Format "2006-01-02 15:04"}}</td>
          <td>
            {{if .Active}}
            <span class="badge badge-green">active</span>
            {{else}}
            <span class="badge badge-red">dead</span>
            {{end}}
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty-state">
      <div class="icon">&#128187;</div>
      <p>No agents recorded.</p>
    </div>
    {{end}}
  </section>

  <!-- Event Timeline -->
  <section>
    <h2><span class="section-icon">&#128336;</span> Event Timeline</h2>
    {{if .Events}}
    <div class="filter-bar">
      <input type="text" id="timeline-filter" placeholder="Filter timeline (command, agent, technique...)" oninput="filterTimeline(this.value)">
    </div>
    <table id="timeline-table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Agent / Source</th>
          <th>Operator</th>
          <th>Command</th>
          <th>MITRE Techniques</th>
          <th>Status</th>
          <th>Output</th>
        </tr>
      </thead>
      <tbody id="timeline-body">
        {{range .Events}}
        <tr class="timeline-row {{if .IsLocal}}local-row{{else}}agent-row{{end}}" data-search="{{.CmdType}} {{.AgentInfo}} {{.Args}} {{range .Techs}}{{.ID}} {{.Name}} {{end}}">
          <td class="mono" style="white-space:nowrap;">{{.Ts}}</td>
          <td>
            {{if .IsLocal}}
            <span class="badge badge-yellow">local</span>
            {{else}}
            <span class="mono" style="font-size:11px;">{{.AgentInfo}}</span>
            {{end}}
          </td>
          <td><span style="color:var(--text-muted);font-size:12px;">{{.Operator}}</span></td>
          <td>
            <strong class="mono">{{.CmdType}}</strong>
            {{if .Args}}<br><span style="color:var(--text-muted);font-size:11px;">{{.Args}}</span>{{end}}
          </td>
          <td>
            {{range .Techs}}
            <span class="tech-badge" style="background:{{tacticColor .TacticID}};" title="{{.Tactic}}">{{.ID}}</span>
            {{end}}
          </td>
          <td><span class="{{statusClass .Status}}">{{.Status}}</span></td>
          <td>
            {{if .HasOutput}}
            <button class="output-toggle" onclick="toggleOutput({{.RowIdx}})">show output</button>
            <div id="out-{{.RowIdx}}" class="output-box {{if .ErrMsg}}error-box{{end}}">{{if .Output}}{{.Output}}{{end}}{{if .ErrMsg}}
[ERR] {{.ErrMsg}}{{end}}</div>
            {{else}}
            <span style="color:var(--text-muted);">—</span>
            {{end}}
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty-state">
      <div class="icon">&#128336;</div>
      <p>No events recorded yet.</p>
    </div>
    {{end}}
  </section>

  <!-- Technique Details -->
  {{if .TacticMatrix}}
  <section>
    <h2><span class="section-icon">&#128202;</span> Technique Details</h2>
    <table>
      <thead>
        <tr>
          <th>Technique ID</th>
          <th>Name</th>
          <th>Tactic</th>
          <th>Count</th>
        </tr>
      </thead>
      <tbody>
        {{range .TacticMatrix}}
        {{range .Techs}}
        <tr>
          <td>
            <a href="https://attack.mitre.org/techniques/{{.Tech.ID}}/" target="_blank" style="color:{{.Color}};text-decoration:none;font-family:monospace;">
              {{.Tech.ID}}
            </a>
          </td>
          <td>{{.Tech.Name}}</td>
          <td>
            <span class="badge" style="background:{{.Color}}22;color:{{.Color}};border:1px solid {{.Color}}55;">
              {{.Tech.TacticID}} — {{.Tech.Tactic}}
            </span>
          </td>
          <td><strong>{{.Count}}</strong></td>
        </tr>
        {{end}}
        {{end}}
      </tbody>
    </table>
  </section>
  {{end}}

</div>

<footer>
  <div class="container">
    Red Team Report &bull; Generated {{.GeneratedAt}} &bull; <span class="badge badge-red">CONFIDENTIAL — DO NOT DISTRIBUTE</span>
  </div>
</footer>

<script>
function toggleOutput(idx) {
  var el = document.getElementById('out-' + idx);
  var btn = el.previousElementSibling;
  if (el.style.display === 'block') {
    el.style.display = 'none';
    btn.textContent = 'show output';
  } else {
    el.style.display = 'block';
    btn.textContent = 'hide output';
  }
}

function filterTimeline(val) {
  val = val.toLowerCase();
  var rows = document.querySelectorAll('#timeline-body tr');
  rows.forEach(function(row) {
    var search = (row.getAttribute('data-search') || '').toLowerCase();
    row.style.display = (!val || search.indexOf(val) >= 0) ? '' : 'none';
  });
}
</script>
</body>
</html>`
