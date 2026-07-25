#![allow(dead_code)]
/// Minimal SOCKS5 proxy — no-auth only, CONNECT command only.
/// socks_start(port) binds the listener and accepts in a background thread.
/// socks_stop() signals the accept loop to exit.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static SOCKS_STOP: AtomicBool = AtomicBool::new(false);

// ── SOCKS5 client handler ─────────────────────────────────────────────────────

fn handle_socks5(mut client: TcpStream) {
    client.set_nonblocking(false).ok();

    // ── 1. Auth negotiation (RFC 1928 §3) ────────────────────────────────────
    let mut hdr = [0u8; 2];
    if client.read_exact(&mut hdr).is_err() { return; }
    if hdr[0] != 0x05 { return; } // must be SOCKS5
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 && client.read_exact(&mut methods).is_err() { return; }
    // Always reply: version=5, method=0 (no auth)
    if client.write_all(&[0x05, 0x00]).is_err() { return; }

    // ── 2. CONNECT request (RFC 1928 §4) ────────────────────────────────────
    let mut req = [0u8; 4];
    if client.read_exact(&mut req).is_err() { return; }
    if req[0] != 0x05 || req[1] != 0x01 { return; } // only CONNECT(1)

    let target_host: String = match req[3] {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            if client.read_exact(&mut addr).is_err() { return; }
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            // Domain name
            let mut lenbuf = [0u8; 1];
            if client.read_exact(&mut lenbuf).is_err() { return; }
            let mut domain = vec![0u8; lenbuf[0] as usize];
            if client.read_exact(&mut domain).is_err() { return; }
            String::from_utf8_lossy(&domain).into_owned()
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            if client.read_exact(&mut addr).is_err() { return; }
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => return,
    };
    let mut port_buf = [0u8; 2];
    if client.read_exact(&mut port_buf).is_err() { return; }
    let port = u16::from_be_bytes(port_buf);

    let target = format!("{}:{}", target_host, port);

    // ── 3. Open upstream connection ──────────────────────────────────────────
    let server = match TcpStream::connect(&target) {
        Ok(s) => s,
        Err(_) => {
            // Connection refused reply
            let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };

    // Success reply: VER=5 REP=0 RSV=0 ATYP=1 BND.ADDR=0.0.0.0 BND.PORT=0
    if client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).is_err() { return; }

    // ── 4. Bidirectional relay ───────────────────────────────────────────────
    let client_for_thread = match client.try_clone() { Ok(c) => c, Err(_) => return };
    let server_for_main   = match server.try_clone() { Ok(s) => s, Err(_) => return };

    // Thread: client → server
    let t = std::thread::spawn(move || {
        let mut r = client_for_thread;
        let mut w = server;
        let _ = std::io::copy(&mut r, &mut w);
        let _ = w.shutdown(std::net::Shutdown::Both);
    });

    // Current thread: server → client
    let mut r = server_for_main;
    let mut w = client;
    let _ = std::io::copy(&mut r, &mut w);
    let _ = w.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn socks_start(port: u16) -> Result<(), String> {
    SOCKS_STOP.store(false, Ordering::Relaxed);

    let listener = TcpListener::bind(("0.0.0.0", port))
        .map_err(|e| format!("socks bind: {}", e))?;
    listener.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;

    std::thread::spawn(move || {
        loop {
            if SOCKS_STOP.load(Ordering::Relaxed) { break; }
            match listener.accept() {
                Ok((client, _)) => {
                    std::thread::spawn(move || handle_socks5(client));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });

    Ok(())
}

pub fn socks_stop() {
    SOCKS_STOP.store(true, Ordering::Relaxed);
}
