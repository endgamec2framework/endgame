#![allow(dead_code)]
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

struct FwdEntry {
    rhost: String,
    rport: u16,
    proto: String,
    stop_tx: std::sync::mpsc::Sender<()>,
}

static FORWARDS: OnceLock<Arc<Mutex<HashMap<String, FwdEntry>>>> = OnceLock::new();

fn get_fwds() -> Arc<Mutex<HashMap<String, FwdEntry>>> {
    FORWARDS.get_or_init(|| Arc::new(Mutex::new(HashMap::new()))).clone()
}

pub fn portfwd_add(proto: &str, lport: u16, rhost: &str, rport: u16) -> String {
    let key = format!("{}:{}", proto, lport);
    {
        let fwds = get_fwds();
        let lock = fwds.lock().unwrap();
        if lock.contains_key(&key) {
            return format!("port forward {}:{} already exists", proto, lport);
        }
    }

    let rhost = rhost.to_string();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    if proto == "tcp" {
        let ln = match TcpListener::bind(format!("0.0.0.0:{}", lport)) {
            Ok(l) => l,
            Err(e) => return format!("tcp bind :{} failed: {}", lport, e),
        };
        get_fwds().lock().unwrap().insert(key, FwdEntry {
            rhost: rhost.clone(), rport, proto: proto.to_string(), stop_tx,
        });
        let rhost2 = rhost.clone();
        thread::spawn(move || {
            ln.set_nonblocking(true).ok();
            loop {
                if stop_rx.try_recv().is_ok() { break; }
                match ln.accept() {
                    Ok((client, _)) => {
                        let rh = rhost2.clone();
                        thread::spawn(move || {
                            if let Ok(server) = TcpStream::connect(format!("{}:{}", rh, rport)) {
                                forward_tcp(client, server);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
        });
        format!("tcp forwarding :{} → {}:{}", lport, rhost, rport)
    } else if proto == "udp" {
        let sock = match UdpSocket::bind(format!("0.0.0.0:{}", lport)) {
            Ok(s) => s,
            Err(e) => return format!("udp bind :{} failed: {}", lport, e),
        };
        get_fwds().lock().unwrap().insert(key, FwdEntry {
            rhost: rhost.clone(), rport, proto: proto.to_string(), stop_tx,
        });
        let rhost_udp = rhost.clone();
        thread::spawn(move || {
            sock.set_nonblocking(true).ok();
            let mut buf = vec![0u8; 65535];
            loop {
                if stop_rx.try_recv().is_ok() { break; }
                match sock.recv_from(&mut buf) {
                    Ok((n, _src)) => {
                        if let Ok(dst) = UdpSocket::bind("0.0.0.0:0") {
                            dst.send_to(&buf[..n], format!("{}:{}", rhost_udp, rport)).ok();
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        format!("udp forwarding :{} → {}:{}", lport, rhost, rport)
    } else {
        format!("unknown proto: {}", proto)
    }
}

pub fn portfwd_del(proto: &str, lport: u16) -> String {
    let key = format!("{}:{}", proto, lport);
    let fwds = get_fwds();
    let mut lock = fwds.lock().unwrap();
    if let Some(e) = lock.remove(&key) {
        let _ = e.stop_tx.send(());
        format!("{} port forward :{} removed", proto, lport)
    } else {
        format!("no {} forward on port {}", proto, lport)
    }
}

pub fn portfwd_list() -> String {
    let fwds = get_fwds();
    let lock = fwds.lock().unwrap();
    if lock.is_empty() {
        return "(no active port forwards)".to_string();
    }
    let mut lines: Vec<String> = lock.iter().map(|(k, e)| {
        let port = k.split(':').nth(1).unwrap_or("?");
        format!("{} :{} → {}:{}", e.proto, port, e.rhost, e.rport)
    }).collect();
    lines.sort();
    lines.join("\n")
}

fn forward_tcp(mut a: TcpStream, mut b: TcpStream) {
    let mut a2 = match a.try_clone() { Ok(c) => c, Err(_) => return };
    let mut b2 = match b.try_clone() { Ok(c) => c, Err(_) => return };
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match b2.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => { if a2.write_all(&buf[..n]).is_err() { break; } }
            }
        }
    });
    let mut buf = [0u8; 8192];
    loop {
        match a.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => { if b.write_all(&buf[..n]).is_err() { break; } }
        }
    }
}
