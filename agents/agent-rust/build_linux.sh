#!/bin/bash
# Build the Rust agent for Linux x86_64.
# Run from the agents/agent-rust/ directory.
# Environment variables:
#   AGENT_SERVER_URL  — C2 URL  (default: http://127.0.0.1:8080)
#   AGENT_TRANSPORT   — http|tcp|dns|doh  (default: http)
#   AGENT_SLEEP_SEC   — beacon interval in seconds  (default: 60)
#   AGENT_JITTER_PCT  — jitter percentage  (default: 20)

set -e
TARGET=x86_64-unknown-linux-gnu
rustup target add "$TARGET" 2>/dev/null || true
cargo build --release --target "$TARGET" "$@"
echo "[+] Linux binary: target/${TARGET}/release/agent-rust"
