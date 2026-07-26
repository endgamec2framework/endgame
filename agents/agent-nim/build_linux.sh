#!/bin/bash
set -e
nim compile \
  --os:linux --cpu:amd64 \
  -d:release -d:noSleepMask \
  --opt:size \
  -d:ssl \
  --passL:"-L/usr/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3 -lpthread" \
  -o:agent_linux \
  agent.nim
