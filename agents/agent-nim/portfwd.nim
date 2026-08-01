## portfwd.nim — TCP/UDP port forwarding relay (Windows).
## Supports up to PORTFWD_MAX simultaneous forwards.
## Args: "[tcp|udp] <lport> <rhost> <rport>"

when defined(windows):
  import winim/lean
  import std/strutils

  const PORTFWD_MAX = 16

  type FwdEntry = object
    active : bool
    isUDP  : bool
    stop   : bool
    lport  : int
    rhost  : array[256, char]
    rport  : int
    lsock  : SOCKET
    thread : HANDLE

  var gFwds: array[PORTFWD_MAX, FwdEntry]
  var gFwdInited = false

  proc fwdInit() =
    if gFwdInited: return
    gFwdInited = true
    for i in 0..<PORTFWD_MAX:
      gFwds[i].lsock = INVALID_SOCKET

  # ── Bidirectional relay helpers ──────────────────────────────────────────

  type RelayPair = object
    src, dst: SOCKET

  proc relayHalf(p: LPVOID): DWORD {.stdcall.} =
    let rp  = cast[ptr RelayPair](p)
    let src = rp.src
    let dst = rp.dst
    dealloc(p)
    var buf: array[16384, byte]
    while true:
      let n = recv(src, cast[ptr char](addr buf[0]), int32(sizeof(buf)), 0)
      if n <= 0: break
      discard send(dst, cast[ptr char](addr buf[0]), n, 0)
    discard shutdown(dst, SD_SEND)
    return 0

  # ── TCP per-client relay ─────────────────────────────────────────────────

  type TcpClientParam = object
    client: SOCKET
    rhost : array[256, char]
    rport : int

  proc tcpRelayProc(p: LPVOID): DWORD {.stdcall.} =
    let pp     = cast[ptr TcpClientParam](p)
    let client = pp.client
    var rhostBuf: array[256, char]
    copyMem(addr rhostBuf[0], addr pp.rhost[0], 256)
    let rport = pp.rport
    dealloc(p)
    defer: discard closesocket(client)
    # Build null-terminated rhost string for getaddrinfo
    var rhostStr = newString(256)
    copyMem(addr rhostStr[0], addr rhostBuf[0], 256)
    let nl = rhostStr.find('\0')
    if nl >= 0: rhostStr.setLen(nl)
    var hints: ADDRINFOA
    zeroMem(addr hints, sizeof(hints))
    hints.ai_family   = AF_INET
    hints.ai_socktype = SOCK_STREAM
    var res: ptr ADDRINFOA = nil
    if getaddrinfo(rhostStr, $rport, addr hints, addr res) != 0: return 1
    defer: freeaddrinfo(res)
    let server = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
    if server == INVALID_SOCKET: return 1
    if connect(server, res.ai_addr, int32(res.ai_addrlen)) != 0:
      discard closesocket(server); return 1
    defer: discard closesocket(server)
    # Spawn client→server half in a thread
    let fwd = cast[ptr RelayPair](alloc0(sizeof(RelayPair)))
    fwd.src = client; fwd.dst = server
    var tid: DWORD = 0
    let th = CreateThread(nil, 0, relayHalf, cast[LPVOID](fwd), 0, addr tid)
    # server→client in this thread
    var buf: array[16384, byte]
    while true:
      let n = recv(server, cast[ptr char](addr buf[0]), int32(sizeof(buf)), 0)
      if n <= 0: break
      discard send(client, cast[ptr char](addr buf[0]), n, 0)
    discard shutdown(client, SD_SEND)
    if th != 0:
      discard WaitForSingleObject(th, DWORD(3000))
      discard CloseHandle(th)
    return 0

  # ── TCP listen server thread ─────────────────────────────────────────────

  type ServerParam = object
    idx: int

  proc tcpServerProc(p: LPVOID): DWORD {.stdcall.} =
    let pp  = cast[ptr ServerParam](p)
    let idx = pp.idx
    dealloc(p)
    var wsaData: WSADATA
    discard WSAStartup(WORD(0x0202), addr wsaData)
    let ln = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
    if ln == INVALID_SOCKET: return 1
    gFwds[idx].lsock = ln
    var reuseOpt: int32 = 1
    discard setsockopt(ln, int32(SOL_SOCKET), int32(SO_REUSEADDR),
      cast[ptr char](addr reuseOpt), int32(sizeof(reuseOpt)))
    var sa: sockaddr_in
    sa.sin_family      = int16(AF_INET)
    sa.sin_port        = htons(uint16(gFwds[idx].lport))
    sa.sin_addr.S_addr = int32(0)
    if `bind`(ln, cast[ptr sockaddr](addr sa), int32(sizeof(sa))) != 0 or
       listen(ln, 16) != 0:
      discard closesocket(ln); gFwds[idx].lsock = INVALID_SOCKET; return 1
    while not gFwds[idx].stop:
      var ca: sockaddr_in; var cLen: int32 = int32(sizeof(ca))
      let client = accept(ln, cast[ptr sockaddr](addr ca), addr cLen)
      if client == INVALID_SOCKET: break
      let cp = cast[ptr TcpClientParam](alloc0(sizeof(TcpClientParam)))
      cp.client = client
      cp.rport  = gFwds[idx].rport
      copyMem(addr cp.rhost[0], addr gFwds[idx].rhost[0], 256)
      var tid: DWORD = 0
      discard CloseHandle(CreateThread(nil, 0, tcpRelayProc, cast[LPVOID](cp), 0, addr tid))
    discard closesocket(ln)
    gFwds[idx].lsock = INVALID_SOCKET
    return 0

  # ── UDP relay thread ─────────────────────────────────────────────────────

  proc udpRelayProc(p: LPVOID): DWORD {.stdcall.} =
    let pp  = cast[ptr ServerParam](p)
    let idx = pp.idx
    dealloc(p)
    let sock = socket(int32(AF_INET), int32(SOCK_DGRAM), int32(IPPROTO_UDP))
    if sock == INVALID_SOCKET: return 1
    gFwds[idx].lsock = sock
    var sa: sockaddr_in
    sa.sin_family      = int16(AF_INET)
    sa.sin_port        = htons(uint16(gFwds[idx].lport))
    sa.sin_addr.S_addr = int32(0)
    if `bind`(sock, cast[ptr sockaddr](addr sa), int32(sizeof(sa))) != 0:
      discard closesocket(sock); gFwds[idx].lsock = INVALID_SOCKET; return 1
    var rhostStr = newString(256)
    copyMem(addr rhostStr[0], addr gFwds[idx].rhost[0], 256)
    let nl = rhostStr.find('\0')
    if nl >= 0: rhostStr.setLen(nl)
    var hints: ADDRINFOA
    zeroMem(addr hints, sizeof(hints))
    hints.ai_family   = AF_INET
    hints.ai_socktype = SOCK_DGRAM
    var res: ptr ADDRINFOA = nil
    if getaddrinfo(rhostStr, $gFwds[idx].rport, addr hints, addr res) != 0:
      discard closesocket(sock); gFwds[idx].lsock = INVALID_SOCKET; return 1
    var dst: sockaddr_in
    copyMem(addr dst, res.ai_addr, sizeof(dst))
    freeaddrinfo(res)
    var buf: array[65535, byte]
    var cAddr: sockaddr_in; var cLen: int32 = int32(sizeof(cAddr))
    while not gFwds[idx].stop:
      let n = recvfrom(sock, cast[ptr char](addr buf[0]), int32(sizeof(buf)), 0,
        cast[ptr sockaddr](addr cAddr), addr cLen)
      if n <= 0: break
      discard sendto(sock, cast[ptr char](addr buf[0]), n, 0,
        cast[ptr sockaddr](addr dst), int32(sizeof(dst)))
    discard closesocket(sock)
    gFwds[idx].lsock = INVALID_SOCKET
    return 0

  # ── Public API ───────────────────────────────────────────────────────────

  proc portfwdAdd*(proto, lportStr, rhost, rportStr: string): string =
    fwdInit()
    let lport = try: parseInt(lportStr) except: -1
    let rport = try: parseInt(rportStr) except: -1
    if lport < 1 or lport > 65535: return "[-] portfwd: invalid lport"
    if rport < 1 or rport > 65535: return "[-] portfwd: invalid rport"
    if rhost.len == 0: return "[-] portfwd: rhost required"
    let isUDP = (proto == "udp")
    for i in 0..<PORTFWD_MAX:
      if gFwds[i].active and gFwds[i].lport == lport and gFwds[i].isUDP == isUDP:
        return "[-] portfwd: " & proto & ":" & lportStr & " already exists"
    var slot = -1
    for i in 0..<PORTFWD_MAX:
      if not gFwds[i].active: slot = i; break
    if slot < 0: return "[-] portfwd: max " & $PORTFWD_MAX & " forwards reached"
    zeroMem(addr gFwds[slot], sizeof(FwdEntry))
    gFwds[slot].active = true
    gFwds[slot].isUDP  = isUDP
    gFwds[slot].stop   = false
    gFwds[slot].lport  = lport
    gFwds[slot].rport  = rport
    gFwds[slot].lsock  = INVALID_SOCKET
    for i in 0..<min(rhost.len, 255):
      gFwds[slot].rhost[i] = rhost[i]
    let pp = cast[ptr ServerParam](alloc0(sizeof(ServerParam)))
    pp.idx = slot
    var tid: DWORD = 0
    gFwds[slot].thread = CreateThread(nil, 0,
      if isUDP: udpRelayProc else: tcpServerProc,
      cast[LPVOID](pp), 0, addr tid)
    if gFwds[slot].thread == 0:
      gFwds[slot].active = false
      dealloc(pp)
      return "[-] portfwd: CreateThread failed"
    return "[+] " & proto & " forwarding :" & lportStr & " → " & rhost & ":" & rportStr

  proc portfwdDel*(proto, lportStr: string): string =
    fwdInit()
    let lport = try: parseInt(lportStr) except: -1
    let isUDP = (proto == "udp")
    for i in 0..<PORTFWD_MAX:
      if gFwds[i].active and gFwds[i].lport == lport and gFwds[i].isUDP == isUDP:
        gFwds[i].stop = true
        if gFwds[i].lsock != INVALID_SOCKET:
          discard closesocket(gFwds[i].lsock)
        if gFwds[i].thread != 0:
          discard WaitForSingleObject(gFwds[i].thread, DWORD(2000))
          discard CloseHandle(gFwds[i].thread)
          gFwds[i].thread = 0
        gFwds[i].active = false
        return "[+] " & proto & " port forward :" & lportStr & " removed"
    return "[-] portfwd: no " & proto & " forward on port " & lportStr

  proc portfwdList*(): string =
    fwdInit()
    var lines: seq[string]
    for i in 0..<PORTFWD_MAX:
      if gFwds[i].active:
        var rh = newString(256)
        copyMem(addr rh[0], addr gFwds[i].rhost[0], 256)
        let nl = rh.find('\0')
        if nl >= 0: rh.setLen(nl)
        lines.add((if gFwds[i].isUDP: "udp" else: "tcp") &
          " :" & $gFwds[i].lport & " → " & rh & ":" & $gFwds[i].rport)
    if lines.len == 0: return "(no active port forwards)"
    return lines.join("\n")

  proc parsePortfwdArgs*(args: string): tuple[proto, lport, rhost, rport: string] =
    let parts = args.strip().splitWhitespace()
    if parts.len >= 4 and (parts[0] == "tcp" or parts[0] == "udp"):
      return (parts[0], parts[1], parts[2], parts[3])
    elif parts.len >= 3:
      return ("tcp", parts[0], parts[1], parts[2])
    return ("", "", "", "")

  proc parsePortfwdDelArgs*(args: string): tuple[proto, lport: string] =
    let parts = args.strip().splitWhitespace()
    if parts.len >= 2 and (parts[0] == "tcp" or parts[0] == "udp"):
      return (parts[0], parts[1])
    elif parts.len >= 1:
      return ("tcp", parts[0])
    return ("tcp", args.strip())

else:
  # Linux stubs
  proc portfwdAdd*(proto, lportStr, rhost, rportStr: string): string =
    "[-] portfwd: not supported on Linux"
  proc portfwdDel*(proto, lportStr: string): string =
    "[-] portfwd: not supported on Linux"
  proc portfwdList*(): string = "(no active port forwards)"
  proc parsePortfwdArgs*(args: string): tuple[proto, lport, rhost, rport: string] =
    ("", "", "", "")
  proc parsePortfwdDelArgs*(args: string): tuple[proto, lport: string] =
    ("tcp", "")
