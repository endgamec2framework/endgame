//go:build windows

package agent

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSetFileTime = kernel32.NewProc("SetFileTime")
	procGetFileTime = kernel32.NewProc("GetFileTime")
)

// timestompFile sets the Created, Accessed, and Modified timestamps of target.
// ref can be:
//   - "" or "kernel32"   → copy from %SystemRoot%\System32\kernel32.dll
//   - "YYYY-MM-DD"       → set all timestamps to midnight on that date (UTC)
//   - any other path     → copy timestamps from that file
func timestompFile(target, ref string) error {
	var ct, at, wt windows.Filetime

	switch {
	case ref == "" || strings.EqualFold(ref, "kernel32"):
		ref = `C:\Windows\System32\kernel32.dll`
		fallthrough
	default:
		// Try parsing as a date first
		if t, err := time.Parse("2006-01-02", ref); err == nil {
			ft := timeToFiletime(t)
			ct, at, wt = ft, ft, ft
		} else {
			// Treat ref as a source file and copy its timestamps
			var err2 error
			ct, at, wt, err2 = getFiletimes(ref)
			if err2 != nil {
				return fmt.Errorf("ref %q: %w", ref, err2)
			}
		}
	}

	return setFiletimes(target, ct, at, wt)
}

func getFiletimes(path string) (created, accessed, written windows.Filetime, err error) {
	p, err2 := syscall.UTF16PtrFromString(path)
	if err2 != nil {
		err = err2
		return
	}
	h, err2 := windows.CreateFile(p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err2 != nil {
		err = err2
		return
	}
	defer windows.CloseHandle(h)

	r, _, e := procGetFileTime.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&created)),
		uintptr(unsafe.Pointer(&accessed)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		err = e
	}
	return
}

func setFiletimes(path string, created, accessed, written windows.Filetime) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p,
		windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	r, _, e := procSetFileTime.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&created)),
		uintptr(unsafe.Pointer(&accessed)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		return e
	}
	return nil
}

func timeToFiletime(t time.Time) windows.Filetime {
	// Windows FILETIME = 100-nanosecond intervals since 1601-01-01 UTC
	const epoch int64 = 116444736000000000
	ns := t.UTC().UnixNano()
	ft := ns/100 + epoch
	return windows.Filetime{
		LowDateTime:  uint32(ft),
		HighDateTime: uint32(ft >> 32),
	}
}
