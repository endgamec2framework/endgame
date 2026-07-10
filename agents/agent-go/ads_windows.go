//go:build windows

package agent

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WIN32_FIND_STREAM_DATA for FindFirstStreamW/FindNextStreamW.
type win32FindStreamData struct {
	StreamSize int64
	StreamName [296]uint16
}

var (
	procFindFirstStreamW = kernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = kernel32.NewProc("FindNextStreamW")
)

// adsWrite writes data to file:stream. Creates the stream if it doesn't exist.
func adsWrite(path, stream string, data []byte) error {
	full := path + ":" + stream
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// adsRead returns the contents of file:stream.
func adsRead(path, stream string) ([]byte, error) {
	full := path + ":" + stream
	return os.ReadFile(full)
}

// adsList enumerates all named streams on path using FindFirstStreamW / FindNextStreamW.
// Returns lines like "  :streamname:$DATA  (1.2 KB)".
func adsList(path string) (string, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	var data win32FindStreamData
	h, _, e := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(p)),
		0, // InfoLevel = FindStreamInfoStandard
		uintptr(unsafe.Pointer(&data)),
		0,
	)
	const invalidHandle = ^uintptr(0)
	if h == invalidHandle {
		if windows.Errno(e.(syscall.Errno)) == windows.ERROR_HANDLE_EOF {
			return "(no alternate streams)", nil
		}
		return "", fmt.Errorf("FindFirstStreamW: %w", e)
	}
	defer windows.CloseHandle(windows.Handle(h))

	var sb strings.Builder
	for {
		name := windows.UTF16ToString(data.StreamName[:])
		if !strings.EqualFold(name, "::$DATA") { // skip the default data stream
			sb.WriteString(fmt.Sprintf("  %-40s  %s\n", name, humanSize(data.StreamSize)))
		}
		r, _, _ := procFindNextStreamW.Call(h, uintptr(unsafe.Pointer(&data)))
		if r == 0 {
			break
		}
	}
	if sb.Len() == 0 {
		return "(no alternate streams)", nil
	}
	return sb.String(), nil
}

// adsCat is a convenience wrapper that reads and returns stream content as string.
func adsCat(path, stream string) (string, error) {
	b, err := adsRead(path, stream)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// adsDelete removes a named stream by overwriting with a zero-length file.
func adsDelete(path, stream string) error {
	full := path + ":" + stream
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		// Some streams can't be truncated — try DeleteFile via NtSetInformationFile
		p, _ := syscall.UTF16PtrFromString(`\\?\` + full)
		h, e2 := windows.CreateFile(p,
			windows.DELETE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			0, 0,
		)
		if e2 != nil {
			return err
		}
		defer windows.CloseHandle(h)
		// FILE_DISPOSITION_INFO: delete on close
		var disp uint32 = 1
		windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&disp)), 4)
		return nil
	}
	defer f.Close()
	// Drain so it's empty
	io.Copy(io.Discard, f)
	return nil
}
