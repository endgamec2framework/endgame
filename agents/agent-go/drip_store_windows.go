//go:build windows

package agent

import (
	"syscall"
	"unsafe"
)

var procRtlMoveMemory = syscall.NewLazyDLL("kernel32.dll").NewProc("RtlMoveMemory")

func dripStore(dst uintptr, data []byte) {
	if dst == 0 || len(data) == 0 {
		return
	}
	_, _, _ = procRtlMoveMemory.Call(dst, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
}
