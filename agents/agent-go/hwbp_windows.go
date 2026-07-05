//go:build windows

package agent

import (
	"encoding/binary"
	"unsafe"
)

// clearHardwareBreakpoints removes any hardware breakpoints installed
// by EDR/debuggers on the current thread by zeroing DR0-DR7 in the thread context.
// Uses the same raw-buffer CONTEXT approach as hasHWBreakpoints() to stay
// compatible with cross-compilation (windows.CONTEXT is not available in CGO-free builds).
func clearHardwareBreakpoints() {
	defer func() { recover() }()

	buf := make([]byte, ctxSize+16)
	offset := uintptr(unsafe.Pointer(&buf[0])) & 0xF
	if offset != 0 {
		buf = buf[16-offset:]
	}
	ctx := buf[:ctxSize]
	binary.LittleEndian.PutUint32(ctx[ctxFlagsOff:], CONTEXT_DEBUG_REGISTERS)

	hThread, _, _ := procGetCurrentThread.Call()
	r, _, _ := procGetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx[0])))
	if r == 0 {
		return
	}

	// Zero DR0–DR3 (breakpoint addresses) and DR6/DR7 (status/control).
	binary.LittleEndian.PutUint64(ctx[ctxDr0Off:], 0)
	binary.LittleEndian.PutUint64(ctx[ctxDr1Off:], 0)
	binary.LittleEndian.PutUint64(ctx[ctxDr2Off:], 0)
	binary.LittleEndian.PutUint64(ctx[ctxDr3Off:], 0)
	// DR6 and DR7 are at fixed offsets in the x64 CONTEXT (0x68 and 0x70).
	binary.LittleEndian.PutUint64(ctx[0x68:], 0) // Dr6
	binary.LittleEndian.PutUint64(ctx[0x70:], 0) // Dr7

	procSetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx[0])))
}
