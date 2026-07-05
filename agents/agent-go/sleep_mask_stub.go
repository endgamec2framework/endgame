//go:build !windows

package agent

import "time"

// sleepMask on non-Windows is just a regular sleep.
func sleepMask(durationMs uint32) {
	time.Sleep(time.Duration(durationMs) * time.Millisecond)
}

func sleepMaskNoAccess(durationMs uint32) {
	time.Sleep(time.Duration(durationMs) * time.Millisecond)
}

func sleepMaskEkko(durationMs uint32) {
	time.Sleep(time.Duration(durationMs) * time.Millisecond)
}

func encryptRegion(data []byte, key byte) {
	for i := range data {
		data[i] ^= key
	}
}
