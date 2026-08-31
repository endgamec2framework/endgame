//go:build !windows

package agent

// Drip writes target Windows process memory and is not applicable on POSIX
// builds. Keeping a no-op implementation preserves cross-platform builds.
func dripStore(uintptr, []byte) {}
