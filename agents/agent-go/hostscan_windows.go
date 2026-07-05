//go:build windows

package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi    = windows.NewLazySystemDLL("iphlpapi.dll")
	procSendARP = iphlpapi.NewProc("SendARP")
)

// arpProbe sends an ARP request via iphlpapi!SendARP.
// No elevation required — this is a normal Windows API call.
// Returns MAC address string and true if the host responded.
func arpProbe(ip4 net.IP) (string, bool) {
	if ip4 == nil {
		return "", false
	}
	// SendARP expects the IP in the same byte order as inet_addr():
	// bytes stored as-is in a DWORD, i.e. little-endian read of the 4 octets.
	destIP := binary.LittleEndian.Uint32(ip4)

	var macAddr [6]byte
	macLen := uint32(unsafe.Sizeof(macAddr))

	ret, _, _ := procSendARP.Call(
		uintptr(destIP),
		0, // SrcIP: 0 = let Windows choose
		uintptr(unsafe.Pointer(&macAddr[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 {
		return "", false
	}
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5])
	return mac, true
}
