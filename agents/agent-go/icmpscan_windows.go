//go:build windows

package agent

import (
	"encoding/binary"
	"net"
	"unsafe"
)

var (
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
)

// icmpProbe sends an ICMP echo using IcmpSendEcho (no elevation required on Windows).
func icmpProbe(ip4 net.IP, timeoutMs int) bool {
	if ip4 == nil {
		return false
	}
	if timeoutMs <= 0 {
		timeoutMs = 500
	}

	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return false
	}
	defer procIcmpCloseHandle.Call(h)

	// IPAddr: same byte order as SendARP (LittleEndian DWORD of the 4 octets)
	ip4b := ip4.To4()
	destIP := binary.LittleEndian.Uint32(ip4b)

	pingData := [8]byte{'E', 'N', 'D', 'G', 'A', 'M', 'E', 0}
	replyBuf := make([]byte, 28+len(pingData)) // ICMP_ECHO_REPLY + data

	ret, _, _ := procIcmpSendEcho.Call(
		h,
		uintptr(destIP),
		uintptr(unsafe.Pointer(&pingData[0])),
		uintptr(len(pingData)),
		0, // RequestOptions (NULL)
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(timeoutMs),
	)
	return ret > 0
}
