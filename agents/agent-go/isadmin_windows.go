package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	// Fast path: token integrity >= HIGH means already elevated (SYSTEM or admin runas)
	if integrityRID(token) >= 0x3000 {
		return true
	}

	// If UAC is in play the process runs with a filtered MEDIUM token but Windows
	// keeps a linked HIGH-integrity token for the same logon session.  Detect this
	// so that a local-admin running without elevation still gets the orange icon.
	if linked, err := token.GetLinkedToken(); err == nil {
		defer linked.Close()
		return integrityRID(linked) >= 0x3000
	}

	return false
}

func integrityRID(tok windows.Token) uint32 {
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return 0
	}
	buf := make([]byte, n)
	if windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n) != nil {
		return 0
	}
	sidPtr := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	c := sidPtr.SubAuthorityCount()
	if c == 0 {
		return 0
	}
	return sidPtr.SubAuthority(uint32(c) - 1)
}
