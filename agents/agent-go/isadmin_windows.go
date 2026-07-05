package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func isElevated() bool {
	const highIntegrity = 0x3000 // SECURITY_MANDATORY_HIGH_RID

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	// Query TokenIntegrityLevel to get the mandatory label
	var n uint32
	windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return token.IsElevated()
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return token.IsElevated()
	}
	// TOKEN_MANDATORY_LABEL layout: SID_AND_ATTRIBUTES { Sid *SID, Attributes uint32 }
	// We need the last sub-authority of the SID, which is the integrity level RID.
	sidPtr := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	count := sidPtr.SubAuthorityCount()
	if count == 0 {
		return false
	}
	rid := sidPtr.SubAuthority(uint32(count) - 1)
	return rid >= highIntegrity
}
