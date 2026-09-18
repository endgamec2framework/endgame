//go:build windows

package agent

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procLookupPrivilegeNameW = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")
)

const tokenPrivilegesClass = 3 // TokenPrivileges

// privList returns all privileges on the current thread/process token with their states.
func privList() (string, error) {
	var token windows.Token
	r, _, e := procOpenProcessToken2.Call(
		uintptr(windows.CurrentProcess()),
		windows.TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	if r == 0 {
		return "", fmt.Errorf("OpenProcessToken: %w", e)
	}
	defer windows.CloseHandle(windows.Handle(token))

	var needed uint32
	procGetTokenInformation.Call(uintptr(token), tokenPrivilegesClass, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return "", fmt.Errorf("GetTokenInformation (size): unexpected 0")
	}

	buf := make([]byte, needed)
	r, _, e = procGetTokenInformation.Call(
		uintptr(token), tokenPrivilegesClass,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return "", fmt.Errorf("GetTokenInformation: %w", e)
	}

	count := binary.LittleEndian.Uint32(buf[0:4])
	var sb strings.Builder
	fmt.Fprintf(&sb, "Privilege                                       Status\n")
	fmt.Fprintf(&sb, "%-48s  %s\n", strings.Repeat("-", 48), "------")

	offset := 4
	for i := 0; i < int(count) && offset+12 <= len(buf); i++ {
		luidLow := binary.LittleEndian.Uint32(buf[offset:])
		luidHigh := binary.LittleEndian.Uint32(buf[offset+4:])
		attrs := binary.LittleEndian.Uint32(buf[offset+8:])
		offset += 12

		luid := windows.LUID{LowPart: luidLow, HighPart: int32(luidHigh)}
		name := luidToPrivName(luid)

		var status string
		switch {
		case attrs&windows.SE_PRIVILEGE_ENABLED != 0:
			status = "Enabled"
		case attrs&2 != 0: // SE_PRIVILEGE_ENABLED_BY_DEFAULT
			status = "Enabled (default)"
		default:
			status = "Disabled"
		}
		fmt.Fprintf(&sb, "  %-46s  %s\n", name, status)
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// privEnable enables one or more named privileges on the current process token.
// names: comma-separated or "all" to enable everything present.
func privEnable(names string) (string, error) {
	return privAdjust(names, true)
}

// privDisable disables one or more named privileges.
func privDisable(names string) (string, error) {
	return privAdjust(names, false)
}

func privAdjust(names string, enable bool) (string, error) {
	var token windows.Token
	r, _, e := procOpenProcessToken2.Call(
		uintptr(windows.CurrentProcess()),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	if r == 0 {
		return "", fmt.Errorf("OpenProcessToken: %w", e)
	}
	defer windows.CloseHandle(windows.Handle(token))

	var targets []string
	if strings.ToLower(strings.TrimSpace(names)) == "all" {
		targets = allPrivNames(windows.Handle(token))
	} else {
		for _, n := range strings.Split(names, ",") {
			if t := strings.TrimSpace(n); t != "" {
				targets = append(targets, t)
			}
		}
	}

	attrs := uint32(windows.SE_PRIVILEGE_ENABLED)
	if !enable {
		attrs = 4 // SE_PRIVILEGE_REMOVED
	}

	var ok, fail []string
	for _, name := range targets {
		privNameW, _ := syscall.UTF16PtrFromString(name)
		var luid windows.LUID
		if r, _, _ := procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(privNameW)), uintptr(unsafe.Pointer(&luid))); r == 0 {
			fail = append(fail, name+"(not found)")
			continue
		}
		tp := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges:     [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: attrs}},
		}
		r, _, e = procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
		if r == 0 {
			fail = append(fail, name+": "+e.Error())
		} else {
			ok = append(ok, name)
		}
	}

	action := "enabled"
	if !enable {
		action = "disabled"
	}
	var sb strings.Builder
	if len(ok) > 0 {
		fmt.Fprintf(&sb, "[+] %s: %s\n", action, strings.Join(ok, ", "))
	}
	if len(fail) > 0 {
		fmt.Fprintf(&sb, "[-] failed: %s\n", strings.Join(fail, ", "))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// luidToPrivName looks up the string name of a LUID.
func luidToPrivName(luid windows.LUID) string {
	var buf [256]uint16
	size := uint32(256)
	r, _, _ := procLookupPrivilegeNameW.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return fmt.Sprintf("LUID(%d,%d)", luid.LowPart, luid.HighPart)
	}
	return syscall.UTF16ToString(buf[:size])
}

// allPrivNames returns the string names of all privileges on the given token.
func allPrivNames(token windows.Handle) []string {
	var needed uint32
	procGetTokenInformation.Call(uintptr(token), tokenPrivilegesClass, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil
	}
	buf := make([]byte, needed)
	r, _, _ := procGetTokenInformation.Call(
		uintptr(token), tokenPrivilegesClass,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return nil
	}
	count := binary.LittleEndian.Uint32(buf[0:4])
	names := make([]string, 0, count)
	offset := 4
	for i := 0; i < int(count) && offset+12 <= len(buf); i++ {
		luidLow := binary.LittleEndian.Uint32(buf[offset:])
		luidHigh := binary.LittleEndian.Uint32(buf[offset+4:])
		offset += 12
		luid := windows.LUID{LowPart: luidLow, HighPart: int32(luidHigh)}
		names = append(names, luidToPrivName(luid))
	}
	return names
}
