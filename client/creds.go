package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"redteam/server"
)

const credUsage = `uso: cred <subcommand> [opciones]

  list [-q <filtro>]        listar credenciales (filtro por user/domain/host/source)
  add  -u <user> -s <secret> [-t type] [-d domain] [-H host] [--src fuente]
  del  <id>                 eliminar credencial por ID
  show <id>                 mostrar credencial completa
  import <file>             importar desde secretsdump/hashcat output
  dump                      volcar todas las credenciales (plaintext)

  tipos (-t):  plaintext | ntlm | krb5 | certificate  (defecto: plaintext)

ejemplos:
  cred list
  cred list -q krbtgt
  cred add -u admin -s 'P@ssw0rd1' -d corp.local -t plaintext -H 10.0.0.1
  cred add -u krbtgt -s 'aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8' -t ntlm
  cred del 3
  cred import /tmp/ntds.ntds.ntds
  cred import /tmp/hashes.txt`

func (cl *CLI) cmdCred(args []string) {
	if len(args) == 0 {
		fmt.Println(credUsage)
		return
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list", "ls":
		cl.credList(rest)
	case "add":
		cl.credAdd(rest)
	case "del", "rm", "delete":
		if len(rest) == 0 {
			fmt.Println("uso: cred del <id>")
			return
		}
		cl.credDel(rest[0])
	case "show":
		if len(rest) == 0 {
			fmt.Println("uso: cred show <id>")
			return
		}
		cl.credShow(rest[0])
	case "import":
		if len(rest) == 0 {
			fmt.Println("uso: cred import <file>")
			return
		}
		cl.credImport(rest[0])
	case "dump":
		cl.credDump()
	default:
		fmt.Println(credUsage)
	}
}

func (cl *CLI) credList(args []string) {
	_, flags := parseLocalFlags(args)
	filter := flags["q"]
	raw, err := cl.c.ListCreds(filter)
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	var creds []*server.Credential
	if err := json.Unmarshal(raw, &creds); err != nil {
		fmt.Println("[!] parse:", err)
		return
	}
	if len(creds) == 0 {
		fmt.Println("  (no credentials stored)")
		return
	}
	fmt.Printf("\n  %-4s  %-11s  %-20s  %-30s  %-20s  %s\n",
		"ID", "TYPE", "DOMAIN\\USER", "SECRET", "HOST", "SOURCE")
	fmt.Println("  " + strings.Repeat("─", 105))
	for _, c := range creds {
		identity := c.Username
		if c.Domain != "" {
			identity = c.Domain + `\` + c.Username
		}
		secret := c.Secret
		if len(secret) > 30 {
			secret = secret[:27] + "..."
		}
		fmt.Printf("  %-4d  %-11s  %-20s  %-30s  %-20s  %s\n",
			c.ID, c.Type, identity, secret, c.Host, c.Source)
	}
	fmt.Println()
}

func (cl *CLI) credAdd(args []string) {
	_, flags := parseLocalFlags(args)
	username := flags["u"]
	secret := flags["s"]
	if username == "" || secret == "" {
		fmt.Println("[!] -u <user> y -s <secret> son obligatorios")
		return
	}
	credType := flags["t"]
	if credType == "" {
		// auto-detect: if it looks like an NTLM hash
		if isNTLMHash(secret) {
			credType = "ntlm"
		} else {
			credType = "plaintext"
		}
	}
	raw, err := cl.c.AddCred(credType, flags["d"], username, secret, flags["H"], flags["src"])
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(raw, &resp)
	fmt.Printf("[+] credencial guardada (id=%d)  %s\\%s [%s]\n", resp.ID, flags["d"], username, credType)
}

func (cl *CLI) credDel(idStr string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		fmt.Println("[!] ID inválido:", idStr)
		return
	}
	if err := cl.c.DeleteCred(id); err != nil {
		fmt.Println("[!]", err)
		return
	}
	fmt.Printf("[+] credencial %d eliminada\n", id)
}

func (cl *CLI) credShow(idStr string) {
	// list and filter by ID
	raw, err := cl.c.ListCreds("")
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	var creds []*server.Credential
	json.Unmarshal(raw, &creds)
	id, _ := strconv.ParseInt(idStr, 10, 64)
	for _, c := range creds {
		if c.ID == id {
			fmt.Printf("\n  ID:      %d\n", c.ID)
			fmt.Printf("  Type:    %s\n", c.Type)
			fmt.Printf("  Domain:  %s\n", c.Domain)
			fmt.Printf("  User:    %s\n", c.Username)
			fmt.Printf("  Secret:  %s\n", c.Secret)
			fmt.Printf("  Host:    %s\n", c.Host)
			fmt.Printf("  Source:  %s\n", c.Source)
			fmt.Printf("  By:      %s\n", c.Operator)
			fmt.Printf("  At:      %s\n\n", c.CapturedAt.Format("2006-01-02 15:04:05"))
			return
		}
	}
	fmt.Println("[!] credencial no encontrada:", idStr)
}

func (cl *CLI) credImport(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	defer f.Close()

	added := 0
	skipped := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Detect format:
		// secretsdump:   DOMAIN\user:RID:LM:NT:::
		// hashcat:       user:NT
		// crackedHash:   NT:password
		// plaintext:     user:password

		if c := parseSecretsDumpLine(line); c != nil {
			_, err := cl.c.AddCred(c.Type, c.Domain, c.Username, c.Secret, c.Host, c.Source)
			if err == nil {
				added++
			} else {
				skipped++
			}
			continue
		}
		if c := parseColonLine(line); c != nil {
			_, err := cl.c.AddCred(c.Type, c.Domain, c.Username, c.Secret, c.Host, c.Source)
			if err == nil {
				added++
			} else {
				skipped++
			}
			continue
		}
		skipped++
	}
	fmt.Printf("[+] importado: %d credenciales (%d omitidas)\n", added, skipped)
}

func (cl *CLI) credDump() {
	raw, err := cl.c.ListCreds("")
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	var creds []*server.Credential
	json.Unmarshal(raw, &creds)
	for _, c := range creds {
		if c.Domain != "" {
			fmt.Printf("%s\\%s:%s\n", c.Domain, c.Username, c.Secret)
		} else {
			fmt.Printf("%s:%s\n", c.Username, c.Secret)
		}
	}
}

// ── parsers ───────────────────────────────────────────────────────────────

type parsedCred struct {
	Type, Domain, Username, Secret, Host, Source string
}

// parseSecretsDumpLine parses: DOMAIN\user:RID:LMHash:NTHash:::
func parseSecretsDumpLine(line string) *parsedCred {
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return nil
	}
	// parts[0] = DOMAIN\user, parts[1] = RID, parts[2] = LM, parts[3] = NT
	domainUser := parts[0]
	lmHash := parts[2]
	ntHash := parts[3]
	if !isHex32(lmHash) || !isHex32(ntHash) {
		return nil
	}
	domain, user := splitDomainUser(domainUser)
	secret := lmHash + ":" + ntHash
	if lmHash == "aad3b435b51404eeaad3b435b51404ee" {
		secret = ntHash // show only NT hash if LM is empty
	}
	return &parsedCred{Type: "ntlm", Domain: domain, Username: user, Secret: secret, Source: "secretsdump"}
}

// parseColonLine parses: user:secret or domain\user:secret
func parseColonLine(line string) *parsedCred {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return nil
	}
	left := line[:idx]
	right := line[idx+1:]
	if right == "" {
		return nil
	}
	domain, user := splitDomainUser(left)
	credType := "plaintext"
	if isNTLMHash(right) {
		credType = "ntlm"
	}
	return &parsedCred{Type: credType, Domain: domain, Username: user, Secret: right, Source: "import"}
}

func splitDomainUser(s string) (domain, user string) {
	if idx := strings.Index(s, `\`); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	if idx := strings.Index(s, "@"); idx >= 0 {
		return s[idx+1:], s[:idx]
	}
	return "", s
}

func isNTLMHash(s string) bool {
	// NT hash alone: 32 hex chars
	// LM:NT: 32:32
	if isHex32(s) {
		return true
	}
	parts := strings.Split(s, ":")
	return len(parts) == 2 && isHex32(parts[0]) && isHex32(parts[1])
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
