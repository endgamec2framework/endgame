package server

import (
	"regexp"
	"strings"
)

// blank NT / LM hashes that should be ignored
const (
	blankNT = "31d6cfe0d16ae931b73c59d7e0c089c0"
	blankLM = "aad3b435b51404eeaad3b435b51404ee"
)

// parsedCred is an internal struct used during parsing before writing to DB.
type parsedCred struct {
	credType string
	domain   string
	username string
	secret   string
}

// dedup key so we skip identical creds within a single output blob.
func credKey(c parsedCred) string {
	return strings.ToLower(c.credType + "|" + c.domain + "|" + c.username + "|" + c.secret)
}

// ── compiled regexes ──────────────────────────────────────────────────────────

var (
	// secretsdump: DOMAIN\user:rid:lmhash:nthash:::
	// also handles local accounts (no domain prefix): user:500:lm:nt:::
	reSecretsdump = regexp.MustCompile(
		`(?m)^([^:\\\r\n]+)\\([^:\r\n]+):\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::[ \t]*$|` +
			`(?m)^([^:\\\r\n]+):\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::[ \t]*$`,
	)

	// certipy-ad: Got hash for 'user@domain': lm:nt
	reCertipy = regexp.MustCompile(
		`(?i)Got hash for '([^@']+)@([^']+)':\s*([0-9a-fA-F]{32}):([0-9a-fA-F]{32})`,
	)

	// Rubeus kerberoast: $krb5tgs$23$*user$domain$SPN*$...
	reKerberoast = regexp.MustCompile(
		`(\$krb5tgs\$\d+\$\*([^$]+)\$([^$]+)\$[^$]+\*\$[^\s]+)`,
	)

	// Rubeus AS-REP roast: $krb5asrep$23$user@domain:hash...
	reASREP = regexp.MustCompile(
		`(\$krb5asrep\$\d+\$([^@]+)@([^:]+):[^\s]+)`,
	)
)

// parseMimikatz extracts credentials from mimikatz-style output blocks.
// It looks for blocks delimited by "Authentication Id" or "* Username" sections.
func parseMimikatz(output string) []parsedCred {
	var creds []parsedCred

	// Split on common mimikatz block delimiters
	lines := strings.Split(output, "\n")

	var (
		username string
		domain   string
		ntlm     string
		password string
	)

	flush := func() {
		if username == "" || username == "(null)" {
			return
		}
		if ntlm != "" && ntlm != blankNT && ntlm != blankLM {
			creds = append(creds, parsedCred{
				credType: "ntlm",
				domain:   domain,
				username: username,
				secret:   ntlm,
			})
		}
		if password != "" && password != "(null)" {
			creds = append(creds, parsedCred{
				credType: "plaintext",
				domain:   domain,
				username: username,
				secret:   password,
			})
		}
		username, domain, ntlm, password = "", "", "", ""
	}

	reUsername := regexp.MustCompile(`(?i)^\s*\*?\s*Username\s*:\s*(.+)$`)
	reDomain   := regexp.MustCompile(`(?i)^\s*\*?\s*Domain\s*:\s*(.+)$`)
	reNTLM     := regexp.MustCompile(`(?i)^\s*\*?\s*NTLM\s*:\s*([0-9a-fA-F]{32})`)
	rePassword := regexp.MustCompile(`(?i)^\s*\*?\s*Password\s*:\s*(.+)$`)

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		// A new Authentication Id block means we flush the current one
		if strings.Contains(line, "Authentication Id") || strings.HasPrefix(strings.TrimSpace(line), "msv") {
			flush()
			continue
		}

		if m := reUsername.FindStringSubmatch(line); m != nil {
			val := strings.TrimSpace(m[1])
			if val != "" && val != "(null)" {
				if username != "" {
					flush()
				}
				username = val
			}
			continue
		}
		if m := reDomain.FindStringSubmatch(line); m != nil {
			domain = strings.TrimSpace(m[1])
			continue
		}
		if m := reNTLM.FindStringSubmatch(line); m != nil {
			ntlm = strings.ToLower(strings.TrimSpace(m[1]))
			continue
		}
		if m := rePassword.FindStringSubmatch(line); m != nil {
			val := strings.TrimSpace(m[1])
			if val != "(null)" && val != "" {
				password = val
			}
			continue
		}
	}
	flush()
	return creds
}

// ParseCreds scans an arbitrary output string and returns all recognised credentials.
func ParseCreds(output string) []parsedCred {
	seen := map[string]bool{}
	var result []parsedCred

	add := func(c parsedCred) {
		c.domain = strings.TrimSpace(c.domain)
		c.username = strings.TrimSpace(c.username)
		c.secret = strings.TrimSpace(c.secret)
		if c.username == "" || c.secret == "" {
			return
		}
		// skip blank hashes
		low := strings.ToLower(c.secret)
		if low == blankNT || low == blankLM {
			return
		}
		k := credKey(c)
		if seen[k] {
			return
		}
		seen[k] = true
		result = append(result, c)
	}

	// ── secretsdump ───────────────────────────────────────────────────────────
	for _, m := range reSecretsdump.FindAllStringSubmatch(output, -1) {
		// group 1-4: domain\user match
		if m[1] != "" {
			nt := strings.ToLower(m[4])
			if nt != blankNT {
				add(parsedCred{credType: "ntlm", domain: m[1], username: m[2], secret: nt})
			}
		} else {
			// group 5-7: local user (no domain)
			nt := strings.ToLower(m[7])
			if nt != blankNT {
				add(parsedCred{credType: "ntlm", domain: "", username: m[5], secret: nt})
			}
		}
	}

	// ── certipy-ad ────────────────────────────────────────────────────────────
	for _, m := range reCertipy.FindAllStringSubmatch(output, -1) {
		nt := strings.ToLower(m[4])
		if nt != blankNT {
			add(parsedCred{credType: "ntlm", domain: m[2], username: m[1], secret: nt})
		}
	}

	// ── Rubeus kerberoast ─────────────────────────────────────────────────────
	for _, m := range reKerberoast.FindAllStringSubmatch(output, -1) {
		add(parsedCred{credType: "kerberoast", domain: m[3], username: m[2], secret: m[1]})
	}

	// ── Rubeus AS-REP roast ───────────────────────────────────────────────────
	for _, m := range reASREP.FindAllStringSubmatch(output, -1) {
		add(parsedCred{credType: "asrep", domain: m[3], username: m[2], secret: m[1]})
	}

	// ── Mimikatz blocks ───────────────────────────────────────────────────────
	for _, c := range parseMimikatz(output) {
		add(c)
	}

	return result
}
