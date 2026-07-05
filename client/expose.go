package client

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ── tipos ─────────────────────────────────────────────────────────────────────

type tunnelEntry struct {
	kind     string
	procs    []*os.Process
	agentURL string
	opURL    string
}

var (
	tunMu   sync.Mutex
	tunnels = map[string]*tunnelEntry{}
)

var urlRe = regexp.MustCompile(`https?://[a-zA-Z0-9._\-]+\.[a-zA-Z]{2,}(?::\d+)?`)

// ── ayuda ─────────────────────────────────────────────────────────────────────

const exposeUsage = `uso: expose <provider> [opciones]

providers:
  cloudflare   Sin VPS. Gratis. Recomendado para ops rápidas.
  chisel       Con VPS propio. TCP puro. Máximo control.
  ngrok        Sin VPS. Solo HTTP (mTLS requiere cuenta ngrok).

subcomandos:
  expose status    túneles activos y sus URLs
  expose stop      parar todos los túneles

──────────────────────────────────────────────────────────────────
OPCIÓN A — cloudflare (sin VPS, gratis)
──────────────────────────────────────────────────────────────────

  Paso 1 · Arrancar listener de agentes y wstunnel para operador:
    c2> listener start http 8080
    c2> listener start wstunnel 40000

  Paso 2 · Exponer ambos puertos (instala cloudflared automáticamente):
    c2> expose cloudflare
    [+] agent C2  → https://abc-def-xyz.trycloudflare.com
    [+] operator  → wss://uvw-rst.trycloudflare.com/ws

  Paso 3 · Compilar agente apuntando a la URL de cloudflare:
    c2> build http abc-def-xyz.trycloudflare.com 60 20

  Paso 4 · Generar perfil de operador con la URL wss://:
    c2> gencert alice
    → editar alice.json:  "via_ws": "wss://uvw-rst.trycloudflare.com/ws"

  Paso 5 · El operador conecta desde cualquier red:
    $ c2-client -profile alice.json

──────────────────────────────────────────────────────────────────
OPCIÓN B — chisel (con VPS, control total)
──────────────────────────────────────────────────────────────────

  Pre-requisito · Instalar y arrancar chisel SERVER en el VPS:
    vps$ wget -qO chisel https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
    vps$ gunzip chisel && chmod +x chisel
    vps$ ./chisel server --port 9000 --auth redteam:s3cret --reverse

  Paso 1 · Conectar chisel desde Kali (instala chisel cliente automáticamente):
    c2> expose chisel vps.example.com:9000 -u redteam:s3cret
    [+] agent C2  → http://vps.example.com:8080
    [+] operator  → vps.example.com:31337  (mTLS directo)

  Paso 2 · Compilar agente apuntando a la IP del VPS:
    c2> build http vps.example.com 60 20

  Paso 3 · Operador conecta directamente (mTLS, sin wstunnel):
    → editar alice.json:  "server": "vps.example.com:31337"
    $ c2-client -profile alice.json

  Con puerto personalizado:
    c2> expose chisel vps.example.com:443 -u ops:pass -p 8443

──────────────────────────────────────────────────────────────────
OPCIÓN C — ngrok (sin VPS, solo HTTP)
──────────────────────────────────────────────────────────────────

  Paso 1 · Exponer solo el listener HTTP de agentes:
    c2> expose ngrok
    [+] agent C2  → https://xxxx-xx-xx-xx-xx.ngrok-free.app

  Paso 2 · Compilar agente:
    c2> build http xxxx-xx-xx-xx-xx.ngrok-free.app 60 20

  Nota: el API mTLS del operador (:31337) no puede exponerse con ngrok
        en la versión gratuita. Usar cloudflare o chisel para operadores remotos.

  Con puerto alternativo:
    c2> expose ngrok -p 9090

──────────────────────────────────────────────────────────────────
  expose status    ver URLs de los túneles activos
  expose stop      matar todos los procesos de túnel`

// ── dispatch principal ────────────────────────────────────────────────────────

func (cl *CLI) cmdExpose(args []string) {
	if len(args) == 0 {
		fmt.Println(exposeUsage)
		return
	}
	switch args[0] {
	case "cloudflare", "cf":
		cl.exposeCloudflare(args[1:])
	case "chisel":
		cl.exposeChisel(args[1:])
	case "ngrok":
		cl.exposeNgrok(args[1:])
	case "status":
		cl.exposeTunnelStatus()
	case "stop":
		cl.exposeTunnelStop()
	default:
		fmt.Println(exposeUsage)
	}
}

// ── cloudflare ────────────────────────────────────────────────────────────────

func (cl *CLI) exposeCloudflare(args []string) {
	_, flags := parseLocalFlags(args)
	agentPort := flags["p"]
	if agentPort == "" {
		agentPort = "8080"
	}
	wsPort := flags["ws"]
	if wsPort == "" {
		wsPort = "40000"
	}

	cf, err := ensureTool("cloudflared",
		"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-"+goArch(),
		"binary")
	if err != nil {
		fmt.Println("[!]", err)
		return
	}

	entry := &tunnelEntry{kind: "cloudflare"}

	// Túnel para agentes
	fmt.Printf("[*] cloudflared → agent HTTP :%s …\n", agentPort)
	agentURL, proc1, err := startCloudflaredTunnel(cf, agentPort)
	if err != nil {
		fmt.Println("[!] agent tunnel:", err)
		return
	}
	entry.procs = append(entry.procs, proc1)
	entry.agentURL = agentURL
	fmt.Printf("\033[32m[+]\033[0m agent C2  → %s\n", agentURL)

	// Túnel para operador via wstunnel
	fmt.Printf("[*] cloudflared → operator wstunnel :%s …\n", wsPort)
	wsURL, proc2, err := startCloudflaredTunnel(cf, wsPort)
	if err != nil {
		fmt.Println("[!] wstunnel tunnel:", err)
	} else {
		entry.procs = append(entry.procs, proc2)
		entry.opURL = wsURL
		opWS := "wss://" + strings.TrimPrefix(wsURL, "https://") + "/ws"
		fmt.Printf("\033[32m[+]\033[0m operator  → %s\n", opWS)
		fmt.Printf("\n    Genera perfil de operador con:\n")
		fmt.Printf("    gencert <label>   →  editar .json  via_ws: %s\n\n", opWS)
	}

	tunMu.Lock()
	tunnels["cloudflare"] = entry
	tunMu.Unlock()
}

func startCloudflaredTunnel(cfPath, port string) (tunnelURL string, proc *os.Process, err error) {
	cmd := exec.Command(cfPath, "tunnel", "--url", "http://127.0.0.1:"+port, "--no-autoupdate")

	// cloudflared escribe la URL a stderr
	pr, pw, _ := os.Pipe()
	cmd.Stderr = pw
	cmd.Stdout = io.Discard

	if err = cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return
	}
	pw.Close()

	urlCh := make(chan string, 1)
	go func() {
		defer pr.Close()
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "trycloudflare.com") {
				if m := urlRe.FindString(line); m != "" {
					select {
					case urlCh <- m:
					default:
					}
				}
			}
		}
	}()

	select {
	case u := <-urlCh:
		return u, cmd.Process, nil
	case <-time.After(40 * time.Second):
		cmd.Process.Kill()
		return "", nil, fmt.Errorf("timeout esperando URL de cloudflared")
	}
}

// ── chisel ────────────────────────────────────────────────────────────────────

func (cl *CLI) exposeChisel(args []string) {
	pos, flags := parseLocalFlags(args)
	if len(pos) == 0 {
		fmt.Println("uso: expose chisel <host:port> [-u <user:pass>] [-p <agent_port>]")
		return
	}

	chiselURL, err := latestGHAsset("jpillora", "chisel", "linux_"+goArch()+".gz")
	if err != nil {
		chiselURL = "https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_" + goArch() + ".gz"
	}
	ch, err := ensureTool("chisel", chiselURL, "gzip")
	if err != nil {
		fmt.Println("[!]", err)
		return
	}

	vps := pos[0]
	agentPort := flags["p"]
	if agentPort == "" {
		agentPort = "8080"
	}

	a := []string{"client"}
	if u := flags["u"]; u != "" {
		a = append(a, "--auth", u)
	}
	host := strings.Split(vps, ":")[0]
	a = append(a, vps,
		"R:"+agentPort+":127.0.0.1:"+agentPort,
		"R:31337:127.0.0.1:31337",
	)

	fmt.Printf("[*] chisel client %s → R:%s, R:31337\n", vps, agentPort)
	cmd := exec.Command(ch, a...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Println("[!]", err)
		return
	}

	tunMu.Lock()
	tunnels["chisel"] = &tunnelEntry{
		kind:     "chisel",
		procs:    []*os.Process{cmd.Process},
		agentURL: "http://" + host + ":" + agentPort,
		opURL:    host + ":31337",
	}
	tunMu.Unlock()

	fmt.Printf("\033[32m[+]\033[0m agent C2  → http://%s:%s\n", host, agentPort)
	fmt.Printf("\033[32m[+]\033[0m operator  → %s:31337  (mTLS directo)\n", host)
}

// ── ngrok ─────────────────────────────────────────────────────────────────────

func (cl *CLI) exposeNgrok(args []string) {
	_, flags := parseLocalFlags(args)
	agentPort := flags["p"]
	if agentPort == "" {
		agentPort = "8080"
	}

	ng, err := ensureTool("ngrok",
		"https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-"+goArch()+".tgz",
		"targz")
	if err != nil {
		// Fallback: snap
		fmt.Println("[*] intentando: snap install ngrok")
		exec.Command("snap", "install", "ngrok").Run()
		ng = cl.findTool("ngrok")
		if ng == "" {
			fmt.Println("[!] no se pudo instalar ngrok")
			return
		}
	}

	fmt.Printf("[*] ngrok http :%s\n", agentPort)
	cmd := exec.Command(ng, "http", agentPort)
	if err := cmd.Start(); err != nil {
		fmt.Println("[!]", err)
		return
	}

	// ngrok necesita ~2s para arrancar su API local
	time.Sleep(2 * time.Second)
	ngURL := queryNgrokAPI()

	tunMu.Lock()
	tunnels["ngrok"] = &tunnelEntry{
		kind:     "ngrok",
		procs:    []*os.Process{cmd.Process},
		agentURL: ngURL,
	}
	tunMu.Unlock()

	if ngURL != "" {
		fmt.Printf("\033[32m[+]\033[0m agent C2  → %s\n", ngURL)
	} else {
		fmt.Println("[!] no se pudo obtener URL de ngrok (¿ya está corriendo en :4040?)")
	}
	fmt.Println("[!] operator mTLS requiere cuenta ngrok — usa 'expose cloudflare' o 'expose chisel'")
}

func queryNgrokAPI() string {
	resp, err := http.Get("http://localhost:4040/api/tunnels")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var result struct {
		Tunnels []struct {
			PublicURL string `json:"public_url"`
		} `json:"tunnels"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	for _, t := range result.Tunnels {
		if strings.HasPrefix(t.PublicURL, "https://") {
			return t.PublicURL
		}
	}
	return ""
}

// ── status / stop ─────────────────────────────────────────────────────────────

func (cl *CLI) exposeTunnelStatus() {
	tunMu.Lock()
	defer tunMu.Unlock()
	if len(tunnels) == 0 {
		fmt.Println("no hay túneles activos")
		return
	}
	fmt.Printf("%-12s  %-40s  %s\n", "PROVIDER", "AGENT URL", "OPERATOR URL")
	fmt.Println(strings.Repeat("-", 85))
	for k, t := range tunnels {
		fmt.Printf("%-12s  %-40s  %s\n", k, t.agentURL, t.opURL)
	}
}

func (cl *CLI) exposeTunnelStop() {
	tunMu.Lock()
	defer tunMu.Unlock()
	if len(tunnels) == 0 {
		fmt.Println("no hay túneles activos")
		return
	}
	for k, t := range tunnels {
		for _, p := range t.procs {
			p.Kill()
		}
		fmt.Printf("[+] %s detenido\n", k)
		delete(tunnels, k)
	}
}

// ── helpers de descarga ───────────────────────────────────────────────────────

func goArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	default:
		return "amd64"
	}
}

// ensureTool devuelve la ruta al binario, descargándolo si no está presente.
func ensureTool(name, downloadURL, format string) (string, error) {
	// Check PATH and common dirs
	extras := []string{"/tmp", "/usr/local/bin"}
	for _, p := range append([]string{""}, extras...) {
		candidate := p + "/" + name
		if p == "" {
			if path, err := exec.LookPath(name); err == nil {
				return path, nil
			}
		} else if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	dest := "/tmp/" + name
	fmt.Printf("[*] descargando %s …\n", name)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("descargando %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d al descargar %s", resp.StatusCode, name)
	}

	switch format {
	case "binary":
		if err := writeBinary(resp.Body, dest); err != nil {
			return "", err
		}
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", err
		}
		defer gz.Close()
		if err := writeBinary(gz, dest); err != nil {
			return "", err
		}
	case "targz":
		if err := extractTarGz(resp.Body, name, dest); err != nil {
			return "", err
		}
	}

	fmt.Printf("[+] %s → %s\n", name, dest)
	return dest, nil
}

func writeBinary(r io.Reader, dest string) error {
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}

func extractTarGz(r io.Reader, binaryName, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		base := hdr.Name
		if idx := strings.LastIndex(base, "/"); idx >= 0 {
			base = base[idx+1:]
		}
		if base == binaryName {
			return writeBinary(tr, dest)
		}
	}
	return fmt.Errorf("binario %q no encontrado en el archivo", binaryName)
}

// latestGHAsset consulta la GitHub API para obtener la URL de descarga del asset.
func latestGHAsset(owner, repo, assetContains string) (string, error) {
	resp, err := http.Get("https://api.github.com/repos/" + owner + "/" + repo + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var rel struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, assetContains) {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("asset %q no encontrado", assetContains)
}
