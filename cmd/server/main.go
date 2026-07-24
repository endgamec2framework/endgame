package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"redteam/profile"
	"redteam/server"
)

// exeDir returns the directory containing the running binary.
func exeDir() string {
	exe, err := exec.LookPath(os.Args[0])
	if err != nil {
		exe = os.Args[0]
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return "."
	}
	return filepath.Dir(abs)
}

func main() {
	// Subcomando: new-operator (solo local en el VPS)
	if len(os.Args) >= 2 && os.Args[1] == "new-operator" {
		cmdNewOperator(os.Args[2:])
		return
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
C2 server

USO:
  c2-server [opciones]           Arrancar el servidor
  c2-server new-operator [opts]  Generar perfil de operador (local en VPS)
  c2-server -gencerts-only       Generar certs TLS y salir

OPCIONES DEL SERVIDOR:
  -http-port     int    Puerto listener HTTP para agentes      (default 8080)
  -https-port    int    Puerto listener HTTPS sin mTLS         (default 8444)
  -mtls-port     int    Puerto listener mTLS para agentes      (default 8443)
  -operator-port int    Puerto API de operadores (loopback)    (default 31337)
  -db            string Base de datos SQLite                   (default data/c2.db)
  -certs         string Directorio de certificados TLS         (default certs/)
  -data          string Directorio de uploads/downloads        (default data/)
  -gencerts-only        Generar certs y salir

  La interfaz web se arranca desde el cliente: c2-client -gui-port 8888

SUBCOMANDO new-operator:
  c2-server new-operator -name <nombre> [-port 31337] [-certs certs/] [-via-ws <url>] [-export <ruta>]

  -name    string  Nombre del operador (obligatorio)
  -port    int     Puerto operator del servidor (default 31337)
  -certs   string  Directorio de certs          (default certs/)
  -via-ws  string  URL WS tunnel (wss://...)    omitir si usa SSH tunnel
  -export  string  Exportar copia adicional a esta ruta (opcional)

  El perfil se guarda siempre en ~/.endgame/profiles/<nombre>.json

EJEMPLOS:
  # Arrancar servidor con defaults (busca certs/ y data/ junto al binario o en el directorio padre)
  c2-server -http-port 8080 -https-port 8444 -mtls-port 8443 -operator-port 31337 -db data/c2.db -certs certs -data data

  # Perfil con SSH tunnel (el operador usa ssh -L)
  c2-server new-operator -name alice
  c2-server new-operator -name bob -export /tmp/bob.json   # copia extra para enviar

  # Perfil con Cloudflare Tunnel (sin SSH, desde cualquier red)
  #   1. Abrir WS bridge:  listener start wstunnel 40000
  #   2. Exponer:          cloudflared tunnel --url http://127.0.0.1:40000
  #   3. Generar perfil con la URL pública:
  c2-server new-operator -name carol -via-ws wss://xxx.trycloudflare.com/ws

`)
	}

	httpPort     := flag.Int("http-port",     8080,  "Puerto listener HTTP (agentes)")
	httpsPort    := flag.Int("https-port",    8444,  "Puerto listener HTTPS sin mTLS (agentes C/Rust)")
	mtlsPort     := flag.Int("mtls-port",     8443,  "Puerto listener mTLS (agentes)")
	operatorPort := flag.Int("operator-port", 31337, "Puerto API de operadores (solo loopback)")
	// When the binary lives inside a "bin/" directory, use the parent as project root.
	base := exeDir()
	if filepath.Base(base) == "bin" {
		base = filepath.Dir(base)
	}
	dbPath       := flag.String("db",    filepath.Join(base, "data", "c2.db"), "Base de datos SQLite")
	certsDir     := flag.String("certs", filepath.Join(base, "certs"),         "Directorio de certificados TLS")
	dataDir      := flag.String("data",  filepath.Join(base, "data"),          "Directorio de uploads/downloads")
	genCertsOnly := flag.Bool("gencerts-only", false,  "Generar certs y salir")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	if *genCertsOnly {
		os.MkdirAll(*certsDir, 0700)
		ca, err := server.EnsureCA(*certsDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error generando certs:", err)
			os.Exit(1)
		}
		ca.SignServerCert(*certsDir, nil)
		fmt.Printf("[+] certs escritos en %s/\n", *certsDir)
		return
	}

	cfg := server.Config{
		HTTPPort:     *httpPort,
		HTTPSPort:    *httpsPort,
		MTLSPort:     *mtlsPort,
		OperatorPort: *operatorPort,
		DBPath:       *dbPath,
		CertsDir:     *certsDir,
		DataDir:      *dataDir,
	}

	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error iniciando servidor:", err)
		os.Exit(1)
	}

	// Generar perfil admin la primera vez
	if err := ensureAdminProfile(srv, *operatorPort); err != nil {
		fmt.Fprintln(os.Stderr, "advertencia al generar perfil admin:", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[*] apagando servidor...")
		cancel()
	}()

	go func() {
		if err := srv.Start(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "error servidor:", err)
			cancel()
		}
	}()

	if err := srv.StartOperatorListener(*operatorPort); err != nil {
		fmt.Fprintln(os.Stderr, "error arrancando operator API:", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Operator API en 127.0.0.1:%d (solo loopback)\n", *operatorPort)
	fmt.Printf("[*] Los operadores deben usar túnel SSH:\n")
	fmt.Printf("    ssh -L %d:127.0.0.1:%d user@<vps>\n\n", *operatorPort, *operatorPort)

	<-ctx.Done()
}

// cmdNewOperator genera un perfil de operador localmente en el VPS.
// Uso: c2-server new-operator -name alice [-port 31337] [-certs certs/] [-via-ws <url>]
func cmdNewOperator(args []string) {
	fs := flag.NewFlagSet("new-operator", flag.ExitOnError)
	name         := fs.String("name",   "",      "Nombre del operador (obligatorio)")
	exportPath   := fs.String("export", "",      "Exportar copia adicional a esta ruta (opcional)")
	operatorPort := fs.Int("port",      31337,   "Puerto operator del servidor")
	certsDir     := fs.String("certs",  "certs", "Directorio de certs del servidor")
	viaWS        := fs.String("via-ws", "",      "URL WebSocket tunnel (ej: wss://xxx.trycloudflare.com/ws)")
	fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "uso: c2-server new-operator -name <nombre> [-port 31337] [-certs certs/] [-via-ws <url>]")
		os.Exit(1)
	}

	ca, err := server.LoadCA(*certsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error cargando CA:", err)
		fmt.Fprintln(os.Stderr, "¿Está arrancado el servidor al menos una vez para generar certs/ca.crt?")
		os.Exit(1)
	}

	certPEM, keyPEM, err := ca.SignAgentCert("operator-" + *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error firmando cert:", err)
		os.Exit(1)
	}

	p := &profile.Profile{
		Name:          *name,
		Server:        fmt.Sprintf("127.0.0.1:%d", *operatorPort),
		CACertPEM:     string(ca.CACertPEM),
		ClientCertPEM: string(certPEM),
		ClientKeyPEM:  string(keyPEM),
		ViaWS:         *viaWS,
	}

	profileDir := profile.DefaultDir()
	savedPath, err := profile.Save(p, profileDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error guardando perfil:", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Perfil guardado: %s\n", savedPath)

	if *exportPath != "" {
		if err := profile.Export(p, *exportPath); err != nil {
			fmt.Fprintln(os.Stderr, "error exportando perfil:", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Copia exportada: %s\n", *exportPath)
	}

	fmt.Println()
	if *viaWS != "" {
		fmt.Printf("Modo WS tunnel (%s):\n", *viaWS)
		fmt.Printf("  c2-client -name %s\n\n", *name)
	} else {
		fmt.Printf("Modo SSH tunnel:\n")
		fmt.Printf("  ssh -L %d:127.0.0.1:%d user@<vps>\n", *operatorPort, *operatorPort)
		fmt.Printf("  c2-client -name %s\n\n", *name)
	}
}

func ensureAdminProfile(srv *server.Server, operatorPort int) error {
	profileDir := profile.DefaultDir()
	adminPath  := profileDir + "/admin.json"
	if _, err := os.Stat(adminPath); err == nil {
		return nil // ya existe
	}

	certPEM, keyPEM, err := srv.GetCA().SignAgentCert("operator-admin")
	if err != nil {
		return err
	}

	p := &profile.Profile{
		Name:          "admin",
		Server:        fmt.Sprintf("127.0.0.1:%d", operatorPort),
		CACertPEM:     string(srv.GetCA().CACertPEM),
		ClientCertPEM: string(certPEM),
		ClientKeyPEM:  string(keyPEM),
	}

	profile.Save(p, profileDir)

	exportPath := "admin.json"
	profile.Export(p, exportPath)

	fmt.Printf("[+] Perfil admin generado: %s\n", exportPath)
	fmt.Printf("    Conéctate con túnel SSH:\n")
	fmt.Printf("    ssh -L %d:127.0.0.1:%d user@<vps>\n", operatorPort, operatorPort)
	fmt.Printf("    c2-client -profile admin.json\n\n")
	return nil
}
