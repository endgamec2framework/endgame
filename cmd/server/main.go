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
	// Subcommand: new-operator (local on the VPS only)
	if len(os.Args) >= 2 && os.Args[1] == "new-operator" {
		cmdNewOperator(os.Args[2:])
		return
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
C2 server

USAGE:
  c2-server [options]            Start the server
  c2-server new-operator [opts]  Generate operator profile (local on VPS)
  c2-server -gencerts-only       Generate TLS certs and exit

SERVER OPTIONS:
  -http-port     int    HTTP listener port for agents      (default 8080)
  -https-port    int    HTTPS listener port without mTLS   (default 8444)
  -mtls-port     int    mTLS listener port for agents      (default 8443)
  -tcp-port      int    TCP listener port for C agents     (default 4444; 0 disables)
  -operator-port int    Operator API port (loopback)       (default 31337)
  -db            string SQLite database                    (default data/c2.db)
  -certs         string TLS certificates directory         (default certs/)
	-data          string Uploads/downloads directory        (default data/)
	-plugins       string Modules directory                  (default data/plugins/)
  -gencerts-only        Generate certs and exit

  The web interface is launched from the client: c2-client -gui-port 8888

SUBCOMMAND new-operator:
  c2-server new-operator -name <name> [-port 31337] [-certs certs/] [-via-ws <url>] [-export <path>]

  -name    string  Operator name (required)
  -port    int     Server operator port (default 31337)
  -certs   string  Certs directory      (default certs/)
  -via-ws  string  WS tunnel URL (wss://...)    omit if using SSH tunnel
  -export  string  Export an additional copy to this path (optional)

  The profile is always saved to ~/.endgame/profiles/<name>.json

EXAMPLES:
  # Start server with defaults (looks for certs/ and data/ next to the binary or parent directory)
  c2-server -http-port 8080 -https-port 8444 -mtls-port 8443 -operator-port 31337 -db data/c2.db -certs certs -data data

  # Profile with SSH tunnel (operator uses ssh -L)
  c2-server new-operator -name alice
  c2-server new-operator -name bob -export /tmp/bob.json   # extra copy to send

  # Profile with Cloudflare Tunnel (no SSH, from any network)
  #   1. Open WS bridge:  listener start wstunnel 40000
  #   2. Expose:          cloudflared tunnel --url http://127.0.0.1:40000
  #   3. Generate profile with the public URL:
  c2-server new-operator -name carol -via-ws wss://xxx.trycloudflare.com/ws

`)
	}

	httpPort := flag.Int("http-port", 8080, "HTTP listener port (agents)")
	httpsPort := flag.Int("https-port", 443, "HTTPS listener port without mTLS (C/Rust agents)")
	mtlsPort := flag.Int("mtls-port", 8443, "mTLS listener port (agents)")
	tcpPort := flag.Int("tcp-port", 4444, "TCP listener port (C agents; 0 to disable)")
	operatorPort := flag.Int("operator-port", 31337, "Operator API port (loopback only)")
	// When the binary lives inside a "bin/" directory, use the parent as project root.
	base := exeDir()
	if filepath.Base(base) == "bin" {
		base = filepath.Dir(base)
	}
	dbPath := flag.String("db", filepath.Join(base, "data", "c2.db"), "SQLite database path")
	certsDir := flag.String("certs", filepath.Join(base, "certs"), "TLS certificates directory")
	dataDir := flag.String("data", filepath.Join(base, "data"), "Uploads/downloads directory")
	pluginsDir := flag.String("plugins", "", "Modules directory (default: <data>/plugins)")
	genCertsOnly := flag.Bool("gencerts-only", false, "Generate certs and exit")
	flag.Parse()
	if *pluginsDir == "" {
		*pluginsDir = filepath.Join(*dataDir, "plugins")
	}

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	if *genCertsOnly {
		os.MkdirAll(*certsDir, 0700)
		ca, err := server.EnsureCA(*certsDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error generating certs:", err)
			os.Exit(1)
		}
		ca.SignServerCert(*certsDir, nil)
		fmt.Printf("[+] certs written to %s/\n", *certsDir)
		return
	}

	cfg := server.Config{
		HTTPPort:     *httpPort,
		HTTPSPort:    *httpsPort,
		MTLSPort:     *mtlsPort,
		TCPPort:      *tcpPort,
		OperatorPort: *operatorPort,
		DBPath:       *dbPath,
		CertsDir:     *certsDir,
		DataDir:      *dataDir,
		PluginsDir:   *pluginsDir,
	}

	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error starting server:", err)
		os.Exit(1)
	}

	// Generate admin profile on first run
	if err := ensureAdminProfile(srv, *operatorPort); err != nil {
		fmt.Fprintln(os.Stderr, "warning generating admin profile:", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[*] shutting down server...")
		cancel()
	}()

	go func() {
		if err := srv.Start(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "server error:", err)
			cancel()
		}
	}()

	if err := srv.StartOperatorListener(*operatorPort); err != nil {
		fmt.Fprintln(os.Stderr, "error starting operator API:", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Operator API on 127.0.0.1:%d (loopback only)\n", *operatorPort)
	fmt.Printf("[*] Operators must use SSH tunnel:\n")
	fmt.Printf("    ssh -L %d:127.0.0.1:%d user@<vps>\n\n", *operatorPort, *operatorPort)

	<-ctx.Done()
}

// cmdNewOperator generates an operator profile locally on the VPS.
// Usage: c2-server new-operator -name alice [-port 31337] [-certs certs/] [-via-ws <url>]
func cmdNewOperator(args []string) {
	fs := flag.NewFlagSet("new-operator", flag.ExitOnError)
	name := fs.String("name", "", "Operator name (required)")
	exportPath := fs.String("export", "", "Export an additional copy to this path (optional)")
	operatorPort := fs.Int("port", 31337, "Server operator port")
	certsDir := fs.String("certs", "certs", "Server certs directory")
	viaWS := fs.String("via-ws", "", "WebSocket tunnel URL (e.g. wss://xxx.trycloudflare.com/ws)")
	fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: c2-server new-operator -name <name> [-port 31337] [-certs certs/] [-via-ws <url>]")
		os.Exit(1)
	}

	ca, err := server.LoadCA(*certsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading CA:", err)
		fmt.Fprintln(os.Stderr, "Has the server been started at least once to generate certs/ca.crt?")
		os.Exit(1)
	}

	certPEM, keyPEM, err := ca.SignAgentCert("operator-" + *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error signing cert:", err)
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
		fmt.Fprintln(os.Stderr, "error saving profile:", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Profile saved: %s\n", savedPath)

	if *exportPath != "" {
		if err := profile.Export(p, *exportPath); err != nil {
			fmt.Fprintln(os.Stderr, "error exporting profile:", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Copy exported: %s\n", *exportPath)
	}

	fmt.Println()
	if *viaWS != "" {
		fmt.Printf("WS tunnel mode (%s):\n", *viaWS)
		fmt.Printf("  c2-client -name %s\n\n", *name)
	} else {
		fmt.Printf("SSH tunnel mode:\n")
		fmt.Printf("  ssh -L %d:127.0.0.1:%d user@<vps>\n", *operatorPort, *operatorPort)
		fmt.Printf("  c2-client -name %s\n\n", *name)
	}
}

func ensureAdminProfile(srv *server.Server, operatorPort int) error {
	profileDir := profile.DefaultDir()
	adminPath := profileDir + "/admin.json"
	// The admin profile is generated by the installer before the server has
	// ever handled an operator request. Persist its role at startup so the
	// role middleware does not fall back to the default operator role.
	if err := srv.GetDB().SetOperatorRole("operator-admin", server.RoleAdmin); err != nil {
		return fmt.Errorf("register admin role: %w", err)
	}
	if _, err := os.Stat(adminPath); err == nil {
		return nil // already exists
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

	fmt.Printf("[+] Admin profile generated: %s\n", exportPath)
	fmt.Printf("    Connect via SSH tunnel:\n")
	fmt.Printf("    ssh -L %d:127.0.0.1:%d user@<vps>\n", operatorPort, operatorPort)
	fmt.Printf("    c2-client -profile admin.json\n\n")
	return nil
}
