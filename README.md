<div align="center">
  <img width="320px" src="assets/endgame.png" />
  <h1>ENDGAME C2 FRAMEWORK</h1>
  <br/>

  <p><i>ENDGAME is a professional command and control framework built for authorized red team engagements, penetration testing, and educational security research. Designed to simulate realistic adversary techniques, assess detection coverage, and help security teams understand their defensive gaps — with built-in AI to accelerate campaign analysis and operator decision-making. Ideal for lab environments, security training, and hands-on learning.</i></p>

  <p>
    <a href="https://endgamec2framework.com"><b>🌐 endgamec2framework.com</b></a>
    &nbsp;·&nbsp;
    <a href="https://endgamec2framework.github.io/endgame/"><b>📄 Documentation</b></a>
  </p>
  <br/>

  <img src="assets/screenshots/kill_chain_graph.png" width="90%" /><br /><br />
  <img src="assets/screenshots/operator_console.png" width="90%" /><br />

</div>

---

### Quick Start

> See [INSTALL.md](INSTALL.md) for full installation instructions.

ENDGAME runs on Kali Linux, Ubuntu 22.04+ and Debian 11+. You will need Go 1.21+ and MinGW for cross-compilation.

```bash
git clone https://github.com/endgamec2framework/endgame
cd endgame
./install.sh
```

To update to the latest version, simply re-run the installer — it will `git pull`, rebuild binaries, and preserve existing certificates and operator profiles:

```bash
./install.sh
```

---

### Features

#### Server

> Written in Go — single binary, no external dependencies

- Multi-operator teamserver with real-time event sync
- SQLite-backed operation log (agents, tasks, results, loot)
- Payload builder with polymorphic encoder and Garble obfuscation
- Malleable HTTP profiles (Amazon, custom JSON)
- DNS-over-HTTPS (DoH) transport endpoint (RFC 8484)
- Stager delivery with one-liner generation
- Built-in report generator (HTML · JSON · CSV · ATT&CK Navigator layer)
- mTLS operator API on :31337

#### Client / GUI

> Cross-platform web GUI served locally, accessible from any browser

- Kill-chain graph view with real-time agent topology
- Agent table with live beacon status
- Per-agent operator console with full command history
- Internal pentest suite: credential verification, lateral movement, SMB exec
- Loot manager (credentials, files, screenshots, keylog)
- AI-assisted command suggestions and campaign summarization
- Multi-operator support with shared session state

#### Agent (Go)

> Windows and Linux — cross-compiled with MinGW / native GCC

- **Transports**: HTTP · mTLS · DNS · DNS-over-HTTPS (DoH) · SMB named pipe (`\\.\pipe\svcctl`) · TCP
- **Evasion**: ETW blind patch · AMSI bypass via hardware breakpoint (VEH DR0) · NTDLL unhook · Ekko sleep mask · PPID spoof · PEB command-line spoof · Header wipe · BLOCKDLLS (ProcessBinarySignaturePolicy — blocks unsigned DLLs)
- **Injection**: VirtualAllocEx+CreateRemoteThread · Early-bird APC · Thread hijack · Fork-and-run · Evasive inject · Process hollowing · UDRL / Phantom DLL Loading (NtCreateSection SEC_IMAGE — shellcode runs from module-backed memory, defeats anonymous-region EDR heuristics)
- **Post-exploitation**: Screenshot · Keylogger · Clipboard monitor · LSASS minidump · Token impersonation · UAC bypass · Persistence (Run key / Scheduled task / COM hijacking / LNK dropper) · Self-delete
- **Lateral movement**: `psexec` · `smbexec` (SCM → cmd.exe chain) · `atexec` (MS-TSCH scheduled task, runs as SYSTEM) · `wmi` · `dcom` · `winrm` · `ssh` · Port forward · SOCKS5 · Reverse SOCKS · HTTP pivot
- **EDR silence**: WFP rule injection · Event log wipe
- In-process BOF execution (Beacon Object Files)
- Sandbox detection (30+ EDR/AV process checks, timing, artifact checks)

#### Agent (Nim)

> Windows — lightweight alternative agent

- HTTP transport with AES-256-CBC encrypted tasking
- AMSI/ETW bypass
- Process injection and shellcode execution
- Token manipulation

#### Loaders

- **C loader** — reflective shellcode runner, no CRT dependency
- **Go loader** — cross-platform, supports DLL and EXE staging  
- **Nim loader** — syscall-based injection, minimal footprint
- **Shellcode loader** — raw x64 NASM stub for manual mapping

#### Reports & MITRE ATT&CK

> Built into the web GUI and the CLI client

- **4-tab report panel**: Overview (stats + key findings) · Timeline (filterable event log) · MITRE ATT&CK matrix · Export
- **Export formats**: self-contained HTML report · JSON dump · CSV timeline · ATT&CK Navigator layer (`.json`, v4.5)
- **ATT&CK Navigator integration**: export a layer from the GUI and open it directly in `mitre-attack.github.io/attack-navigator` — technique scores normalised 0–100 by observation count
- **Technique coverage**: 50+ operator commands mapped to ATT&CK techniques across all 12 tactics (Recon → C2 → Impact)
- **Key findings**: auto-generated severity list (LSASS dump, token theft, persistence, lateral movement, credential capture…)
- **AI executive summary**: optional `report --ai` mode calls a local Ollama LLM to generate a narrative summary
- **Operator activity log**: every local command appended to `activity.jsonl` and merged into the final report

#### Extensibility

- BOF (Beacon Object File) support — drop `.o` files into `bofs/` and execute in-agent
- Custom malleable C2 profiles via JSON
- REST API for external operator tooling
- AI module (pluggable LLM backend for command generation and analysis)

---

### Screenshots

<div align="center">
  <img src="assets/screenshots/agent_table.png" width="90%" /><br /><br />
</div>

---

### Legal Notice

> **This tool is for authorized security testing, educational use, and lab environments only.**
> Use against systems without explicit written authorization is illegal and strictly prohibited.
> By using this software you agree to the [Ethical Use Policy](ETHICS.md).

---

### Note

Please do not open issues regarding EDR/AV detection.

Default builds include known IOCs published in the [IOC documentation](https://endgamec2framework.github.io/endgame/#ioc). Operators conducting authorized engagements are expected to recompile agents with custom certificates, build flags, and malleable profiles. See [ETHICS.md](ETHICS.md) for the full responsible use policy.
