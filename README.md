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

ENDGAME runs on Kali Linux, Ubuntu 22.04+ and Debian 11+. You will need Go 1.21+, Nim 2.0+, and MinGW for cross-compilation.

```bash
git clone https://github.com/endgamec2framework/endgame
cd endgame
./install.sh
make all
```

---

### Features

#### Server

> Written in Go — single binary, no external dependencies

- Multi-operator teamserver with real-time event sync
- SQLite-backed operation log (agents, tasks, results, loot)
- Payload builder with polymorphic encoder and Garble obfuscation
- Malleable HTTP profiles (Amazon, custom JSON)
- Stager delivery with one-liner generation
- Built-in report generator (HTML/PDF)
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

- **Transports**: HTTP · mTLS · DNS · SMB named pipe (`\\.\pipe\svcctl`) · TCP
- **Evasion**: ETW blind patch · AMSI bypass via hardware breakpoint (VEH DR0) · NTDLL unhook · Ekko sleep mask · PPID spoof · PEB command-line spoof · Header wipe
- **Injection**: VirtualAllocEx+CreateRemoteThread · Early-bird APC · Thread hijack · Fork-and-run · Evasive inject
- **Post-exploitation**: Screenshot · Keylogger · Clipboard · LSASS minidump · Token impersonation · UAC bypass · Persistence (Run key / Scheduled task) · Self-delete
- **Lateral movement**: WinRM · SMB exec · Port forward · SOCKS5 · Reverse SOCKS · HTTP pivot
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
