# Contributing to ENDGAME C2 FRAMEWORK

Thank you for your interest in contributing. Please read this guide before opening issues or pull requests.

## Before You Start

- Read the [Ethical Use Policy](ETHICS.md) — contributions must align with the project's legitimate security research purpose
- Check existing [Issues](https://github.com/endgamec2framework/endgame/issues) and [Pull Requests](https://github.com/endgamec2framework/endgame/pulls) to avoid duplicates

## Reporting Bugs

Use the bug report issue template. Include:

- ENDGAME version / commit hash
- Operating system and Go version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (sanitize any sensitive data)

For **security vulnerabilities**, see [SECURITY.md](SECURITY.md) — do not open a public issue.

## Feature Requests

Open an issue with the `enhancement` label. Describe:

- The use case and why it matters for red team operations
- Any existing workarounds
- Rough implementation idea (optional)

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Follow existing Go code style (`gofmt`, no unused imports)
3. Keep PRs focused — one feature or fix per PR
4. Add a clear description of what changed and why
5. Ensure `go build ./...` passes before submitting

## Code Guidelines

- **Go**: standard library preferred over third-party where possible; keep imports grouped (stdlib / external / internal)
- **Agents**: changes to agent code must be tested on Windows 10/11 x64
- **Crypto**: do not introduce new cryptographic primitives — use the existing AES-GCM and mTLS layer
- **No hardcoded secrets**: tokens, keys, and certificates are always runtime-generated

## Community Modules

ENDGAME supports reviewed community modules as external processes. A module
must live in its own directory under `data/plugins/<module-id>/`, include a
strict `plugin.json` manifest, and implement the JSON-over-stdio protocol
described in [`plugins/README.md`](plugins/README.md).

The first module API is intentionally limited to a bounded snapshot of
read-oriented data and graph access plus normalized report output. Modules do
not receive direct database handles, agent keys, transport sockets, inherited
C2 secrets, or arbitrary agent-tasking access. They are still native
processes, so keep modules independently licensed, review their source, pin
the reviewed version, and install them with restrictive filesystem
permissions.

Before proposing a new permission or a module that can affect agents, open an
issue describing the threat model and the required operator confirmation.

## What We Won't Accept

- Features designed exclusively for criminal use
- Code that removes existing safety checks or ethical guardrails
- Dependencies with restrictive licenses incompatible with MIT
