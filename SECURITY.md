# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Yes    |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in ENDGAME C2 itself (not in a target system), please report it responsibly:

1. **Email**: send details to the maintainers privately before any public disclosure
2. **Include**: description of the vulnerability, steps to reproduce, potential impact, and any suggested fix
3. **Response time**: we aim to acknowledge reports within 48 hours and provide a fix within 14 days for critical issues
4. **Disclosure**: we follow coordinated disclosure — please allow us time to patch before publishing

## Scope

Vulnerabilities in scope for this policy:

- Authentication bypass in the operator API or GUI
- Path traversal or arbitrary file read/write in the server
- Remote code execution on the C2 server itself
- Privilege escalation within the operator role system
- Cryptographic weaknesses in the mTLS or agent communication layer

Out of scope:

- Detection by EDR/AV vendors (this is expected and intentional)
- Agent behavior on target systems (offensive capabilities are by design)
- Issues requiring physical access to the C2 host
- Social engineering

## Credit

Researchers who responsibly disclose valid vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).
