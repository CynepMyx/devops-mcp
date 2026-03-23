# Security Policy

## Threat Model

DevOps MCP is designed for **trusted self-hosted environments**. It is not a public-facing service.

**What it protects against:**
- SSH command injection (blocks `$(...)`, backticks)
- Path traversal in log access
- Unauthorized Docker container control (confirmation required for destructive actions)
- Privilege escalation (non-root container, all capabilities dropped)
- Audit trail gaps (every call logged to `/audit/audit.jsonl`)

**What it does NOT protect against:**
- A compromised AI client with access to the MCP endpoint
- Insider threats with physical access to the server
- Docker socket abuse — mounting `/var/run/docker.sock` gives significant host access by design

**Intended deployment:** localhost-only (`127.0.0.1:8765`), accessed via SSH tunnel from a trusted machine.

## Reporting a Vulnerability

If you find a security issue, please **do not open a public GitHub issue**.

Email: oleg.v.usoltsev@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

You can expect a response within 72 hours.
