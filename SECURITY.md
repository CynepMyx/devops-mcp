# Security Policy

## Threat Model

DevOps MCP is designed for **trusted self-hosted environments**. It is not a public-facing service.

**What it protects against:**
- **SSH read-only by default** — only safe, read-only commands are allowed without `confirmed=true` (uptime, df, cat, grep, journalctl, systemctl status, docker ps, etc.)
- **Conditionally safe commands** — `sed`, `curl`, `wget`, `find` allowed only when no mutating flags are present (`sed -i`, `curl -X POST`, `find -exec` require `confirmed=true`)
- **SSH command injection** — blocks `$(...)` and backtick substitution; output redirection always blocked
- **Path traversal in log access** — `log_tail` resolves symlinks and checks against an allowlist
- **Unauthorized Docker container control** — `stop` and `restart` require `confirmed=true`
- **Privilege escalation** — non-root container (mcpuser), all Linux capabilities dropped, read-only rootfs
- **Audit trail** — every tool call logged to `/audit/audit.jsonl`; write failures emit a warning instead of being silently swallowed
- **SSH password auth disabled** — password authentication off by default (ALLOW_SSH_PASSWORD=false)

**What it does NOT protect against:**
- A compromised AI client with access to the MCP endpoint
- Insider threats with physical access to the server
- Docker socket abuse — mounting `/var/run/docker.sock` gives significant host access by design

**Intended deployment:** localhost-only (127.0.0.1:8765), accessed via SSH tunnel from a trusted machine.

## Reporting a Vulnerability

If you find a security issue, please **do not open a public GitHub issue**.

Email: oleg.v.usoltsev@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

You can expect a response within 72 hours.
