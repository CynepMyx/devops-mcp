# Security Policy

## Threat Model

DevOps MCP is designed for **trusted self-hosted environments**. It is not a public-facing service.

**What `confirmed=true` actually is.** The flag is set by the model itself, in the same
call it is meant to authorize. Nothing stops a model from setting it, and in five months
of real use it was set on 47% of `ssh_exec` calls. So the allowlist is a guard against an
accidental destructive command, not a security boundary. The boundaries that do hold are
the permission prompt in the MCP client and the fact that the endpoint listens on
localhost only. Tool annotations (`readOnlyHint`, `destructiveHint`) exist so the client
can enforce that prompt by protocol instead of by convention.

**What it protects against:**
- **SSH read-only by default** — only safe, read-only commands are allowed without `confirmed=true` (uptime, df, cat, grep, journalctl, systemctl status, docker ps, etc.)
- **Conditionally safe commands** — `sed`, `curl`, `wget`, `find` allowed only when no mutating flags are present (`sed -i`, `curl -X POST`, `find -exec` require `confirmed=true`)
- **SSH command injection** — blocks `$(...)` and backtick substitution; output redirection always blocked
- **Path traversal in log access** — `log_tail` resolves symlinks and checks against an allowlist
- **Unauthorized Docker container control** — `stop` and `restart` require `confirmed=true`
- **Privilege escalation** — non-root container (mcpuser), all Linux capabilities dropped, `no-new-privileges`, source mounted read-only
- **Remote file access** — `file_get` and `file_put` refuse `shadow`, `gshadow`, `sudoers`, `authorized_keys` and private keys outright; `file_put` needs `confirmed=true`, keeps mode and owner, and writes through a temporary file in the same directory
- **Verified writes** — `file_put`'s optional `verify_cmd` restores the previous content when the check fails. Because that command runs automatically as part of a write, it is limited to config tests (`nginx -t` and the like) with no operators, redirects or substitutions; general execution stays in `ssh_exec`, where it appears as its own tool call the user can see and refuse
- **Audit trail** — every tool call logged to `/audit/audit.jsonl` with an outcome of `ok`, `refused` or `error`; write failures emit a warning instead of being silently swallowed. File bodies and other long values are stored as `<N chars, sha256=...>`, so the log proves what was written without becoming a copy of it
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
