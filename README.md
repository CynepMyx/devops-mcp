# DevOps MCP

A self-hosted [Model Context Protocol](https://modelcontextprotocol.io/) server that gives AI assistants (Claude, Cursor, etc.) direct access to your Linux server — Docker containers, SSH execution, system health, logs, Nginx, Prometheus, and more.

Deploy it once on your server. Connect any MCP-compatible client.

> **Intended for trusted self-hosted environments.** Binds to `127.0.0.1` by default. Access to Docker socket and SSH gives the server significant power over your infrastructure — treat it accordingly.

---

## Tools

| Tool | Description |
|------|-------------|
| `server_health` | CPU, memory, disk, uptime, Docker summary, failed systemd units |
| `system_info` | Detailed system info: hostname, platform, load avg, CPU freq |
| `docker_list` | List containers with status, ports, health |
| `docker_logs` | Fetch logs from a container (tail N lines) |
| `docker_inspect` | Full container inspect (config, mounts, network) |
| `docker_stats` | CPU/memory/network stats for running containers |
| `docker_control` | Start, stop, or restart a container |
| `ssh_exec` | Execute commands on remote hosts via SSH key |
| `file_get` | Read a remote file over SFTP — no shell, no quoting problems |
| `file_put` | Write a remote file over SFTP: diff preview, backup, preserved mode, config test with automatic rollback |
| `db_query` | Run SQL against PostgreSQL or MySQL; writes require confirmation |
| `ssh_sessions` | Inspect or close the SSH connections kept open between calls |
| `log_tail` | Read system log files (syslog, nginx, auth, etc.) |
| `nginx_test` | Run nginx -t config validation |
| `systemd_status` | Check status of systemd services |
| `tls_check` | Verify TLS certificate expiry and chain for a domain |
| `prometheus_query` | Run PromQL instant or range queries |
| `prometheus_targets` | List Prometheus scrape targets and their health |
| `search_web` | Web search via SerpAPI |
| `search_ai` | AI-powered technical search via Exa |

---

## Security

Security is built in, not bolted on:

- **SSH commands are read-only by default** — only safe, read-only commands allowed without `confirmed=true` (uptime, df, cat, grep, journalctl, `systemctl status`, `docker ps`, etc.)
- **Conditionally safe commands** — `sed`, `curl`, `wget`, `find` allowed only without mutating flags; `sed -i`, `curl -X POST`, `find -exec` require `confirmed=true`
- **Log path allowlist** — `log_tail` only reads from predefined safe paths
- **Nginx container allowlist** — `nginx_test` only runs against approved container names
- **docker_control requires confirmation** — `stop` and `restart` require `confirmed=true`; AI must ask user before proceeding
- **file_put requires confirmation** — writes need `confirmed=true`; `dry_run=true` returns the unified diff and touches nothing
- **Credential files are refused** — `file_get` and `file_put` will not open `shadow`, `sudoers`, `authorized_keys` or private keys
- **Tool annotations** — every tool declares `readOnlyHint` / `destructiveHint`, so the client can gate destructive calls by protocol rather than by trusting the model to read a description
- **Container runs as non-root** — `mcpuser` (UID 1000), all Linux capabilities dropped, `no-new-privileges`
- **SSH key path validation** — only keys from `/app/keys/` are accepted
- **TLS check port allowlist** — `tls_check` only connects to ports: `80, 443, 465, 993, 995, 8080, 8443`
- **Audit log** — every tool call is logged to `/audit/audit.jsonl` with timestamp, args and outcome (`ok`, `refused`, `error`)

---

## Quick Start

### Prerequisites

- Docker + Docker Compose on the target server
- SSH access to the server

### 1. Clone and configure

```bash
git clone https://github.com/CynepMyx/devops-mcp.git
cd devops-mcp
cp .env.example .env
```

Edit `.env`:

```dotenv
SERPAPI_KEY=your_serpapi_key       # optional, for search_web
EXA_API_KEY=your_exa_key           # optional, for search_ai
DOCKER_GID=999                     # match your server's docker group GID
PROTECTED_CONTAINERS=devops-mcp   # comma-separated, cannot be stopped/restarted
```

### 2. Deploy

```bash
docker compose up -d
```

The MCP server starts on `127.0.0.1:8765`, serving streamable HTTP on `/mcp` and
legacy SSE on `/sse`.

### 3. Connect to Claude Code

Add to `~/.claude.json` (or your Claude Desktop config):

```json
{
  "mcpServers": {
    "devops": {
      "type": "http",
      "url": "http://YOUR_SERVER:8765/mcp"
    }
  }
}
```

`/mcp` runs stateless: every request carries what it needs, so restarting the
container does not leave the client holding a dead session and answering
`-32602` to every call. The older SSE transport is still mounted:

```json
{ "type": "sse", "url": "http://YOUR_SERVER:8765/sse" }
```

For remote servers, use an SSH tunnel:

```bash
ssh -L 8765:127.0.0.1:8765 user@your-server
```

Then use `http://localhost:8765/sse`.

---

## SSH Key Setup

Place your private key in the `keys/` directory:

```bash
cp ~/.ssh/id_ed25519 keys/my-server.pem
chmod 600 keys/my-server.pem
```

Then use in `ssh_exec`:

```
ssh_exec(host="10.0.0.5", user="deploy", key="/app/keys/my-server.pem", command="uptime")
```

---

## SSH Host Key Verification

By default,  connects with **warn mode**: unknown hosts are allowed but a warning appears in the response. This is convenient but not strict.

To enable **strict mode**, populate :

```bash
# On your host machine, scan the target server and append to known_hosts
ssh-keyscan -H 10.0.0.5 >> /opt/devops-mcp/ssh/known_hosts
```

Then pass  in . Hosts not in  will be rejected.

> The  file is mounted read-only into the container and gitignored — it never ends up in source control.

---

## Connections Stay Open

`ssh_exec`, `file_get` and `file_put` share one live SSH connection per host and
credential instead of authenticating on every call. Measured against a real host, the
first call takes 220 ms and the ones after it 50 ms, and a twenty step diagnostic opens
one connection instead of twenty. That second part matters as much as the speed: a burst
of connections from one address is exactly what fail2ban is built to notice.

The pool covers connections this server opens itself. If you reach a host through a
second hop that the container does not control — an `ssh` or `sshpass` call inside the
command, say — that hop is still a fresh connection every time, and the target sees the
same burst it always did.

Commands still run as separate channels, so nothing carries over between them: no working
directory, no environment, no shell state. That is on purpose. A persistent *shell* would
let two separately validated calls add up to one command that neither of them was.

Connections close themselves after five minutes idle, and `ssh_sessions` shows what is
open or closes it now:

```
ssh_sessions(action="status")
ssh_sessions(action="close", host="10.0.0.5")
```

Credentials never share a connection: the pool key includes host, port, username and
which key or password was used, and a password is stored only as a hash. Set
`SSH_POOL=false` to go back to connecting every time.

---

## Editing Remote Files

`ssh_exec` runs everything through a shell, so writing a config with it means fighting
quoting rules and a 500 character ceiling. `file_get` / `file_put` use SFTP instead —
the bytes travel as bytes.

```
file_put(host="10.0.0.5", user="deploy", key="/app/keys/my-server.pem",
         path="/etc/nginx/conf.d/site.conf", content="...", dry_run=true)
```

The dry run returns a unified diff and writes nothing. Repeat with `confirmed=true` to
apply it: the previous version is saved as `site.conf.bak_<timestamp>`, mode and owner
are carried over, and the new content lands via a temporary file in the same directory,
so a reader never sees a half-written config. A file that does not exist yet needs an
explicit `mode`, because guessing `0644` on a config is how secrets end up world-readable.

### Check it, and put the old one back if it fails

A broken config is harmless right up until something reloads it. Pass `verify_cmd` and
the check runs against what was just written:

```
file_put(host="10.0.0.5", user="deploy", key="/app/keys/my-server.pem",
         path="/etc/nginx/conf.d/site.conf", content="...",
         verify_cmd="nginx -t", confirmed=true)
```

If the test exits non-zero, the previous content is restored, the same test is run again
to prove the server is back where it started, and the now-pointless backup is removed.
The response carries `verify`, `rolled_back` and `verify_after_rollback`, so the failure
is visible rather than inferred. Set `rollback_on_failure=false` to keep the new content
anyway.

`verify_cmd` accepts config tests only (`nginx -t`, `apachectl configtest`, `sshd -t`,
`php -l`, `named-checkconf`, `haproxy -c`, `systemd-analyze verify`, `docker compose
config`, and similar). It runs automatically as part of a write, so it has to be a test
and not a general shell; anything else belongs in `ssh_exec`, where it shows up as its
own call.

---

## Example Prompts

Once connected, you can ask your AI assistant things like:

- *"Check server health and show me any failed services"*
- *"Restart the nginx container and verify config is valid"*
- *"Show last 50 lines from the nginx access log"*
- *"Is the TLS cert for example.com still valid?"*
- *"Run a Prometheus query for 5-minute CPU usage"*
- *"SSH into 10.0.0.5 as deploy and check disk usage"*

---

## Architecture

```
Claude / Cursor / any MCP client
        |  SSE (HTTP)
        v
  FastAPI + MCP Server  <---- security.py (validation layer)
        |
  +-----+------+----------+-----------+----------+
  |            |          |           |          |
Docker SDK  Paramiko  psutil/dbus  httpx      Prometheus
(local)     (SSH)     (system)    (HTTP)       API
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_HOST` | `0.0.0.0` | Bind address inside container |
| `MCP_PORT` | `8765` | Port |
| `AUDIT_LOG_PATH` | `/audit/audit.jsonl` | Audit log location |
| `PROTECTED_CONTAINERS` | `devops-mcp` | Containers immune to start/stop/restart |
| `SERPAPI_KEY` | — | SerpAPI key for `search_web` |
| `EXA_API_KEY` | — | Exa key for `search_ai` |
| `PROMETHEUS_URL` | `http://host.docker.internal:9090` | Prometheus endpoint |
| `ALLOW_SSH_PASSWORD` | `false` | Enable SSH password auth (key-based is default) |
| `SSH_POOL` | `true` | Keep SSH connections open between calls; `false` reconnects every time |
| `SSH_POOL_IDLE_TTL` | `300` | Close a pooled connection after this many idle seconds |
| `SSH_POOL_MAX` | `20` | Maximum pooled connections before the least recently used one is dropped |
| `SSH_POOL_KEEPALIVE` | `30` | Keepalive interval, so an idle connection is not dropped silently |
| `DEV_HOT_RELOAD` | `false` | Enable live tool file-watching (dev only) |

---

## Security & Threat Model

DevOps MCP is designed for **trusted self-hosted environments**. Read [SECURITY.md](SECURITY.md) for the full threat model.

**Key constraints:**
- Binds to `127.0.0.1` by default — not exposed to the internet
- Docker socket access is intentional and powerful — treat the endpoint accordingly
- SSH keys are validated against a path allowlist (`/app/keys/`)
- Destructive actions (`stop`, `restart`, dangerous shell commands) require explicit `confirmed=true`
- Every tool call is appended to `/audit/audit.jsonl`

---

## License

MIT
