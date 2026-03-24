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

- **SSH injection protection** — blocks command substitution, backticks; allows shell operators
- **Danger commands require confirmation** — `rm`, `reboot`, `systemctl stop`, etc. need `confirmed=true`
- **Log path allowlist** — `log_tail` only reads from predefined safe paths
- **Nginx container allowlist** — `nginx_test` only runs against approved container names
- **docker_control requires confirmation** — `stop` and `restart` require `confirmed=true`; AI must ask user before proceeding
- **Container runs as non-root** — `mcpuser` (UID 1000), read-only filesystem, all Linux capabilities dropped
- **SSH key path validation** — only keys from `/app/keys/` are accepted
- **TLS check port allowlist** — `tls_check` only connects to ports: `80, 443, 465, 993, 995, 8080, 8443`
- **Audit log** — every tool call is logged to `/audit/audit.jsonl` with timestamp and args

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

The MCP server starts on `127.0.0.1:8765` (SSE transport).

### 3. Connect to Claude Code

Add to `~/.claude.json` (or your Claude Desktop config):

```json
{
  "mcpServers": {
    "devops": {
      "type": "sse",
      "url": "http://YOUR_SERVER:8765/sse"
    }
  }
}
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
