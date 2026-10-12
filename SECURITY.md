# Security Policy

## Threat Model

DevOps MCP is a **personal tool for one engineer** in a trusted self-hosted environment. It is not a
public-facing service and not a shared one: there is no user model, and every decision below is
measured against that. The 12.10.2026 audit (CHANGELOG 0.6.0) is written up with this model in mind.

**What `confirmed=true` actually is.** The flag is set by the model itself, in the same
call it is meant to authorize. Nothing stops a model from setting it, and in five months
of real use it was set on 47% of `ssh_exec` calls. So the allowlist is a guard against an
accidental destructive command, not a security boundary. The boundaries that do hold are
the permission prompt in the MCP client and the fact that the endpoint listens on
localhost only. Tool annotations (`readOnlyHint`, `destructiveHint`) exist so the client
can enforce that prompt by protocol instead of by convention.

**What it protects against:**
- **SSH read-only by default** — only safe, read-only commands are allowed without `confirmed=true` (uptime, df, cat, grep, journalctl, systemctl status, docker ps, etc.)
- **Flags are parsed, not searched** — for commands whose flags decide between a read and a write (`sed`, `curl`, `git`, `ip`, `journalctl`, `dpkg`, `find`, `date`, `sort`, `ss` and others) the words are parsed per command in `command_args.py`: glued short options (`-ni`), GNU abbreviations (`--rot`), tabs, sed scripts with `e`/`w`, `git -c`, `ls-remote --upload-pack` and `ext::` all count. Anything the parser does not understand asks for confirmation. `wget` always asks: it writes a file by default. `command` passes only as `command -v`
- **Hard denials** — `find` without `-maxdepth`, `pkill -f` / `pgrep -f` without a `[b]racket` pattern, and `rm -r` on `/` or a top-level directory are refused even with `confirmed=true`; each entry comes from a real incident (see CHANGELOG 0.5.3). The check looks for the word anywhere outside quotes, sees through wrappers (`sudo`, `nice -n`, `timeout`, `xargs`, `/usr/bin/find`), `--long` abbreviations, backslashes, split quotes and quoted payloads given to `sh -c`, `eval`, `su -c`, `ssh`. It is not a shell parser: a variable that expands to the word or base64 piped into a shell is left to the allowlist and `confirmed=true`.
- **SSH command injection** — blocks `$(...)` and backtick substitution; output redirection always blocked
- **Bounded output** — `ssh_exec` reads at most 1 MiB of output; past that the channel is closed and the reply says it was cut. A single `cat` of a big log used to be read whole and the 256M container was OOM-killed
- **DNS rebinding** — `/mcp` and SSE accept only requests addressed to `127.0.0.1` or `localhost` (any port) and no foreign `Origin` (MCP SDK `TransportSecuritySettings`; `MCP_ALLOWED_HOSTS` overrides). A web page that points its own domain at 127.0.0.1 can no longer reach the tunnel from a browser. Cross-site requests without rebinding were already refused (`Content-Type` and preflight)
- **Database queries** — without `confirmed=true` a query runs in a read-only transaction, so the server itself refuses `WITH ... DELETE` or `EXPLAIN ANALYZE DELETE` that look like reads; `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `pg_rotate_logfile`, `pg_promote` need confirmation; a confirmed MySQL write is committed
- **Path traversal in log access** — `log_tail` resolves symlinks and checks against an allowlist
- **Unauthorized Docker container control** — `stop` and `restart` require `confirmed=true`; the protected list is checked against the name Docker resolved, so `/devops-mcp` or an ID prefix cannot stop the server itself
- **Privilege escalation** — non-root container (mcpuser), all Linux capabilities dropped, `no-new-privileges`, source mounted read-only
- **Remote file access** — `file_get` and `file_put` refuse `shadow`, `gshadow`, `sudoers`, `authorized_keys` and private keys outright, also when the path is a symlink to one; both work on the resolved path, so writing to a symlinked `sites-enabled` config updates the file it points to and keeps the link; `file_put` needs `confirmed=true`, keeps mode and owner, and writes through a temporary file in the same directory
- **Backups outside service directories** — the previous content goes to `/var/backups/oleg/<full path>.bak_<time>` (directories 0700; `~/backups/` without rights there). A copy next to the file was loaded by nginx as a second config from `sites-enabled/*`. No file or directory created on a server names the tool
- **Verified writes** — `file_put`'s optional `verify_cmd` restores the previous content when the check fails. Because that command runs automatically as part of a write, it is limited to config tests (`nginx -t` and the like) with no operators, redirects or substitutions, and the arguments are checked per tool: no `postconf -e`, `php-fpm` without `-t`, `json.tool` with an output file, `yq -i`, `wp --exec/--require`, `nginx -g`; general execution stays in `ssh_exec`, where it appears as its own tool call the user can see and refuse
- **Audit trail** — every tool call logged to `/audit/audit.jsonl` with an outcome of `ok`, `refused` or `error`; write failures emit a warning instead of being silently swallowed. File bodies and other long values are stored as `<N chars, sha256=...>`, so the log proves what was written without becoming a copy of it
- **Pooled connections are per credential** — a kept-open SSH connection is keyed by host, port, username and which key or password opened it, so one host's session is never handed to a different credential; passwords are stored as a hash, sessions close after five minutes idle and on shutdown, and `ssh_sessions` closes them on demand
- **Host keys are checked by default** — once `known_hosts` is populated, a host that is not in it is refused rather than warned about; an empty file falls back to warn mode so a fresh install is usable
- **Jump hosts carry bytes, not credentials** — with `jump_host` the target's authentication happens end to end inside the tunnel, so its password never appears in the process list of the intermediate server, which is what running `sshpass` as a command there would do
- **SSH password auth disabled** — password authentication off by default (ALLOW_SSH_PASSWORD=false)

**What it does NOT protect against, on purpose:**
- A compromised AI client with access to the MCP endpoint
- Insider threats with physical access to the server
- **Anyone who can already run code as the owner on the VPS or on the engineer's machine.** There is no HTTP token: such a process can read the SSH keys directly, so a token would add nothing for one user. Add one before the endpoint serves more than one person or leaves 127.0.0.1
- **Docker socket** — `/var/run/docker.sock` is root on the host, and `:ro` on a socket does not limit the API. Whoever takes over the MCP process also holds the keys to every client server, which is worse, so a socket proxy was considered and left out for a one-user deployment
- **Reading secrets** — `ssh_exec`, `file_get` (outside the deny-list) and `db_query` can read `.env` files, configs and password hashes; reading them is part of the work. Commands that pass passwords on the command line (`mysql -p...`) are visible in the process list of the target and are logged verbatim in the audit log, which only root, the owner and the MCP can read
- **Commands keep running after a timeout** — the reply says so; without a pty there is no reliable way to stop the remote process

**Not handled yet:**
- **Recursive walks from `/`** — `du`, `grep -r` and the like pass the validator and keep running on the server after a timeout, which on a large disk is real load. Blocking them outright would cut a useful tool, so the fix is still being worked out: a disk overview of the remote host first (usage and inodes per filesystem), then walks only into the directories it points to. Until then the operator picks the narrowest command for the server at hand

**Intended deployment:** localhost-only (127.0.0.1:8765), accessed via SSH tunnel from a trusted machine.

## Reporting a Vulnerability

If you find a security issue, please **do not open a public GitHub issue**.

Email: oleg.v.usoltsev@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

You can expect a response within 72 hours.
