# Changelog

## [0.5.0] - 2026-08-06

### Added
- SSH connections are kept open between tool calls. Every `ssh_exec` used to be a full connect, key exchange, auth and close; a twenty command diagnostic paid that twenty times, and twenty connections in a row from one address are what fail2ban is built to notice (it banned us for fifteen minutes mid-incident once). Measured against a real host: first call 220 ms, later calls 50 ms, one handshake instead of eight. `file_get` and `file_put` ride the same connection.
- `ssh_sessions` tool: `action='status'` lists open connections with usage and idle time, `action='close'` drops them now, optionally for one host or user only.
- Connections are keyed by host, port, username and credential, so two different keys or passwords never share one. A password is kept only as a short hash of itself.
- Idle connections close after `SSH_POOL_IDLE_TTL` seconds (default 300) via a background reaper, on shutdown, and whenever the transport turns out to be dead. New settings: `SSH_POOL`, `SSH_POOL_IDLE_TTL`, `SSH_POOL_MAX`, `SSH_POOL_KEEPALIVE`.
- Responses carry `connection: reused | new`, so the audit log shows which calls paid for a handshake.

### Notes
- Commands still run as separate channels: no working directory, environment or shell state carries between calls. A persistent shell would let two separately validated calls add up to one command neither of them was.
- `tools/ssh_pool.py` is deliberately absent from the hot-reload list, since reloading it would drop the dict of live connections while the sockets stayed open.

## [0.4.0] - 2026-08-05

### Added
- `file_put` can check what it wrote and undo it. Pass `verify_cmd` (`nginx -t`, `apachectl configtest`, `sshd -t`, `php -l`, `named-checkconf`, `haproxy -c`, `systemd-analyze verify`, `docker compose config` and similar) and the test runs against the new file over the same connection. On a non-zero exit the previous content goes back atomically, the test runs again to prove the server is where it started, and the backup that is no longer needed is removed. The response carries `verify`, `rolled_back` and `verify_after_rollback`. `rollback_on_failure=false` keeps the new content instead.
- `verify_cmd` is restricted to config tests. It fires automatically as part of a write, so it must be a test rather than a general shell, and operators, redirects and substitutions are rejected inside it. Anything else belongs in `ssh_exec`, where the user sees it as its own call.

### Fixed
- Backup names carried a per-second timestamp, so two writes to the same file inside one second silently overwrote the first copy. Names are now checked for collisions and get a `-2` suffix.
- `scripts/smoke_file_transfer.py` refuses to run against an existing target. Its first checks are about creating a file, and a leftover from an earlier run made them pass for the wrong reason.

## [0.3.0] - 2026-08-05

### Fixed
- **Audit log recorded failures as successes.** Tools report problems by returning `{"error": ...}` rather than raising, so the `finally` block in `call_tool` saw a normal return and wrote `result_status: "ok"`. Every blocked command and every failed login since March is logged as a success. Outcomes are now `ok`, `refused` (rejected by our own rules) or `error` (the operation failed).
- `security.py`: removed a dead first definition of `validate_db_query` and its `_DB_*` constants, shadowed by a second definition 200 lines below, plus a stray mid-file `import re as _re`.

### Added
- `file_get` and `file_put` — read and write remote files over SFTP. No shell is involved, so there is no 500 character ceiling and no quoting to fight: semicolons in an nginx directive, backticks and `$(...)` in a script, HTML in an alert body all travel verbatim. `file_put` returns a unified diff, saves `path.bak_<timestamp>`, preserves mode and owner, and writes through a temporary file in the same directory. `dry_run=true` shows the diff without touching anything; the write itself needs `confirmed=true`.
- Credential files (`shadow`, `gshadow`, `sudoers`, `authorized_keys`, private keys) are refused by both file tools.
- `ToolAnnotations` on all 19 tools (`readOnlyHint`, `destructiveHint`), so a client can gate destructive calls by protocol instead of trusting the model to read a description.
- Streamable HTTP transport on `/mcp`, stateless. Restarting the container used to leave the client holding a dead SSE session that answered `-32602` to every call until a manual reconnect. `/sse` stays mounted, so nothing has to move today.
- Ruff (`E9,F`) in CI. The duplicate definition above is exactly what F811 catches.
- Tests: `tests/test_audit.py` drives `call_tool` and reads the log file back, `tests/test_file_transfer.py` covers the path rules and the pre-connection refusals. 190 tests total.

### Changed
- Audit records keep the SSH key path (which key we connected with is the point of the trail) but mask a `key` field holding anything else, and replace values longer than 200 characters with `<N chars, sha256=...>`.
- `requirements.txt` pinned to the versions the running container actually has, instead of `>=`.
- `SECURITY.md`: states plainly that `confirmed=true` is set by the model itself and is therefore a guard against accidents, not a security boundary.

### Removed
- `_wip/db_query.py` — a stale copy of the shipped tool, carrying a `passwd=` typo.

## [0.2.0] - 2026-03-24

### Fixed
- `docker_control`: `stop` and `restart` now require `confirmed=true`. Previously the tool description promised confirmation but the code did not enforce it.
- `docker_control`: Docker `NotFound` exceptions are now returned as error dicts instead of propagating as unhandled exceptions.
- `ssh_exec`: Replaced silent `AutoAddPolicy` with `_CapturingWarningPolicy` — unknown host keys are reported in the response instead of being silently accepted.

### Added
- `ssh_exec`: `verify_host_key=true` parameter enables strict mode — rejects hosts not present in `/app/ssh/known_hosts`.
- `ssh/known_hosts` mount point in `docker-compose.yml` for host key management.
- `host_key` field in `ssh_exec` response shows mode and any warnings.
- `LICENSE` file (MIT).
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- GitHub Actions CI: syntax check and import smoke test.

### Removed
- `db_query` tool from public surface (registered but missing dependencies and schema). Moved to `_wip/` — will be re-introduced in a future release with proper asyncpg/aiomysql support.

### Changed
- `README`: removed "production-ready" framing, added trusted self-hosted disclaimer and SSH host key documentation.
- `.env.example`: removed DB-related variables.

## [0.1.0] - 2026-03-23

Initial release. 16 tools covering Docker, SSH, system health, logs, Nginx, Prometheus, and web search.
