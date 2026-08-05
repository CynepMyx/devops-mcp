# Changelog

## [0.3.0] - 2026-08-05

### Fixed
- **Audit log recorded failures as successes.** Tools report problems by returning `{"error": ...}` rather than raising, so the `finally` block in `call_tool` saw a normal return and wrote `result_status: "ok"`. Every blocked command and every failed login since March is logged as a success. Outcomes are now `ok`, `refused` (rejected by our own rules) or `error` (the operation failed).
- `security.py`: removed a dead first definition of `validate_db_query` and its `_DB_*` constants, shadowed by a second definition 200 lines below, plus a stray mid-file `import re as _re`.

### Added
- `file_get` and `file_put` — read and write remote files over SFTP. No shell is involved, so there is no 500 character ceiling and no quoting to fight: semicolons in an nginx directive, backticks and `$(...)` in a script, HTML in an alert body all travel verbatim. `file_put` returns a unified diff, saves `path.bak_<timestamp>`, preserves mode and owner, and writes through a temporary file in the same directory. `dry_run=true` shows the diff without touching anything; the write itself needs `confirmed=true`.
- Credential files (`shadow`, `gshadow`, `sudoers`, `authorized_keys`, private keys) are refused by both file tools.
- `ToolAnnotations` on all 19 tools (`readOnlyHint`, `destructiveHint`), so a client can gate destructive calls by protocol instead of trusting the model to read a description.
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
