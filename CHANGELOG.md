# Changelog

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
