# Changelog

## [0.6.2] - 2026-11-11

### Security
- `sort`, `tree`, `dmesg`, `ss`, `journalctl` and `find` are checked against an allowlist of options instead of a list of known-dangerous ones. The denylists passed any option nobody had thought of, and every review pass found another (`sort --compress-program`, `find -fprint`, `journalctl --image`). Now an option that is not listed asks for confirmation: for example `sort -T /etc`, `tree --fromfile`, `journalctl --interval`, `find -files0-from`, all of which passed on 0.6.1. Long options must be spelled out, so GNU abbreviations (`--vac=1s`) ask too. `find` checks its whole expression: starting points, then listed tests and operators, each value taken as the value even when it starts with `-` (`-mtime -5`).
- Functions in a read-only SQL query come from an allowlist (aggregates, string, number, date and JSON functions, catalog and size lookups). Anything else asks: `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file`, `lo_get`, `set_config`, `pg_sleep`, a user-defined `public.f()`, calls in quotes or under `/*! */`. Schema-qualified calls pass only from `pg_catalog` and `information_schema`. `pg_read_binary_file` was listed in a test as a free read before; it now asks like the rest. Calls are looked for with every quote mark blanked too: a first version skipped string literals by the plain `'...'` rule and missed calls hidden by syntax only one server has (MySQL `'\''`, Postgres `$$...$$` and `E'\''`), found in review before merge. The price is that `(` inside a string literal (`LIKE 'foo(%'`) asks.
- `tree` parses its own options rather than with getopt: a value letter takes the next word and the letters after it still act, so `tree -Lo 1 /tmp/x /etc` wrote `/tmp/x` and passed as a read since 0.6.0 (the old check treated the `o` as the value of `-L`). A value letter must now end its word.

### Changed
- Replayed against the audit log (8 593 distinct `ssh_exec` commands, 14 `db_query` queries): no decision changed in either direction, so the allowlists cover everything actually used. A probe confirmed that the new code is the one being tested: the five forms above passed on 0.6.1 and ask on 0.6.2.

## [0.6.1] - 2026-11-11

Leftovers of the 0.6.0 audit and requests from live work on client servers. Each security item was reproduced against the running 0.6.0 in its own image first.

### Security
- DNS lookups no longer take names from a file or stdin without confirmation. `dig -f /etc/passwd @server` and `cat /etc/passwd | nslookup - server` passed as reads and sent the file line by line to the server named. `dig -f`/`-k`, and `nslookup` without a name or with `-` for it, now ask. `dig`, `nslookup` and `host` moved under the argument checks, so a shell expansion in their words (`dig $line.example.com`) asks too.
- `file_get`/`file_put` refuse sshd host keys (`ssh_host_*_key`) and FIDO-backed user keys (`id_*_sk`); the `.pub` halves stay readable. Both passed before, while plain `id_ed25519` was refused.
- The audit log no longer stores `file_put` content, only its length and hash. Short content was stored verbatim: a sudo password put on a client server as a one-line file landed in the log (17.10.2026). Long content kept its first 200 characters, which is where credentials in a config usually are. Fields whose name contains password, secret or token are masked whatever their prefix: `jump_password` was stored as given.

### Changed
- Reads that asked for confirmation in real work now pass: `mysql -V`/`--version`; `ipset list`/`test` (no `-file`, which writes the listing); `iptables`/`ip6tables` listings built from `-L`/`-S` and the letters `nvxw` with `-t TABLE` (`-L -Z` zeroes counters and still asks); `iptables-save` without `-M`; `zcat`, `zgrep`, `tr`; and `awk` in one small grammar, `[condition] {print fields}` with an optional `-F`. Other awk programs ask: system(), getline from a command, `print >` and `|` all write or run something, and the grammar is the boundary, not a parser of awk.
- `ssh_exec` commands may be up to 1000 characters (was 500; the limit was hit twice in a day of real work).
- Replayed against all 8 583 distinct commands in the audit log: no command that passed starts asking; 247 that asked now pass (zcat/zgrep, iptables, ipset test, awk print), 25 reads over 500 characters now pass, 115 longer non-reads now ask instead of being refused for length.

## [0.6.0] - 2026-10-12

Security audit of the whole server: every finding below was reproduced on a stand (the image on the VPS, throwaway containers, real SFTP and databases) before it was fixed. The model is a personal MCP for one engineer; see SECURITY.md for what is left out on purpose and why.

### Security
- `ssh_exec` allowlist: flags and scripts are parsed per command instead of searched as substrings (`command_args.py`). Each of these passed without confirmation and acted: `command rm -rf ...` and `hash -p /bin/rm cat` (any command through a builtin), `git -c core.fsmonitor=...`, `git ls-remote --upload-pack=...`, `ext::` URLs and `git log --output=...`, `sed '1e ...'` and `sed -ni` (rewrote a three-line file to one line), `curl -XPOST` and `--json`, `curl -so FILE`, plain `wget`, `ip l s eth0 down` and `ip r d default` (abbreviations), `ip -b FILE`, `journalctl --rot`, plus mutating flags of commands that were listed as always safe (`ifconfig eth0 down`, `hostname x`, `date -s`, `dmesg -C`, `ss -K`, `sort -o`, `uniq in out`, `tree -o`, `ping -f`, `file -C`). Replayed against all 5 205 distinct commands in the audit log: no real read starts asking for confirmation, 34 that asked by mistake now pass (`-i` found inside `registry-infra`).
- An adversarial pass over the new parser closed eight more ways through, each reproduced: a quoted `'>'` that swallowed the next word (`curl '>' -XPOST` to docker.sock, `sed -e p '>' -i`), GNU abbreviations `sed --e`, `sed --l N` and `date --s=`, `curl -w '%output{FILE}'` (curl 8.3+ writes the file), and `tree -R` (writes `00Tree.html` in every directory). Redirects are now removed where the quote mask sees them, never by the shape of a word. A later automated review added three more, also reproduced: a sed label ending at `;` (`sed ':a;e id'`), curl targets other than http(s) through `--url`, `--proto-default` or a glob in the scheme (`{dict,http}://`), and `ip -fam inet l s lo down` (an abbreviated value option shifted the parse). ip global options now come from an explicit list.
- A third pass (automated review after the push) found more, each checked on the stand: the words of a parsed command were judged before bash expands them (`sed p ${X:--i} f` edited the file in place; also `{-i,f}`, `$'-i'`, `git log {--output=x,-1}`), so an expansion in their arguments now asks, except `$HOME`, `$USER`, `$PWD`. curl long options come from an allowlist (`--expand-output` wrote a file with curl 8.10; curl 7.x takes any abbreviation), and a bare host that makes curl guess another protocol (`dict.x:6379` is DICT) asks. `docker compose config -o` wrote a file. `>&1x` and `>/dev/nullx` created files. `verify_cmd` arguments are an allowlist per server: `nginx -t -c` and `apachectl -t -C` load modules, `php-fpm -t -d` an extension, `named-checkzone -o` and `visudo -x` write, `iptables-restore -M` runs a program. The review of that fix found four more of the same classes, also reproduced: `dict:/127.0.0.1:6379` with one slash is DICT to curl 8.10; a quote or backslash right after the target (`2>/dev/null'x'`) created /dev/nullx; `INTO/*! */ /*!OUTFILE*/` split the keyword pair; `pg_file_write` was missing; `ping -i 0` and `-l` flood as root. And curl options that send a local file (`-H @/etc/shadow`, `--url-query a@FILE`, a `-b` cookie file) or let a redirect reach dict:// (`--proto-redir`), and `journalctl --image`, which mounts a disk image. A backslash-newline, which bash joins (sed p, backslash, newline, -i edited the file in place), is joined before the words are checked.
- The quote mask ended a double-quoted string at an escaped quote, so in `echo "a\" b" ; touch x ; echo "c"` the middle command looked like quoted data: any command ran without confirmation and past the hard denials. Present in every release with the mask, reproduced in bash on the stand; fixed together with the pattern that pulls quoted payloads out for the interpreter check. The same with ANSI-C quoting: inside `$'...'` an escaped quote does not end the string and `\x63` spells a letter, so `$'...'` with escapes other than `\r \t \n \\` is refused even with confirmation.
- After a dropped connection only real reads are retried: the retry decision uses the same parser.
- `pkill -f '[s]leep 300'` is refused when `sleep 300` appears elsewhere in the same command: the shell running it has the whole line in its argv, and on the stand this killed the ssh session.
- HTTP transport accepts only `Host` 127.0.0.1/localhost and no foreign `Origin` (DNS rebinding from a browser through the SSH tunnel). `MCP_ALLOWED_HOSTS` overrides.
- `db_query`: unconfirmed queries run in a read-only transaction (`WITH d AS (DELETE ...) SELECT` and `EXPLAIN ANALYZE DELETE` deleted rows on Postgres); `pg_terminate_backend` and friends need confirmation. Before this release `SELECT '#'; COMMIT; DELETE FROM t; COMMIT` deleted every row on MySQL without confirmation: the comment stripper hid the `;` behind the `#` in the string, aiomysql always allows several statements, and the `COMMIT` ended the read-only transaction. `INTO OUTFILE` behind `/*! */` or a `'#'` wrote a file. Every check now also runs on the raw query and on one with comment and quote marks blanked, and any `;` before the end is refused; a quoted name (`"pg_terminate_backend"(pid)`), `U&` escapes, `dblink` and `query_to_xml` need confirmation.
- `file_get`/`file_put` resolve symlinks: a link to `id_rsa` no longer walks around the deny-list, and writing to a symlinked config updates its target instead of replacing the link with a detached copy.
- `verify_cmd` arguments are checked per tool (`wp ... --exec` ran PHP, `python3 -m json.tool in out` overwrote `out`, `postconf -e` edited main.cf).
- `docker_control` checks the protected list against the resolved container name (`/devops-mcp` went through).
- The image no longer carries `keys/`, `ssh/`, `.env` and `.git` (no `.dockerignore`, `COPY . .` baked four private keys into every layer; the running container mounts them anyway).
- Dependencies: `mcp` 1.27.0 → 1.28.1, `anyio` 4.13.0 → 4.14.2 (trivy: three HIGH, one CRITICAL).

### Fixed
- `db_query` on MySQL committed nothing: `aiomysql` opens with autocommit off and a confirmed `INSERT` reported success and vanished on close. No such write was ever made through the tool (checked in the audit log).
- `ssh_exec` reads at most 1 MiB of output and says when it cut; `head -c 300000000 /dev/zero` OOM-killed the 256M container.
- `file_put` keeps the previous content in `/var/backups/oleg/<path>.bak_<time>` (0700, `~/backups/` without rights) instead of next to the file, where nginx loaded it from `sites-enabled/*` (duplicate `upstream` broke `nginx -t`) and logrotate exited 1 on the duplicate rules. The temporary file no longer names the tool.
- Timeouts below 1 second are raised to 1 (`0` gave `BlockingIOError`).

### Changed
- Base image `python:3.12-slim-trixie` (Debian 13: 44 HIGH and no CRITICAL against 55 HIGH and 2 CRITICAL), built in two stages so gcc stays out: 329 MB instead of 589 MB.
- `git -c ...` and `wget ...` now always ask for confirmation; neither was used without it in the audit log.

## [0.5.3] - 2026-10-12

### Added
- Hard denials in `validate_ssh_command`: a few commands are refused even with `confirmed=true`, because they have no safe form. `find` without `-maxdepth` (an unbounded walk took a production box down on 10.03.2026), `pkill -f` and `pgrep -f` without a `[b]racket` pattern (the pattern matched its own command line and killed the session on 04.10.2026), and `rm -r` on `/` or a top-level directory such as `/etc`, `/var`, `/home`. `sudo`, `nice`, `nohup` and `env` prefixes are looked through. Everything else keeps the allowlist-plus-confirmation model.

## [0.5.2] - 2026-09-27

### Fixed
- `ssh_exec` closes the command's stdin right after starting it. A command that reads its input (`grep` without a file, `cat`, `read`) used to wait for input nobody would send and ran into the timeout.
- A timeout is reported as a timeout. `socket.timeout` is an `OSError`, so it went down the dead-connection branch: a healthy pooled connection was thrown away, the error said "Connection dropped", and a read-only command was run a second time. Now only that command's channel is closed, the connection stays in the pool, and nothing is repeated.
- The HTTP server keeps idle connections for 300 seconds instead of uvicorn's default 5. A client request sent into a connection the server had just closed came back as `ECONNRESET`.

## [0.5.1] - 2026-08-06

### Changed
- Host key checking is strict by default once `known_hosts` has anything in it, and stays in warn mode while the file is empty. Before, strict mode existed but had to be asked for per call, so in practice every connection reported "unknown host key" and everyone learned to scroll past it. `SSH_STRICT_HOST_KEY` overrides the default in either direction; `verify_host_key` still wins per call.
- README documents reading host keys off the machine itself rather than with `ssh-keyscan`, which trusts whoever answers on the port — the thing host key checking is there to catch.

## [0.5.0] - 2026-08-06

### Added
- SSH connections are kept open between tool calls. Every `ssh_exec` used to be a full connect, key exchange, auth and close; a twenty command diagnostic paid that twenty times, and twenty connections in a row from one address are what fail2ban is built to notice (it banned us for fifteen minutes mid-incident once). Measured against a real host: first call 220 ms, later calls 50 ms, one handshake instead of eight. `file_get` and `file_put` ride the same connection.
- `ssh_sessions` tool: `action='status'` lists open connections with usage and idle time, `action='close'` drops them now, optionally for one host or user only.
- Connections are keyed by host, port, username and credential, so two different keys or passwords never share one. A password is kept only as a short hash of itself.
- Idle connections close after `SSH_POOL_IDLE_TTL` seconds (default 300) via a background reaper, on shutdown, and whenever the transport turns out to be dead. New settings: `SSH_POOL`, `SSH_POOL_IDLE_TTL`, `SSH_POOL_MAX`, `SSH_POOL_KEEPALIVE`.
- Responses carry `connection: reused | new`, so the audit log shows which calls paid for a handshake.

### Added (ProxyJump)
- `jump_host`, `jump_user`, `jump_key`, `jump_password`, `jump_port` on `ssh_exec`, `file_get` and `file_put`: reach a server through an intermediate one, the way `ssh -J` does. The jump host carries bytes only; authentication with the target happens end to end inside the tunnel, so the target's password never becomes an argument to a command running on the jump box.
- This is what makes SFTP reach hosts behind a bastion at all. Running `ssh` or `sshpass` as a command on the intermediate server cannot carry `file_get` / `file_put`, so on those hosts config editing meant `printf | tee` through two shells.
- Jump connections are pooled and shared between every target behind them, counted as their own entry, and reported as `via` in `ssh_sessions`. The reaper will not close a jump host while something is tunnelled through it, and closing one explicitly closes its dependants rather than leaving dead entries behind.

### Notes
- Commands still run as separate channels: no working directory, environment or shell state carries between calls. A persistent shell would let two separately validated calls add up to one command neither of them was.
- A connection that dies mid-flight is retried once, but only for a read. `file_put` is never replayed: if the transport dropped after the rename, a second pass would read the new content as the old one, report "nothing to write" about a config it had just replaced, and treat the replacement as the thing to restore. It now returns an error naming the stage it stopped at and where the previous content is. `ssh_exec` retries only commands that pass the read-only allowlist, since a second `apt install` is worse than an honest error.
- The pool only covers connections this server opens. A second hop inside the command (`ssh`, `sshpass`) is still a fresh connection every time, so the fail2ban argument does not extend to hosts reached that way.
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
