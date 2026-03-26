import re
from pathlib import Path

NGINX_CONTAINER_ALLOWLIST = frozenset([
    "nginx",
    "nginx-proxy",
    "nginx-main",
])

LOG_PATH_ALLOWLIST_PREFIXES = [
    "/var/log/dpkg.log",
    "/var/log/fail2ban.log",
    "/var/log/cloud-init.log",
    "/var/log/cloud-init-output.log",
    "/var/log/unattended-upgrades/",
    "/var/log/apt/",
    "/var/log/nginx/",
    "/var/log/syslog",
    "/var/log/auth.log",
]

ALLOWED_PORTS = frozenset([443, 80, 8443, 8080, 465, 993, 995])

# ---------------------------------------------------------------------------
# SSH command validation — read-only allowlist model
#
# Without confirmed=true only explicitly safe, read-only patterns are allowed.
# Everything else is considered potentially mutating and requires confirmation.
# Injection patterns and output redirects are always blocked regardless.
# ---------------------------------------------------------------------------

# Single-word commands that are unconditionally read-only.
# Commands that can mutate state via flags (sed -i, curl -X POST, wget --post-data,
# find -exec, awk system()) are intentionally excluded and handled separately below.
_SAFE_SINGLE = frozenset({
    # System info
    "uptime", "df", "free", "ps", "top", "htop", "vmstat", "iostat",
    "netstat", "lsof", "who", "w", "last", "lastb",
    # File reading (no mutating flags possible for these)
    "cat", "head", "tail", "less", "more", "wc", "sort", "uniq", "cut",
    "grep", "egrep", "fgrep",
    # Filesystem inspection (read-only, no -exec/-delete)
    "ls", "ll", "stat", "file", "du", "lsblk", "tree",
    # Kernel / system logs
    "journalctl", "dmesg",
    # Network diagnostics (read-only: ping, traceroute, dns)
    "ping", "traceroute", "tracepath", "nslookup", "dig", "host",
    "ss", "ip", "ifconfig",
    # Identity / environment
    "whoami", "id", "hostname", "uname", "date", "cal",
    "printenv", "which", "whereis", "type",
    # Misc safe
    "echo", "true", "false",
})

# Tokens/substrings that make otherwise-safe commands mutating.
# Keyed by command name; any occurrence of any value in the full command → require confirmed.
# Note: awk is excluded entirely (its program text can contain system() calls which
# are too complex to validate reliably — it goes straight to confirmed=true).
_MUTATING_TOKENS: dict[str, tuple[str, ...]] = {
    "sed":  ("-i", "--in-place"),
    "curl": ("-x ", "--request ", "-d ", "--data", "--upload-file", "-t ",
             "-f ", "--form", "--output", "-o "),
    "wget": ("--post-data", "--post-file", "-o ", "--output-document",
             "--ftp-user", "--execute"),
    "find": ("-exec ", "-execdir ", "-delete", "-ok ", "-okdir "),
}

# Commands allowed only when no mutating token is present.
_CONDITIONALLY_SAFE = frozenset(_MUTATING_TOKENS.keys())

# Two-word prefixes for commands whose safety depends on the subcommand.
# Only the listed subcommands are allowed without confirmation.
_SAFE_TWO_WORD = frozenset({
    # systemctl — status queries only
    "systemctl status", "systemctl list-units", "systemctl list-services",
    "systemctl is-active", "systemctl is-enabled", "systemctl is-failed",
    "systemctl show",
    # docker — read-only subcommands
    "docker ps", "docker images", "docker logs", "docker inspect",
    "docker stats", "docker top", "docker port", "docker diff",
    "docker version", "docker info", "docker network",
})

# Always-blocked patterns regardless of confirmed (command injection / redirects).
_INJECTION_PATTERNS = ("$(", "`")


def validate_log_path(path: str) -> Path:
    if "\x00" in path:
        raise PermissionError("Null byte in path")
    if ".." in Path(path).parts:
        raise PermissionError("Path traversal not allowed")
    if any(c in path for c in ("*", "?", "[", "]")):
        raise PermissionError("Glob characters not allowed in path")

    # resolve() follows symlinks — resolved path must still fall inside allowlist,
    # which implicitly enforces "symlink target stays in /var/log"
    p = Path(path).resolve()
    path_str = str(p)

    for prefix in LOG_PATH_ALLOWLIST_PREFIXES:
        allowed = prefix.rstrip("/")
        if path_str == allowed or (prefix.endswith("/") and path_str.startswith(prefix)):
            if not p.exists():
                raise FileNotFoundError(f"File not found: {path}")
            if not p.is_file():
                raise PermissionError(f"Not a regular file: {path}")
            return p

    raise PermissionError(f"Path not in allowlist: {path}")


def validate_nginx_container(name: str) -> None:
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError(f"Invalid container name format: {name}")
    if name not in NGINX_CONTAINER_ALLOWLIST:
        raise PermissionError(f"Container not in allowlist: {name}")


_DB_READ_PREFIXES = frozenset(('select', 'show', 'describe', 'desc', 'explain', 'with'))
_DB_WRITE_PREFIXES = frozenset(('insert', 'update', 'delete', 'replace', 'call', 'do'))
_DB_DDL_PREFIXES = frozenset(('create', 'drop', 'alter', 'truncate', 'rename'))
_DB_PRIV_PREFIXES = frozenset(('grant', 'revoke'))


def validate_db_query(query: str, confirmed: bool) -> None:
    if len(query) > 10000:
        raise ValueError("Query too long (max 10000 chars)")
    tokens = query.strip().split()
    if not tokens:
        raise ValueError("Empty query")
    first = tokens[0].lower()
    if first in _DB_PRIV_PREFIXES:
        raise PermissionError("GRANT/REVOKE operations are not allowed")
    if first in _DB_WRITE_PREFIXES or first in _DB_DDL_PREFIXES:
        if not confirmed:
            raise ValueError(
                f"Query '{first.upper()}' modifies data. "
                "Repeat with confirmed=true after user approval."
            )


def validate_ssh_key_path(path: str) -> None:
    if "\x00" in path:
        raise PermissionError("Null byte in path")
    if not path.startswith("/app/keys/"):
        raise PermissionError("Key path must be under /app/keys/")
    filename = path[len("/app/keys/"):]
    if not filename or "/" in filename:
        raise PermissionError("Key path must point to a file directly in /app/keys/")
    if ".." in filename:
        raise PermissionError("Path traversal not allowed")
    if not re.match(r'^[a-zA-Z0-9_.\-]+$', filename):
        raise PermissionError(f"Invalid characters in key filename: {filename}")


def _is_subcommand_safe(cmd: str) -> bool:
    """Return True if a single shell command (no operators) is read-only safe."""
    tokens = cmd.strip().split()
    if not tokens:
        return True
    first = tokens[0].lower()

    # Check two-word prefix first (more specific match for systemctl/docker)
    if len(tokens) >= 2:
        two = f"{first} {tokens[1].lower()}"
        if two in _SAFE_TWO_WORD:
            return True

    # Unconditionally safe single-word commands
    if first in _SAFE_SINGLE:
        return True

    # Conditionally safe: allowed only when no mutating tokens appear in the full cmd
    if first in _CONDITIONALLY_SAFE:
        cmd_lower = cmd.lower()
        mutating = _MUTATING_TOKENS[first]
        return not any(tok in cmd_lower for tok in mutating)

    return False


def _split_shell_commands(command: str) -> list[str]:
    """Split a shell command string into individual commands by shell operators."""
    # Split on ||, |, &&, ; — order matters: || before |
    return re.split(r'\|\||&&|[|;]', command)


def validate_ssh_command(command: str, confirmed: bool) -> None:
    if len(command) > 500:
        raise ValueError("Command exceeds maximum length of 500 characters")

    # Always block command injection patterns
    for pattern in _INJECTION_PATTERNS:
        if pattern in command:
            raise ValueError(f"Shell injection pattern detected: {pattern!r}")

    # Always block output redirection
    if re.search(r'>{1,2}\s*\S', command):
        raise ValueError("Output redirection is not allowed")

    # Read-only allowlist check: every sub-command must be safe or confirmed required
    sub_commands = _split_shell_commands(command)
    unsafe = [sc.strip() for sc in sub_commands if sc.strip() and not _is_subcommand_safe(sc)]

    if unsafe:
        if not confirmed:
            examples = ", ".join(repr(sc.split()[0]) for sc in unsafe[:3] if sc.split())
            raise ValueError(
                f"Command requires confirmation ({examples} is not in the read-only allowlist). "
                "Repeat with confirmed=true after user approval."
            )


def validate_host_port(host: str, port: int) -> None:
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        raise ValueError(f"Invalid hostname format: {host}")
    if len(host) > 253:
        raise ValueError("Hostname too long")
    if port not in ALLOWED_PORTS:
        raise PermissionError(f"Port {port} not in allowlist: {sorted(ALLOWED_PORTS)}")


# ---------------------------------------------------------------------------
# DB query validation — whitelist model for SQL
# ---------------------------------------------------------------------------

import re as _re

_DB_COMMENT_PATTERNS = [
    _re.compile(r'/\*.*?\*/', _re.DOTALL),
    _re.compile(r'--[^\n]*'),
    _re.compile(r'#[^\n]*'),
]

_DB_READ_PREFIXES = frozenset({
    "select", "show", "describe", "desc", "explain", "with",
})

_DB_WRITE_PREFIXES = frozenset({
    "insert", "update", "delete", "replace", "call", "do",
    "prepare", "execute",
})

_DB_DDL_PREFIXES = frozenset({
    "create", "drop", "alter", "truncate", "rename",
})

_DB_PRIV_PREFIXES = frozenset({
    "grant", "revoke",
})

_DB_PRIV_PATTERNS = _re.compile(
    r'\b(CREATE\s+USER|DROP\s+USER|ALTER\s+USER|'
    r'CREATE\s+ROLE|DROP\s+ROLE)\b', _re.IGNORECASE
)

_DB_DANGER_PATTERNS = _re.compile(
    r'\b(INTO\s+(OUT|DUMP)FILE|LOAD_FILE|lo_import|lo_export|'
    r'pg_read_file|pg_write_file|COPY\b)', _re.IGNORECASE
)


def _strip_sql_comments(query: str) -> str:
    result = query
    for pat in _DB_COMMENT_PATTERNS:
        result = pat.sub(' ', result)
    return result.strip()


def validate_db_query(query: str, confirmed: bool) -> None:
    cleaned = _strip_sql_comments(query)
    if not cleaned:
        raise ValueError("Empty query after stripping comments")

    stripped = cleaned.rstrip(';').strip()
    if ';' in stripped:
        raise ValueError("Multi-statement queries are not allowed")

    if _DB_PRIV_PATTERNS.search(cleaned):
        raise PermissionError("User/role management is not allowed through this tool")

    if _DB_PRIV_PREFIXES & {cleaned.split()[0].lower()}:
        raise PermissionError("GRANT/REVOKE is not allowed through this tool")

    first = cleaned.split()[0].lower()

    if first in _DB_READ_PREFIXES:
        if _DB_DANGER_PATTERNS.search(cleaned):
            raise PermissionError(
                f"Dangerous construct in SELECT query: {cleaned[:80]}"
            )
        return

    if first in _DB_WRITE_PREFIXES | _DB_DDL_PREFIXES:
        if not confirmed:
            raise ValueError(
                f"Query '{first.upper()}' requires confirmation. "
                "Repeat with confirmed=true after user approval."
            )
        return

    if not confirmed:
        raise ValueError(
            f"Unknown query type '{first.upper()}'. "
            "Repeat with confirmed=true after user approval."
        )
