import re
from pathlib import Path, PurePosixPath

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
    # System info. top/htop excluded: without -b they never exit and hang until timeout.
    "uptime", "df", "free", "ps", "vmstat", "iostat",
    "netstat", "lsof", "who", "w", "last", "lastb",
    # File reading. less/more excluded for the same reason as top: they are pagers.
    "cat", "head", "tail", "wc", "sort", "uniq", "cut",
    "grep", "egrep", "fgrep",
    # Filesystem inspection (read-only, no -exec/-delete)
    "ls", "ll", "stat", "file", "du", "lsblk", "tree",
    # Kernel / system logs. journalctl moved to conditionally safe: --rotate and
    # --vacuum-* delete logs, which is exactly what an intruder does to cover tracks.
    "dmesg",
    # Network diagnostics (read-only: ping, traceroute, dns).
    # 'ip' moved to conditionally safe: 'ip link set eth0 down' or 'ip route del'
    # cuts the connection to the very server we are working on.
    "ping", "traceroute", "tracepath", "nslookup", "dig", "host",
    "ss", "ifconfig",
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
    # Reading is fine (ip a, ip route show); changing addresses, routes or link
    # state on a remote box is how you lock yourself out.
    "ip": ("set ", "del ", "add ", "flush", "change ", "replace ", "append "),
    # Reading journals is fine; these flags delete them.
    "journalctl": ("--rotate", "--vacuum", "--flush", "--sync", "--relinquish-var"),
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
    "docker version", "docker info",
    # NOTE: bare "docker network" is deliberately absent — it would also cover
    # 'docker network rm' and 'docker network prune'. See _SAFE_THREE_WORD.
})

# Three-word prefixes, for subcommands whose parent is too broad to allow wholesale.
_SAFE_THREE_WORD = frozenset({
    "docker network ls", "docker network inspect",
    "docker volume ls", "docker volume inspect",
    "docker image ls", "docker image inspect",
    "docker container ls", "docker container inspect",
    "docker compose ps", "docker compose config",
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

    # Longest prefix wins: three words before two, so that 'docker network ls'
    # can be allowed while 'docker network rm' still falls through to confirmation.
    if len(tokens) >= 3:
        three = f"{first} {tokens[1].lower()} {tokens[2].lower()}"
        if three in _SAFE_THREE_WORD:
            return True

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


def _mask_quotes(command: str) -> tuple[str, bool]:
    """Mask quoted data so shell syntax can be told apart from payload.

    Returns (mask, has_substitution).

    In the mask every character inside quotes is replaced by 'x' and the quote
    characters themselves by a space, so indexes still line up with the original
    string. That lets us search for operators and redirects in the mask while
    slicing the real command by the same positions.

    has_substitution is True only when $( or a backtick appears where the shell
    would actually expand it: outside quotes or inside double quotes. Inside
    single quotes the shell expands nothing, so config text with ; $ ` > is safe.
    """
    out: list[str] = []
    has_substitution = False
    state: str | None = None  # None | "'" | '"'
    i = 0
    n = len(command)
    while i < n:
        c = command[i]

        if state is None and c == "\\" and i + 1 < n:
            out.append(' ')
            out.append('x')
            i += 2
            continue

        if state is None:
            if c in ("'", '"'):
                state = c
                out.append(' ')
            else:
                if c == '`' or (c in '$<>' and i + 1 < n and command[i + 1] == '('):
                    has_substitution = True
                out.append(c)
        elif state == "'":
            if c == "'":
                state = None
                out.append(' ')
            else:
                out.append('x')
        else:  # inside double quotes
            if c == '"':
                state = None
                out.append(' ')
            else:
                if c == '`' or (c in '$<>' and i + 1 < n and command[i + 1] == '('):
                    has_substitution = True
                out.append('x')
        i += 1

    return ''.join(out), has_substitution


# Command separators. Order matters: || and && must match before the single-char
# class, otherwise '&&' would be split as two '&'. A bare '&' backgrounds the left
# side and runs the rest, and a newline separates commands just like ';' — both
# were missing and let 'uptime\nrm -rf /tmp/x' through with only 'uptime' inspected.
_OPERATOR_RE = re.compile(r'\|\||&&|[|;&\n\r]')


def _split_shell_commands(command: str) -> list[str]:
    """Split a command into sub-commands by shell operators, ignoring quoted text.

    Operators are located in the masked copy, so a semicolon inside an nginx
    config snippet or a pipe inside a grep pattern no longer splits anything.
    """
    mask, _ = _mask_quotes(command)
    parts: list[str] = []
    start = 0
    for m in _OPERATOR_RE.finditer(mask):
        parts.append(command[start:m.start()])
        start = m.end()
    parts.append(command[start:])
    return parts


def validate_ssh_command(command: str, confirmed: bool) -> None:
    if len(command) > 500:
        raise ValueError("Command exceeds maximum length of 500 characters")

    mask, has_substitution = _mask_quotes(command)

    # Block command substitution only where the shell would expand it.
    # Inside single quotes $( and ` are literal text, so config snippets pass.
    if has_substitution:
        raise ValueError("Shell injection pattern detected: command substitution")

    # Block output redirection, but only outside quotes: '<b>' in an alert body
    # or a ';' in an nginx directive are data, not syntax.
    if re.search(r'>{1,2}\s*\S', mask):
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


# ---------------------------------------------------------------------------
# Remote file transfer (file_get / file_put) — deny-list model
#
# Unlike ssh_exec, these tools do not go through a shell at all, so there is no
# syntax to validate. What is left is the target itself: credential material is
# refused outright, because reading it only feeds secrets into the model's
# context and writing it is never part of a config change.
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 512 * 1024

_FILE_DENY_EXACT = frozenset({
    "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/sudoers",
})
_FILE_DENY_PREFIX = ("/etc/sudoers.d/", "/proc/", "/sys/", "/dev/")
_FILE_DENY_NAMES = frozenset({
    "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
})
_FILE_DENY_SUFFIX = (".pem", ".key", ".pfx", ".p12")


def validate_remote_file_path(path: str) -> str:
    """Validate a path on a remote host; return it normalized."""
    if "\x00" in path:
        raise PermissionError("Null byte in path")
    if not path.startswith("/"):
        raise ValueError("Path must be absolute")

    parts = PurePosixPath(path).parts
    if ".." in parts:
        raise PermissionError("Path traversal not allowed")

    normalized = str(PurePosixPath(path))
    name = PurePosixPath(normalized).name

    if normalized in _FILE_DENY_EXACT or name in _FILE_DENY_NAMES:
        raise PermissionError(f"Refusing to touch credential file: {path}")
    if name.endswith(_FILE_DENY_SUFFIX):
        raise PermissionError(f"Refusing to touch key material: {path}")
    if normalized.startswith(_FILE_DENY_PREFIX):
        raise PermissionError(f"Path not allowed: {path}")
    return normalized


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

_DB_COMMENT_PATTERNS = [
    re.compile(r'/\*.*?\*/', re.DOTALL),
    re.compile(r'--[^\n]*'),
    re.compile(r'#[^\n]*'),
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

_DB_PRIV_PATTERNS = re.compile(
    r'\b(CREATE\s+USER|DROP\s+USER|ALTER\s+USER|'
    r'CREATE\s+ROLE|DROP\s+ROLE)\b', re.IGNORECASE
)

_DB_DANGER_PATTERNS = re.compile(
    r'\b(INTO\s+(OUT|DUMP)FILE|LOAD_FILE|lo_import|lo_export|'
    r'pg_read_file|pg_write_file|COPY\b)', re.IGNORECASE
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
