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


_DANGER_PREFIXES = (
    "rm ", "reboot", "shutdown", "halt", "poweroff",
    "apt install", "apt remove", "apt purge", "apt upgrade",
    "useradd", "userdel", "usermod", "passwd",
    "chmod", "chown", "kill ", "killall", "pkill",
    "dd ", "mkfs", "fdisk",
    "systemctl start", "systemctl stop", "systemctl restart",
    "systemctl enable", "systemctl disable",
    "crontab -r", "iptables -F", "iptables -D", "iptables -A",
    "bash -c", "sh -c", "python3 -c", "python -c", "perl -e",
)

# Only block true injection patterns (command substitution).
# Shell operators &&, ;, || are legitimate and allowed — the remote shell
# interprets them naturally.
_SHELL_INJECTION_PATTERNS = ("$(", "`")


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


def validate_ssh_command(command: str, confirmed: bool) -> None:
    if len(command) > 500:
        raise ValueError("Command exceeds maximum length of 500 characters")
    for pattern in _SHELL_INJECTION_PATTERNS:
        if pattern in command:
            raise ValueError(f"Shell injection pattern detected: {pattern!r}")
    # Block any output redirect (> or >>) regardless of target path
    if re.search(r'>{1,2}\s*\S', command):
        raise ValueError("Output redirection is not allowed")
    cmd_lower = command.strip().lower()
    for prefix in _DANGER_PREFIXES:
        token = prefix.strip()
        # Match at command start or after shell word separators — catches `sudo rm`, `env rm`, etc.
        if re.search(r'(?:^|[\s|;&])' + re.escape(token) + r'(?:\s|$)', cmd_lower):
            if not confirmed:
                raise ValueError(
                    f"Dangerous command '{token}'. "
                    "Repeat with confirmed=true after user approval."
                )
            return


def validate_host_port(host: str, port: int) -> None:
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        raise ValueError(f"Invalid hostname format: {host}")
    if len(host) > 253:
        raise ValueError("Hostname too long")
    if port not in ALLOWED_PORTS:
        raise PermissionError(f"Port {port} not in allowlist: {sorted(ALLOWED_PORTS)}")
