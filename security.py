import os
import fnmatch
import re
import shlex
from pathlib import Path, PurePosixPath

import command_args

KNOWN_HOSTS_PATH = os.environ.get("SSH_KNOWN_HOSTS", "/app/ssh/known_hosts")


def strict_host_key_default() -> bool:
    """Strict host key checking is on once there is something to check against.

    Defaulting to strict with an empty known_hosts would reject every host on a
    fresh install, so the file's existence is the switch. Set
    SSH_STRICT_HOST_KEY=false to force the old warn behaviour.
    """
    override = os.environ.get("SSH_STRICT_HOST_KEY")
    if override is not None:
        return override.lower() == "true"
    try:
        return os.path.getsize(KNOWN_HOSTS_PATH) > 0
    except OSError:
        return False

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
    # Hardware and capabilities
    "nproc", "arch", "lscpu", "lsmem", "lsusb", "lspci",
    # Path and text helpers that only read what they are given
    "basename", "dirname", "readlink", "realpath", "nl", "rev", "column",
    "md5sum", "sha1sum", "sha256sum", "cksum", "cmp", "diff",
    # Process lookup
    "pgrep", "pidof",
    # Package and locale queries with no mutating form
    "dpkg-query", "apt-cache", "getent", "locale", "getconf",
    # Answering "is this installed at all"
    "command",
    # Changing directory decides nothing on its own: 'cd /etc && cat hosts' is
    # still just a read, and 'cd /etc && rm -rf x' is still judged by the rm.
    "cd", "pushd", "popd",
})

# For these commands flags and scripts decide between a read and a write:
# 'sed -ni', 'curl -XPOST', 'ip l s eth0 down', 'git -c core.fsmonitor=...'.
# The words are parsed per command in command_args.py. The substring search that
# was here missed glued short options, GNU abbreviations and tabs (audit 12.10.2026).
# wget is off the list: it writes a file by default, so it always asks.
# awk is excluded entirely (its program text can contain system() calls).
_ARG_CHECKS = command_args.CHECKS

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
    # git — inspection only. push, pull, fetch, reset, clean, checkout, commit
    # and gc are deliberately absent: they rewrite the working tree, the
    # history or the remote.
    "git log", "git status", "git show", "git diff", "git branch",
    "git tag", "git remote", "git describe", "git blame", "git shortlog",
    "git rev-parse", "git ls-files", "git ls-remote", "git cat-file",
    "git for-each-ref", "git reflog", "git count-objects",
    # apt queries that never touch the package database
    "apt list", "apt show", "apt policy", "apt search",
    # systemd inspection beyond plain status
    "systemctl cat", "systemctl list-timers", "systemctl list-sockets",
    "systemctl list-unit-files", "systemctl get-default",
})

# Three-word prefixes, for subcommands whose parent is too broad to allow wholesale.
_SAFE_THREE_WORD = frozenset({
    "docker network ls", "docker network inspect",
    "docker volume ls", "docker volume inspect",
    "docker image ls", "docker image inspect",
    "docker container ls", "docker container inspect",
    "docker compose ps", "docker compose config",
    # 'git config key value' writes to the config file, so only reads pass here.
    "git config --get", "git config --list", "git config -l",
    # 'git stash' on its own stashes the working tree; listing does not.
    "git stash list",
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


# git takes its global options before the subcommand, so 'git -C /srv/app log'
# has '-C' where the allowlist expects 'log'. -C and --git-dir only say which
# repository, so they are stripped to find the subcommand. -c and --exec-path are
# refused before that (command_args.git_safe): core.fsmonitor, core.pager,
# diff.external and core.sshCommand all name programs git will run.
_GIT_GLOBAL_WITH_VALUE = command_args.GIT_GLOBAL_WITH_VALUE
_GIT_GLOBAL_FLAGS = command_args.GIT_GLOBAL_FLAGS


def _strip_git_globals(tokens: list[str]) -> list[str]:
    """Drop git's global options so the subcommand lands where checks look for it."""
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in _GIT_GLOBAL_WITH_VALUE:
            i += 2  # the option and its value
        elif tok in _GIT_GLOBAL_FLAGS or any(
            tok.startswith(opt + "=") for opt in _GIT_GLOBAL_WITH_VALUE
        ):
            i += 1
        else:
            break
    return tokens[:1] + tokens[i:]


def _tokens(cmd: str) -> list[str]:
    """Shell words of one sub-command, quotes removed, tabs split like spaces.

    Harmless redirects ('2>/dev/null', '2>&1') are blanked where the quote mask
    sees them, before splitting. Deciding by the shape of a word after the quotes
    were gone let "curl '>' -XPOST ..." swallow the -XPOST (audit 12.10.2026).
    Redirects that write a file never get here: _writes_to_file refuses them.
    """
    mask, _ = _mask_quotes(cmd)
    blanked = _blank_harmless_redirects(mask)
    cleaned = "".join(" " if b == " " and m != " " else c for c, m, b in zip(cmd, mask, blanked))
    try:
        return shlex.split(cleaned, posix=True)
    except ValueError:
        return cleaned.split()


def _is_subcommand_safe(cmd: str) -> bool:
    """Return True if a single shell command (no operators) is read-only safe."""
    tokens = _tokens(cmd.strip())
    if not tokens:
        return True
    first = tokens[0].lower()

    if first == "git":
        if not command_args.git_safe(tokens):
            return False
        tokens = _strip_git_globals(tokens)

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

    # Commands whose flags decide: parsed, not searched.
    if first in _ARG_CHECKS:
        return _ARG_CHECKS[first](tokens)

    # Unconditionally safe single-word commands
    if first in _SAFE_SINGLE:
        return True

    return False


def parse_jump(args: dict, allow_password: bool, strict_default: bool = False) -> dict | None:
    """Read jump_* parameters into the shape ssh_pool expects, or None.

    A jump host only carries bytes: the connection to the target is negotiated
    end to end inside the tunnel. That is the whole reason to prefer it over
    running ssh or sshpass as a command on the intermediate box, where the
    target's password ends up in the process list.
    """
    host = (args.get("jump_host") or "").strip()
    if not host:
        return None

    user = (args.get("jump_user") or "").strip()
    key_path = (args.get("jump_key") or "").strip()
    password = (args.get("jump_password") or "").strip()

    if not user:
        raise ValueError("jump_host was given without jump_user")
    if password and not allow_password:
        raise PermissionError(
            "Password authentication is disabled. Set ALLOW_SSH_PASSWORD=true to enable."
        )
    if not key_path and not password:
        raise ValueError("jump_host needs jump_key or jump_password")
    if key_path:
        validate_ssh_key_path(key_path)

    return {
        "host": host,
        "user": user,
        "key": key_path,
        "password": password,
        "port": int(args.get("jump_port", 22)),
        "verify_host_key": bool(args.get("verify_host_key", strict_default)),
    }


def is_read_only_command(command: str) -> bool:
    """True when every sub-command is in the read-only allowlist.

    Used to decide whether a command may be retried after the connection died
    mid-flight. Reading twice costs nothing; 'apt install' or 'sed -i' running
    a second time because we could not tell whether the first one landed is a
    different matter.
    """
    try:
        _, has_substitution = _mask_quotes(command)
        if has_substitution:
            return False
        return all(_is_subcommand_safe(sc) for sc in _split_shell_commands(command)
                   if sc.strip())
    except Exception:
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


# Redirections that neither create nor truncate anything: merging one descriptor
# into another (2>&1, 1>&2) and discarding output (>/dev/null, 2>/dev/null,
# &>/dev/null). Anything else that redirects is treated as a write to a file.
_HARMLESS_REDIRECT_RE = re.compile(r'(?:\d*|&)>{1,2}\s*(?:&\s*\d+|/dev/null)')


def _blank_harmless_redirects(mask: str) -> str:
    """Blank out redirections that neither write nor start a new command.

    Replaces each match with spaces of the same length, so positions in the
    mask still line up with the original command and callers can keep slicing
    by them. This also takes the '&' in '2>&1' out of the way of the operator
    scanner, which would otherwise read it as "background this and run '1'".
    """
    return _HARMLESS_REDIRECT_RE.sub(lambda m: ' ' * len(m.group(0)), mask)


def _writes_to_file(mask: str) -> bool:
    """True when the command redirects output into a file.

    The harmless forms are blanked out first, so whatever redirect is left has
    a real target. Takes the quote mask, so an angle bracket inside quoted data
    was already replaced and cannot reach here.
    """
    return bool(re.search(r'>{1,2}\s*\S', _blank_harmless_redirects(mask)))


# Command separators. Order matters: || and && must match before the single-char
# class, otherwise '&&' would be split as two '&'. A bare '&' backgrounds the left
# side and runs the rest, and a newline separates commands just like ';' — both
# were missing and let 'uptime\nrm -rf /tmp/x' through with only 'uptime' inspected.
_OPERATOR_RE = re.compile(r'\|\||&&|[|;&\n\r]')


def _split_shell_commands(command: str) -> list[str]:
    """Split a command into sub-commands by shell operators, ignoring quoted text.

    Operators are located in the masked copy, so a semicolon inside an nginx
    config snippet or a pipe inside a grep pattern no longer splits anything.
    Harmless redirects are blanked out first for the same reason: the '&' in
    '2>&1' is part of a redirect, not a command separator.
    """
    mask, _ = _mask_quotes(command)
    mask = _blank_harmless_redirects(mask)
    parts: list[str] = []
    start = 0
    for m in _OPERATOR_RE.finditer(mask):
        parts.append(command[start:m.start()])
        start = m.end()
    parts.append(command[start:])
    return parts


# ---------------------------------------------------------------------------
# Hard denials: commands with no safe form, refused even with confirmed=true.
# Each entry is a real incident, not a guess:
#   find without -maxdepth walked a whole production disk (10.03.2026);
#   pkill -f matched its own command line and killed the session (04.10.2026);
#   rm -r on a top-level directory has no legitimate use through this tool.
#
# The check looks for the command *word* anywhere outside quotes, not just in
# first position, so wrappers (sudo, nice -n 10, timeout 5, xargs, busybox),
# absolute paths (/usr/bin/find) and chained prefixes cannot hide it. The price
# is that `echo find` is refused too; quote the word if it is data.
# ---------------------------------------------------------------------------

_PROTECTED_RM_TARGETS = frozenset({
    "/", "/bin", "/boot", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt",
    "/opt", "/root", "/sbin", "/srv", "/usr", "/var", "/var/lib", "/var/www",
})
_CMD_WORD_RE = re.compile(r"(?<![\w.-])(find|pkill|pgrep|rm)(?![\w.-])")
_GLOB_CHARS = set("*?[{")


def _long_opt(token: str, full: str) -> bool:
    """GNU getopt accepts any unambiguous abbreviation: --recurs == --recursive."""
    name = token.split("=", 1)[0]
    return name.startswith("--") and len(name) >= 4 and full.startswith(name)


def _short_flags(tokens: list[str]) -> str:
    return "".join(tok[1:] for tok in tokens if tok.startswith("-") and not tok.startswith("--"))


def _rm_target_reason(target: str) -> str | None:
    raw = target.strip("\"'")
    if not raw:
        return None
    if raw[0] in "~$":
        return f"rm -r on {raw} is refused: home directory or variable target"
    path = PurePosixPath(raw)
    norm = str(path) if raw.startswith("/") else None
    if norm is None:
        parts = path.parts
        if not parts or parts[0] in (".", "..") or ".." in parts:
            return f"rm -r on {raw} is refused: relative path through . or .."
        return None
    # PurePosixPath does not resolve '..'; do it by hand so /var/www/../.. is seen as /.
    resolved: list[str] = []
    for part in path.parts[1:]:
        if part == "..":
            if resolved:
                resolved.pop()
        elif part != ".":
            resolved.append(part)
    if resolved and resolved[-1] == "*":
        resolved.pop()
    norm = "/" + "/".join(resolved)
    if norm in _PROTECTED_RM_TARGETS:
        return f"rm -r on {norm} is refused regardless of confirmation"
    if any(ch in _GLOB_CHARS for ch in norm) and len(resolved) <= 2:
        return f"rm -r with a glob near the root ({norm}) is refused"
    return None


_INTERPRETER_RE = re.compile(r"(?<![\w.-])(bash|sh|zsh|dash|ksh|eval|su|ssh|xargs)(?![\w.-])")
_QUOTED_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_SPLIT_WORD_RE = re.compile(r"\w[\"']+\w")


_FIND_MAX_DEPTH = 8
_FIND_VALUE_OPTS = frozenset({
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-lname",
    "-ilname", "-newer", "-anewer", "-cnewer", "-user", "-group", "-uid", "-gid", "-perm", "-size",
    "-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin", "-type", "-xtype", "-fstype", "-printf",
    "-fprintf", "-fprint", "-fprint0", "-links", "-inum", "-samefile", "-used", "-context",
})
_FIND_ACTIONS = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir"})


def _find_reason(args: list[str], raw_args: list[str]) -> str | None:
    """-maxdepth must be an option of find itself, followed by a small number."""
    depth = None
    for i, tok in enumerate(args):
        if tok == "-maxdepth" and (i == 0 or args[i - 1] not in _FIND_VALUE_OPTS):
            if i + 1 < len(args) and args[i + 1].isdigit():
                depth = int(args[i + 1])
            break
    if depth is None:
        return "find without -maxdepth N is refused (unbounded walk, incident 10.03.2026)"
    if depth > _FIND_MAX_DEPTH:
        return f"find -maxdepth {depth} is refused: the limit is {_FIND_MAX_DEPTH}, narrow the start path instead"
    if any(a in _FIND_ACTIONS for a in args):
        starts = []
        for tok in raw_args:
            if tok.startswith(("-", "(", "!")):
                break
            starts.append(tok)
        for tok in starts:
            reason = _rm_target_reason(tok)
            if reason:
                return reason.replace("rm -r", "find -delete/-exec")
    return None


_DANGEROUS_NAMES = ("find", "pkill", "pgrep", "rm")
_WRAPPER_WORDS = frozenset({"sudo", "nice", "nohup", "time", "env", "command", "exec", "timeout", "ionice", "stdbuf"})
_BRACE_RE = re.compile(r"^(.*?)\{([^{}]*)\}(.*)$")
_VAR_DEFAULT_RE = re.compile(r"\$\{[^}]*?[:]?[-=+?]([^}]*)\}")


def _brace_variants(token: str) -> list[str]:
    """fi{n,}d -> ['find', 'fid'] (one level is enough: the shell's result is still a word)."""
    m = _BRACE_RE.match(token)
    if not m:
        return [token]
    pre, body, post = m.groups()
    out = []
    for alt in body.split(","):
        out.extend(_brace_variants(pre + alt + post))
    return out


def _command_name_variants(token: str) -> set[str]:
    """Spellings the shell could resolve to the same program name: quotes, $'..', \\, braces, ${x:-word}."""
    base = token.replace("\\", "")
    names = set()
    for m in _VAR_DEFAULT_RE.finditer(base):
        names.add(m.group(1).strip("\"'").rsplit("/", 1)[-1])
    variants = [base] if "${" in base else _brace_variants(base)
    for v in variants:
        v = v.replace("$'", "").replace("'", "").replace('"', "")
        names.add(v.rsplit("/", 1)[-1])
    return {n for n in names if n}


def _resolve_command_word(sub_command: str) -> str | None:
    """If the first word (after wrappers) is a disguised dangerous name, return the plain name."""
    tokens = sub_command.split()
    i = 0
    while i < len(tokens) and tokens[i].replace("\\", "").strip("\"'").lower() in _WRAPPER_WORDS:
        i += 1
        while i < len(tokens) and (tokens[i].startswith("-") or "=" in tokens[i] or tokens[i].isdigit()):
            i += 1
    if i >= len(tokens):
        return None
    for name in _command_name_variants(tokens[i]):
        for danger in _DANGEROUS_NAMES:
            if name == danger or (any(ch in name for ch in "*?[") and fnmatch.fnmatchcase(danger, name)):
                return danger
    return None


def _deny_in(raw: str, mask: str) -> str | None:
    """Scan one sub-command: raw text and its quote-masked copy of equal length."""
    for m in _CMD_WORD_RE.finditer(mask):
        word = m.group(1)
        args = mask[m.end():].split()
        raw_args = raw[m.end():].split()

        if word == "find":
            reason = _find_reason(args, raw_args)
            if reason:
                return reason

        elif word in ("pkill", "pgrep"):
            full_match = "f" in _short_flags(args) or any(_long_opt(a, "--full") for a in args)
            # Only the classic '[r]un' trick is accepted: a one-character class cannot match
            # the bracket in its own command line. '[^x]run' would.
            bracket_pattern = any(re.match(r"^\[\w\]", tok.lstrip("\"'")) for tok in raw_args)
            if full_match and not bracket_pattern:
                return (f"{word} -f is refused: it matches its own command line (incident 04.10.2026); "
                        "use a '[r]un-x' style pattern or kill by PID")

        elif word == "rm":
            recursive = "r" in _short_flags(args).lower() or any(_long_opt(a, "--recursive") for a in args)
            if recursive:
                after_dashdash = False
                for tok in raw_args:
                    if tok == "--":
                        after_dashdash = True
                        continue
                    if tok.startswith("-") and not after_dashdash:
                        continue
                    reason = _rm_target_reason(tok)
                    if reason:
                        return reason
    return None


def hard_deny_reason(sub_command: str) -> str | None:
    """Return why a single sub-command is refused outright, or None.

    Not a shell parser. It covers the spellings seen in practice and the cheap
    disguises (wrappers, abbreviations, backslashes, split quotes, quoted
    payloads handed to sh -c / eval / ssh); a variable that expands to the word,
    or base64 piped into a shell, is for the allowlist and confirmed=true to catch.
    """
    # The shell drops unquoted backslashes: f\ind is find.
    text = sub_command.replace("\\", "")
    mask, _ = _mask_quotes(text)
    reason = _deny_in(text, mask)
    if reason:
        return reason

    # "find", $'find', fi{n,}d, /usr/bin/fin?, ${x:-find}: the first word rewritten the way the shell resolves it.
    plain = _resolve_command_word(text)
    if plain:
        tokens = text.split()
        k = next((j for j, tok in enumerate(tokens) if plain in _command_name_variants(tok)
                  or any(ch in tok for ch in "*?[")), 0)
        rebuilt = " ".join([plain] + tokens[k + 1:])
        reason = _deny_in(rebuilt, _mask_quotes(rebuilt)[0])
        if reason:
            return reason

    # f"i"nd and fi'n'd: fragments glued by quotes. Join them and look again,
    # but only when a quote sits between word characters, so grep "find /" stays data.
    if _SPLIT_WORD_RE.search(text):
        joined = text.replace("'", "").replace('"', "")
        reason = _deny_in(joined, joined)
        if reason:
            return reason

    # Quoted text handed to an interpreter is code, not data.
    if _INTERPRETER_RE.search(mask):
        for m in _QUOTED_RE.finditer(text):
            payload = m.group(1) if m.group(1) is not None else m.group(2)
            for sc in _split_shell_commands(payload):
                if sc.strip():
                    reason = hard_deny_reason(sc)
                    if reason:
                        return reason
    return None


_BRACKET_CHAR_RE = re.compile(r"\[(\w)\]")


def _pkill_self_match_reason(command: str) -> str | None:
    """'[s]leep 300' does not match its own text, but it matches 'sleep 300' written
    anywhere else in the same command line, and the shell running the command has that
    whole line in its argv. On the stand this killed the ssh session (12.10.2026)."""
    for sc in _split_shell_commands(command):
        words = _tokens(sc)
        for k, word in enumerate(words):
            if word.rsplit("/", 1)[-1] not in ("pkill", "pgrep"):
                continue
            args = words[k + 1:]
            full = "f" in _short_flags(args) or any(_long_opt(a, "--full") for a in args)
            if not full:
                continue
            for pattern in (a for a in args if not a.startswith("-")):
                literal = _BRACKET_CHAR_RE.sub(r"\1", pattern)
                if literal != pattern and literal in command:
                    return (f"{word} -f '{pattern}' is refused: '{literal}' also appears in this "
                            "command, so the pattern matches the shell running it; kill by PID")
    return None


def validate_ssh_command(command: str, confirmed: bool) -> None:
    if len(command) > 500:
        raise ValueError("Command exceeds maximum length of 500 characters")

    mask, has_substitution = _mask_quotes(command)

    # Block command substitution only where the shell would expand it.
    # Inside single quotes $( and ` are literal text, so config snippets pass.
    if has_substitution:
        raise ValueError("Shell injection pattern detected: command substitution")

    # Block output redirection, but only outside quotes: '<b>' in an alert body
    # or a ';' in an nginx directive are data, not syntax. Merging descriptors
    # and discarding output stay allowed: neither creates nor truncates a file,
    # and banning them only taught us to write '| wc -c' instead of '2>/dev/null'.
    if _writes_to_file(mask):
        raise ValueError("Output redirection to a file is not allowed")

    sub_commands = _split_shell_commands(command)

    # Hard denials come before the allowlist: these are refused with or without confirmed.
    for sc in sub_commands:
        reason = hard_deny_reason(sc)
        if reason:
            raise PermissionError(f"Refused: {reason}")
    reason = _pkill_self_match_reason(command)
    if reason:
        raise PermissionError(f"Refused: {reason}")
    # An interpreter anywhere in the pipeline turns every quoted string into code:
    # echo 'find /' | sh, printf ... | bash -s.
    if _INTERPRETER_RE.search(mask):
        for m in _QUOTED_RE.finditer(command):
            payload = m.group(1) if m.group(1) is not None else m.group(2)
            for sc in _split_shell_commands(payload):
                if sc.strip():
                    reason = hard_deny_reason(sc)
                    if reason:
                        raise PermissionError(f"Refused: {reason}")

    # Read-only allowlist check: every sub-command must be safe or confirmed required
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


# Commands file_put may run by itself to check what it just wrote. This is a
# short allowlist on purpose: the verification step fires automatically as part
# of a write, so it has to be a test, not a general shell. Anything else, run
# through ssh_exec where the user sees it as its own call.
_VERIFY_PREFIXES = (
    "nginx -t", "nginx -T", "/usr/sbin/nginx -t",
    "apachectl configtest", "apache2ctl configtest", "httpd -t", "apachectl -t",
    "sshd -t", "/usr/sbin/sshd -t",
    "php -l", "php-fpm -t", "php-fpm7", "php-fpm8",
    "named-checkconf", "named-checkzone",
    "haproxy -c", "postfix check", "postconf",
    "systemd-analyze verify",
    "docker compose config", "docker-compose config",
    "caddy validate", "traefik healthcheck",
    "nft -c -f", "iptables-restore -t", "ip6tables-restore -t",
    "python3 -m json.tool", "python -m json.tool",
    "jq ", "yq ",
    "visudo -c",
    "crontab -T",
    "wp config get",
)


def validate_verify_command(command: str) -> None:
    """Check a verification command before file_put runs it automatically."""
    stripped = command.strip()
    if not stripped:
        raise ValueError("Empty verify_cmd")
    if len(stripped) > 500:
        raise ValueError("verify_cmd exceeds maximum length of 500 characters")

    mask, has_substitution = _mask_quotes(stripped)
    if has_substitution:
        raise ValueError("Shell injection pattern detected in verify_cmd")
    if _OPERATOR_RE.search(mask) or re.search(r'>{1,2}\s*\S', mask):
        raise ValueError(
            "verify_cmd must be a single command without operators or redirects"
        )

    if not stripped.startswith(_VERIFY_PREFIXES):
        raise PermissionError(
            f"verify_cmd must be a config test. Allowed starts: "
            f"{', '.join(sorted(p.strip() for p in _VERIFY_PREFIXES)[:8])} and similar. "
            "For anything else use ssh_exec."
        )

    reason = _verify_args_reason(_tokens(stripped))
    if reason:
        raise PermissionError(f"verify_cmd {reason}. For anything else use ssh_exec.")


def _verify_args_reason(t: list[str]) -> str | None:
    """The prefix says which tool; its arguments decide whether it only tests.
    Each case here passed the prefix check and acted (audit 12.10.2026): wp --exec
    ran PHP, json.tool overwrote its second argument, postconf -e edited main.cf."""
    if not t:
        return None
    head = t[0].rsplit("/", 1)[-1]
    args = t[1:]
    if head == "postconf":
        if any("=" in a or (a.startswith("-") and a not in ("-n", "-d", "-h", "-x")) for a in args):
            return "may only read postconf (-n, -d, names); -e, -X, -M and assignments edit main.cf"
    elif head.startswith("php-fpm"):
        if not any(a in ("-t", "-tt", "--test") for a in args):
            return "must test php-fpm with -t; without it a second FPM master starts"
    elif head in ("python", "python3") and args[:2] == ["-m", "json.tool"]:
        if len([a for a in args[2:] if not a.startswith("-")]) > 1:
            return "may pass json.tool one file; the second one is overwritten"
    elif head == "yq":
        if any(a in ("-i", "--inplace") or (a.startswith("-") and not a.startswith("--") and "i" in a[1:])
               for a in args):
            return "may not edit in place (yq -i)"
    elif head == "wp":
        if any(a.split("=", 1)[0] in ("--exec", "--require", "--ssh", "--http", "--eval") for a in args):
            return "may not run PHP or reach another host through wp-cli global options"
    elif head == "nginx":
        if "-g" in args:
            return "may not add directives with nginx -g (load_module loads code during the test)"
    return None


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


# Called through SELECT, but they act: cut another session's connection, cancel its
# query, make the server reread its config. Not writes, so a read-only transaction
# lets them through; they need confirmation like any other action.
_DB_ACTION_FUNCTIONS = re.compile(
    r'\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_promote)\s*\(',
    re.IGNORECASE,
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
        action = _DB_ACTION_FUNCTIONS.search(cleaned)
        if action and not confirmed:
            raise ValueError(
                f"{action.group(1)}() acts on the server and requires confirmation. "
                "Repeat with confirmed=true after user approval."
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
