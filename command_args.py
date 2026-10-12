"""Argument checks for allowlisted commands.

The allowlist in security.py decides by the first word. For commands whose
flags or script can change the system that is not enough: 'sed -ni' rewrites a
file, 'git -c core.fsmonitor=...' runs a program, 'ip l s eth0 down' cuts the
link, 'curl -XPOST' talks to an API. Each check gets the shell words of one
sub-command (quotes already removed) and returns True only for a read.

Anything it cannot parse counts as not a read: the price is a confirmation
prompt, never a silent write. Verified against every ssh_exec command in the
audit log (12.10.2026) so that the reads actually used keep passing.
"""
import re

# git global options; security.py strips them to find the subcommand.
GIT_GLOBAL_WITH_VALUE = frozenset({
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
})
GIT_GLOBAL_FLAGS = frozenset({
    "--no-pager", "-P", "--paginate", "--bare", "--no-replace-objects",
    "--literal-pathspecs", "--no-optional-locks",
})


def _value(tokens: list[str], i: int, attached: str) -> tuple[str, int]:
    """Value of an option: glued to it ('-o/x') or the next word ('-o /x')."""
    if attached:
        return attached, i
    return (tokens[i + 1] if i + 1 < len(tokens) else ""), i + 1


def _long_name(tok: str) -> tuple[str, str, bool]:
    name, eq, val = tok[2:].partition("=")
    return name, val, bool(eq)


def _prefix_of_any(name: str, full_names) -> bool:
    """GNU getopt_long takes any unambiguous prefix of a long option: --rot is --rotate."""
    return bool(name) and any(full.startswith(name) for full in full_names)


def _short_cluster(tokens, i, value_opts, unsafe_opts):
    """Walk '-abc': False if an unsafe flag is in it, else the index of the last word used."""
    tok = tokens[i]
    for j in range(1, len(tok)):
        ch = tok[j]
        if ch in unsafe_opts:
            return False
        if ch in value_opts:
            _, i = _value(tokens, i, tok[j + 1:])
            break
    return i


def _flags_only(tokens, value_opts, unsafe_opts, unsafe_long=(), max_positional=None):
    """Generic check: no unsafe short/long option, optional limit on positional words."""
    positional = 0
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            positional += len(tokens) - i - 1
            break
        if tok.startswith("--") and len(tok) > 2:
            name, _, _ = _long_name(tok)
            if _prefix_of_any(name, unsafe_long):
                return False
        elif tok.startswith("-") and len(tok) > 1:
            res = _short_cluster(tokens, i, value_opts, unsafe_opts)
            if res is False:
                return False
            i = res
        else:
            positional += 1
        i += 1
    return max_positional is None or positional <= max_positional


# --- builtins and simple commands --------------------------------------------------------

def command_safe(t):
    # 'command -v x' answers "is it installed"; 'command x' runs x.
    return len(t) >= 2 and t[1] in ("-v", "-V")


def ifconfig_safe(t):
    # 'ifconfig' and 'ifconfig eth0' show; 'ifconfig eth0 down' or '... 10.0.0.1' change the link.
    return _flags_only(t, "", "", max_positional=1) and all(
        a in ("-a", "-s", "-v") for a in t[1:] if a.startswith("-"))


_HOSTNAME_READ = {"-a", "--alias", "-A", "--all-fqdns", "-d", "--domain", "-f", "--fqdn", "--long",
                  "-i", "--ip-address", "-I", "--all-ip-addresses", "-s", "--short", "-y", "--yp",
                  "--nis", "-v", "--verbose", "-V", "--version", "-h", "--help"}


def hostname_safe(t):
    # Any positional word or -F/-b sets the hostname.
    return all(a in _HOSTNAME_READ for a in t[1:])


def date_safe(t):
    # 'date -s ...' and 'date MMDDhhmm' set the clock; '+FORMAT' only formats.
    i = 1
    while i < len(t):
        tok = t[i]
        if tok.startswith("--") and len(tok) > 2:
            name, _, has_val = _long_name(tok)
            if _prefix_of_any(name, ("set",)):
                return False
            if not has_val and _prefix_of_any(name, ("date", "file", "reference")) and len(name) >= 2:
                i += 1
        elif tok.startswith("-") and len(tok) > 1:
            res = _short_cluster(t, i, "dfr", "s")
            if res is False:
                return False
            i = res
        elif not tok.startswith("+"):
            return False
        i += 1
    return True


def dmesg_safe(t):
    # -c/-C clear the ring buffer, -D/-E/-n change console logging.
    return _flags_only(t, "flsF", "cCDEn",
                       unsafe_long=("clear", "read-clear", "console-off", "console-on", "console-level"))


def ss_safe(t):
    # -K kills sockets, -D writes a diagnostic dump to a file.
    return _flags_only(t, "fAFN", "KD", unsafe_long=("kill", "diag"))


def sort_safe(t):
    # -o writes a file; --compress-program runs one.
    return _flags_only(t, "ktST", "o", unsafe_long=("output", "compress-program"))


def uniq_safe(t):
    # 'uniq in out' writes the second file.
    return _flags_only(t, "fsw", "", max_positional=1)


def tree_safe(t):
    # -o writes a file; -R writes 00Tree.html into every directory it walks.
    return _flags_only(t, "LPIHT", "oR", unsafe_long=("output",))


def ping_safe(t):
    # -f floods.
    return _flags_only(t, "ciIlmMpQsStTwWF", "f")


def file_safe(t):
    # -C compiles a magic file into the current directory.
    return _flags_only(t, "mefFP", "C", unsafe_long=("compile",))


def timedatectl_safe(t):
    positional = [a for a in t[1:] if not a.startswith("-")]
    return not positional or positional[0] in (
        "status", "show", "timesync-status", "show-timesync", "list-timezones")


_FIND_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir", "-delete",
                 "-fprint", "-fprintf", "-fprint0", "-fls"}


def find_safe(t):
    return not any(tok in _FIND_ACTIONS for tok in t[1:])


_DPKG_READ = {"-l", "--list", "-L", "--listfiles", "-s", "--status", "-S", "--search", "-p",
              "--print-avail", "--print-architecture", "--print-foreign-architectures",
              "--get-selections", "-V", "--verify", "-C", "--audit", "--compare-versions",
              "--help", "--version"}


def dpkg_safe(t):
    # Case matters: -p prints, -P purges. Only query actions pass.
    return all(tok.split("=", 1)[0] in _DPKG_READ for tok in t[1:] if tok.startswith("-"))


_JOURNALCTL_ACTIONS = ("rotate", "vacuum-size", "vacuum-files", "vacuum-time", "flush", "sync",
                       "relinquish-var", "smart-relinquish-var", "setup-keys", "update-catalog",
                       "cursor-file")  # writes the last cursor into the file it names


def journalctl_safe(t):
    for tok in t[1:]:
        if tok.startswith("--") and len(tok) > 2:
            name, _, _ = _long_name(tok)
            if _prefix_of_any(name, _JOURNALCTL_ACTIONS):
                return False
    return True


# --- ip ----------------------------------------------------------------------------------

_IP_VALUE_OPTS = ("family", "loops", "netns", "rcvbuf")
_IP_FLAG_OPTS = {"4", "6", "0", "B", "M", "s", "stats", "statistics", "d", "details", "r", "resolve",
                 "h", "human", "human-readable", "o", "oneline", "t", "timestamp", "ts", "tshort",
                 "br", "brief", "j", "json", "p", "pretty", "c", "color", "colour", "a", "all",
                 "N", "Numeric", "iec"}
_IP_READ_CMDS = ("show", "list", "lst", "get", "help")
_IP_WRITE_CMDS = ("set", "add", "del", "delete", "change", "chg", "replace", "append", "prepend",
                  "flush", "save", "restore", "exec", "attach", "update", "test")


def ip_safe(t):
    i = 1
    while i < len(t) and t[i].startswith("-"):
        opt = t[i].lstrip("-")
        name = opt.split("=", 1)[0]
        if name == "b" or name.startswith("ba"):
            return False  # -batch runs commands from a file
        if name in _IP_FLAG_OPTS:
            i += 1
        elif name and any(v.startswith(name) for v in _IP_VALUE_OPTS):
            # iproute2 takes any prefix: '-fam inet' is -family. Missing that let
            # 'ip -fam inet l s lo down' parse as object 'inet' and read 'l' (audit 12.10.2026).
            i += 2
        else:
            return False
    if i >= len(t):
        return True
    cmd = t[i + 1].lower() if i + 1 < len(t) else ""
    if not cmd:
        return True  # 'ip a', 'ip route': show by default
    # iproute2 accepts any prefix: 's' can mean set, 'sh' only show.
    reads = any(full.startswith(cmd) for full in _IP_READ_CMDS)
    writes = any(full.startswith(cmd) for full in _IP_WRITE_CMDS)
    return reads and not writes


# --- curl --------------------------------------------------------------------------------

_CURL_VALUE_SHORT = set("AbcCdDeEFHKmoPQrtTuUwxXyYz")
_CURL_UNSAFE_SHORT = set("dFTKcOQ")  # data, form, upload, config, cookie jar, remote name, ftp quote
_CURL_UNSAFE_LONG = {
    "data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "json", "form", "form-string",
    "upload-file", "remote-name", "remote-name-all", "remote-header-name", "cookie-jar", "trace",
    "trace-ascii", "stderr", "libcurl", "etag-save", "hsts", "alt-svc", "config", "create-dirs",
    "output-dir", "unix-socket", "abstract-unix-socket", "quote", "variable",
}
_CURL_SINKS = ("/dev/null", "-")
_CURL_HTTP_URL = re.compile(r"^https?://", re.I)
# Values of these options are not request targets, so they skip the URL check.
_CURL_VALUE_LONG = {"proxy", "preproxy", "socks4", "socks4a", "socks5", "socks5-hostname", "doh-url",
                    "max-time", "connect-timeout", "resolve", "connect-to", "header", "user-agent",
                    "user", "referer", "retry", "retry-delay", "retry-max-time", "limit-rate", "range",
                    "cacert", "cert", "key", "interface", "oauth2-bearer", "noproxy", "proxy-user",
                    "ciphers", "cookie", "expect100-timeout", "keepalive-time", "dns-servers",
                    "local-port", "speed-limit", "speed-time", "max-filesize", "max-redirs", "tls-max",
                    "proto", "proto-redir", "happy-eyeballs-timeout-ms", "ip-tos", "write-out"}


def _curl_target_ok(tok: str) -> bool:
    # dict:// and gopher:// send raw bytes to local services (redis FLUSHALL), and a
    # glob like '{dict,http}://' hides the scheme: only http(s) or no scheme at all.
    return "://" not in tok or bool(_CURL_HTTP_URL.match(tok))


def _curl_write_out_safe(fmt: str) -> bool:
    # Since curl 8.3 '%output{FILE}' sends the rest of the write-out to a file, and
    # '@FILE' reads the format from a file we cannot see.
    return "%output{" not in fmt and not fmt.startswith("@")


def curl_safe(t):
    i = 1
    while i < len(t):
        tok = t[i]
        if tok.startswith("--") and len(tok) > 2:
            name, val, has_val = _long_name(tok)
            if name in ("output", "dump-header", "request", "write-out"):
                if not has_val:
                    val, i = _value(t, i, "")
                if name == "request" and val.upper() not in ("GET", "HEAD"):
                    return False
                if name in ("output", "dump-header") and val not in _CURL_SINKS:
                    return False
                if name == "write-out" and not _curl_write_out_safe(val):
                    return False
            elif name in ("proto-default", "url"):
                if name == "proto-default" or has_val:
                    return False  # switches the scheme of every bare URL / curl rejects '='
                val, i = _value(t, i, "")
                if not _curl_target_ok(val):
                    return False
            elif name != "cookie" and _prefix_of_any(name, _CURL_UNSAFE_LONG | {
                    "output", "dump-header", "request", "write-out"}):
                return False  # an abbreviation, or a name we do not handle: ask
            elif name in _CURL_VALUE_LONG and not has_val:
                i += 1
        elif tok.startswith("-") and len(tok) > 1:
            for j in range(1, len(tok)):
                ch = tok[j]
                if ch in _CURL_UNSAFE_SHORT:
                    return False
                if ch in _CURL_VALUE_SHORT:
                    val, i = _value(t, i, tok[j + 1:])
                    if ch in "oD" and val not in _CURL_SINKS:
                        return False
                    if ch == "X" and val.upper() not in ("GET", "HEAD"):
                        return False
                    if ch == "w" and not _curl_write_out_safe(val):
                        return False
                    break
        elif not _curl_target_ok(tok):
            return False
        i += 1
    return True


# --- sed ---------------------------------------------------------------------------------

def sed_safe(t):
    scripts: list[str] = []
    positional: list[str] = []
    from_e = False
    i = 1
    while i < len(t):
        tok = t[i]
        if tok == "--":
            positional += t[i + 1:]
            break
        if tok.startswith("--") and len(tok) > 2:
            name, val, has_val = _long_name(tok)
            # getopt_long takes any unambiguous prefix: '--e' is --expression, '--l' is
            # --line-length (its value must not be mistaken for the script).
            if "in-place".startswith(name):
                return False
            if "file".startswith(name):
                return False  # script from a file: cannot see what it does
            if "expression".startswith(name):
                if not has_val:
                    val, i = _value(t, i, "")
                scripts.append(val)
                from_e = True
            elif "line-length".startswith(name) and not has_val:
                i += 1
        elif tok.startswith("-") and len(tok) > 1:
            for j in range(1, len(tok)):
                ch = tok[j]
                if ch == "i":
                    return False
                if ch in "efl":
                    val, i = _value(t, i, tok[j + 1:])
                    if ch == "f":
                        return False
                    if ch == "e":
                        scripts.append(val)
                        from_e = True
                    break
        else:
            positional.append(tok)
        i += 1
    if not from_e:
        if not positional:
            return False
        scripts.append(positional[0])
    return all(_sed_script_safe(s) for s in scripts)


def _sed_skip_regex(s: str, i: int, delim: str) -> int | None:
    """i points just past the opening delimiter; return the index past the closing one."""
    n = len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == delim:
            return i + 1
        if s[i] == "\n":
            return None
        i += 1
    return None


def _sed_skip_address(s: str, i: int) -> int | None:
    n = len(s)
    if i < n and s[i].isdigit():
        while i < n and (s[i].isdigit() or s[i] == "~"):
            i += 1
    elif i < n and s[i] == "$":
        i += 1
    elif i < n and s[i] == "/":
        i = _sed_skip_regex(s, i + 1, "/")
        if i is None:
            return None
        while i < n and s[i] in "IM":
            i += 1
    elif i + 1 < n and s[i] == "\\":
        delim = s[i + 1]
        i = _sed_skip_regex(s, i + 2, delim)
        if i is None:
            return None
        while i < n and s[i] in "IM":
            i += 1
    return i


def _sed_script_safe(s: str) -> bool:
    """Walk a sed script; False on e/w/W commands or e/w flags of s///, and on anything unknown."""
    n = len(s)
    i = 0

    def skip_blank(k):
        while k < n and s[k] in " \t":
            k += 1
        return k

    while i < n:
        if s[i] in " \t\n;{}":
            i += 1
            continue
        if s[i] == "#":
            while i < n and s[i] != "\n":
                i += 1
            continue
        start = i
        i = _sed_skip_address(s, i)
        if i is None:
            return False
        i = skip_blank(i)
        if i > start and i < n and s[i] == ",":
            i = skip_blank(i + 1)
            if i < n and s[i] in "+~":
                i += 1
                while i < n and s[i].isdigit():
                    i += 1
            else:
                i = _sed_skip_address(s, i)
                if i is None:
                    return False
            i = skip_blank(i)
        if i < n and s[i] == "!":
            i = skip_blank(i + 1)
        if i >= n:
            return False
        c = s[i]
        if c in "ewW":
            return False
        if c in "pPdDnNgGhHxzF={":
            i += 1
        elif c in "qQlL":
            i += 1
            while i < n and s[i].isdigit():
                i += 1
        elif c in "bBtTv:":
            # GNU sed ends a label (and the version of 'v') at ';' or a blank:
            # ':a;e id' is a label, then 'e id' (audit 12.10.2026).
            i = skip_blank(i + 1)
            while i < n and s[i] not in "; \t\n}":
                i += 1
        elif c in "rRaic":
            # file to read or text to insert: to the end of the line
            while i < n and s[i] != "\n":
                i += 1
        elif c in "sy":
            if i + 1 >= n or s[i + 1] in "\\\n":
                return False
            delim = s[i + 1]
            i = _sed_skip_regex(s, i + 2, delim)
            if i is None:
                return False
            i = _sed_skip_regex(s, i, delim)
            if i is None:
                return False
            if c == "s":
                while i < n and (s[i] in "gpiImM" or s[i].isdigit()):
                    i += 1
                if i < n and s[i] in "ew":
                    return False
        else:
            return False
    return True


# --- git ---------------------------------------------------------------------------------

_BRANCH_CHANGE = {"-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy", "-u",
                  "--set-upstream-to", "--unset-upstream", "--edit-description", "-f", "--force",
                  "--track", "--no-track", "--create-reflog", "--recurse-submodules"}
_BRANCH_LIST = {"-l", "--list", "-a", "--all", "-r", "--remotes", "--contains", "--no-contains",
                "--merged", "--no-merged", "--points-at", "--show-current", "-v", "-vv", "--verbose"}
_BRANCH_VALUE = {"--contains", "--no-contains", "--merged", "--no-merged", "--points-at",
                 "--format", "--sort", "--abbrev", "--column"}

_TAG_CHANGE = {"-d", "--delete", "-a", "--annotate", "-s", "--sign", "-u", "--local-user", "-m",
               "--message", "-F", "--file", "-f", "--force", "-e", "--edit", "--create-reflog",
               "--cleanup"}
_TAG_LIST = {"-l", "--list", "--contains", "--no-contains", "--points-at", "--merged",
             "--no-merged", "--sort", "--format", "--column"}


def _list_or_create(rest, change, list_mode_opts, value_opts, cluster_change):
    """git branch/tag: a name without a listing option creates; change options always change."""
    list_mode = False
    positional = 0
    i = 0
    while i < len(rest):
        tok = rest[i]
        name = tok.split("=", 1)[0]
        if name in change or (name.startswith("--") and _prefix_of_any(
                name[2:], [o[2:] for o in change if o.startswith("--")])):
            return False
        if tok.startswith("-") and not tok.startswith("--") and any(c in cluster_change for c in tok[1:]):
            return False
        if name in list_mode_opts or (tok.startswith("-n") and list_mode_opts is _TAG_LIST):
            list_mode = True
        if name in value_opts and "=" not in tok and i + 1 < len(rest) and not rest[i + 1].startswith("-"):
            i += 1
        elif not tok.startswith("-"):
            positional += 1
        i += 1
    return positional == 0 or list_mode


def git_safe(t):
    i = 1
    while i < len(t):
        tok = t[i]
        # -c and --config-env set config for this run: core.fsmonitor, core.pager,
        # diff.external and core.sshCommand all name programs to execute.
        if tok in ("-c", "--config-env") or tok.startswith(("--config-env=", "--exec-path")):
            return False
        if tok in GIT_GLOBAL_WITH_VALUE:
            i += 2
        elif tok in GIT_GLOBAL_FLAGS or any(tok.startswith(o + "=") for o in GIT_GLOBAL_WITH_VALUE):
            i += 1
        else:
            break
    if i >= len(t):
        return True
    sub, rest = t[i], t[i + 1:]
    for tok in rest:
        if "ext::" in tok:
            return False  # ext:: transport runs a command
        if tok.startswith("--") and _prefix_of_any(tok[2:].split("=", 1)[0],
                                                   ("output", "upload-pack", "receive-pack", "exec")):
            return False
    if sub == "ls-remote" and "-u" in rest:
        return False
    if sub == "branch":
        return _list_or_create(rest, _BRANCH_CHANGE, _BRANCH_LIST, _BRANCH_VALUE, "dDmMcCuf")
    if sub == "tag":
        return _list_or_create(rest, _TAG_CHANGE, _TAG_LIST, {"--contains", "--no-contains",
                                                              "--points-at", "--merged", "--no-merged",
                                                              "--sort", "--format", "--column"},
                               "dasumFfe")
    if sub == "remote":
        positional = [a for a in rest if not a.startswith("-")]
        if any(a not in ("-v", "--verbose", "-n", "--push", "--all") for a in rest if a.startswith("-")):
            return False
        return not positional or positional[0] in ("show", "get-url")
    if sub == "reflog":
        positional = [a for a in rest if not a.startswith("-")]
        return not positional or positional[0] not in ("expire", "delete", "drop", "write")
    return True


CHECKS = {
    "command": command_safe, "ifconfig": ifconfig_safe, "hostname": hostname_safe,
    "date": date_safe, "dmesg": dmesg_safe, "ss": ss_safe, "sort": sort_safe, "uniq": uniq_safe,
    "tree": tree_safe, "ping": ping_safe, "file": file_safe, "timedatectl": timedatectl_safe,
    "find": find_safe, "dpkg": dpkg_safe, "journalctl": journalctl_safe, "ip": ip_safe,
    "curl": curl_safe, "sed": sed_safe,
}
