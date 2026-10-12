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
    # -f floods, and so do -l (preload) and -i below 0.2 s as root.
    if not _flags_only(t, "ciIlmMpQsStTwWF", "fl", unsafe_long=("flood", "preload")):
        return False
    for i, tok in enumerate(t):
        if tok.startswith("-") and not tok.startswith("--") and "i" in tok[1:]:
            j = tok.index("i")
            val = tok[j + 1:] or (t[i + 1] if i + 1 < len(t) else "")
            try:
                if float(val) < 0.2:
                    return False
            except ValueError:
                return False
    return True


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
                       "cursor-file",  # writes the last cursor into the file it names
                       "image")  # mounts a disk image


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
_CURL_SINKS = ("/dev/null", "-")
_CURL_HTTP_URL = re.compile(r"^https?:/", re.I)
# Long options are checked against what is known to be a read, not against a list of
# writes: curl 8.3+ takes '--expand-<any option>', 8.12 added '--ssl-sessions FILE', and
# curl 7.x takes any unambiguous prefix ('--max-ti'). Each of those was a way around a
# deny-list (third pass, 12.10.2026), so an unknown name asks.
_CURL_VALUE_LONG = {"proxy", "preproxy", "socks4", "socks4a", "socks5", "socks5-hostname", "doh-url",
                    "max-time", "connect-timeout", "resolve", "connect-to", "header", "user-agent",
                    "user", "referer", "retry", "retry-delay", "retry-max-time", "limit-rate", "range",
                    "cacert", "capath", "cert", "cert-type", "key", "key-type", "interface",
                    "oauth2-bearer", "noproxy", "proxy-user", "ciphers", "tls13-ciphers", "curves",
                    "cookie", "expect100-timeout", "keepalive-time", "dns-servers", "local-port",
                    "speed-limit", "speed-time", "max-filesize", "max-redirs", "tls-max", "proto",
                    "happy-eyeballs-timeout-ms", "ip-tos", "time-cond", "url-query",
                    "aws-sigv4", "pinnedpubkey", "proxy-cacert", "proxy-header"}
_CURL_FLAG_LONG = {"silent", "show-error", "fail", "fail-with-body", "fail-early", "location",
                   "location-trusted", "insecure", "head", "include", "show-headers", "verbose",
                   "compressed", "http1.0", "http1.1", "http2", "http2-prior-knowledge", "http3",
                   "http3-only", "ipv4", "ipv6", "globoff", "keepalive", "buffer", "progress-meter",
                   "progress-bar", "path-as-is", "raw", "tcp-nodelay", "tlsv1", "tlsv1.0", "tlsv1.1",
                   "tlsv1.2", "tlsv1.3", "ssl-no-revoke", "ssl-revoke-best-effort", "cert-status",
                   "alpn", "npn", "sessionid", "digest", "basic", "ntlm", "negotiate", "anyauth",
                   "retry-all-errors", "retry-connrefused", "ca-native", "proxy-insecure",
                   "proxytunnel", "suppress-connect-headers", "tr-encoding", "disable",
                   "disallow-username-in-url", "trace-time", "help", "version", "get", "ssl",
                   "ssl-reqd", "netrc", "netrc-optional"}
# With no scheme curl picks the protocol from the host name: 'dict.x:6379/info' is DICT,
# and '--resolve dict.x:6379:127.0.0.1' points it at a local redis (curl 8.10, stand).
_CURL_GUESSED_HOSTS = ("ftp.", "dict.", "ldap.", "imap.", "smtp.", "pop3.")


def _curl_value_ok(name: str, val: str) -> bool:
    # '@FILE' sends a local file: '-H @/etc/shadow' puts its lines into headers for any
    # host, '--url-query a@FILE' into the query string, and a '-b' value without '='
    # names a cookie file. '--proto-redir' is not allowed at all: with -L it lets a
    # remote redirect reach dict:// or gopher:// on the server itself.
    if name in ("header", "proxy-header") and val.startswith("@"):
        return False
    if name == "url-query" and "@" in val:
        return False
    if name == "cookie" and "=" not in val:
        return False
    return True


def _curl_target_ok(tok: str) -> bool:
    # dict:// and gopher:// send raw bytes to local services (redis FLUSHALL), and a
    # glob like '{dict,http}://' hides the scheme: only http(s), or no scheme with a
    # host curl will not read as another protocol and no glob that could build one.
    if ":/" in tok:
        # curl 8.10 also reads 'dict:/127.0.0.1:6379' (one slash) as DICT
        return bool(_CURL_HTTP_URL.match(tok))
    host = tok.split("/", 1)[0].rsplit("@", 1)[-1].lower()
    return not host.startswith(_CURL_GUESSED_HOSTS) and not any(ch in tok for ch in "{[")


def _curl_write_out_safe(fmt: str) -> bool:
    # Since curl 8.3 '%output{FILE}' sends the rest of the write-out to a file, and
    # '@FILE' reads the format from a file we cannot see.
    return "%output{" not in fmt and not fmt.startswith("@")


def curl_safe(t):
    if any("\n" in tok or "\r" in tok for tok in t):
        return False  # a line break in a header or target writes a second request line
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
            elif name == "url":
                if has_val:
                    return False  # curl rejects '--url=', so do not guess what it would do
                val, i = _value(t, i, "")
                if not _curl_target_ok(val):
                    return False
            elif name in _CURL_VALUE_LONG:
                if not has_val:
                    val, i = _value(t, i, "")
                if not _curl_value_ok(name, val):
                    return False
            elif not (name in _CURL_FLAG_LONG or (name.startswith("no-") and name[3:] in _CURL_FLAG_LONG)):
                return False  # unknown, abbreviated or '--expand-...': ask
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
                    if ch in "Hb" and not _curl_value_ok("header" if ch == "H" else "cookie", val):
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


def compose_config_writes(args) -> bool:
    """'docker compose config -o FILE' writes the rendered project to FILE (pflag: no
    abbreviations, but short options cluster: '-qo FILE')."""
    for tok in args:
        if tok.startswith("--"):
            name = tok[2:].split("=", 1)[0]
            if name and "output".startswith(name):
                return True
        elif tok.startswith("-") and "o" in tok[1:]:
            return True
    return False


def docker_compose_config_safe(t):
    return not compose_config_writes(t[3:])


CHECKS = {
    "command": command_safe, "ifconfig": ifconfig_safe, "hostname": hostname_safe,
    "date": date_safe, "dmesg": dmesg_safe, "ss": ss_safe, "sort": sort_safe, "uniq": uniq_safe,
    "tree": tree_safe, "ping": ping_safe, "file": file_safe, "timedatectl": timedatectl_safe,
    "find": find_safe, "dpkg": dpkg_safe, "journalctl": journalctl_safe, "ip": ip_safe,
    "curl": curl_safe, "sed": sed_safe,
}
