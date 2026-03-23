import asyncio
import ssl
import socket
from datetime import datetime, timezone

from security import validate_host_port


def _do_tls_check(host: str, port: int, timeout: int) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            tls_version = ssock.version()

    not_after_str = cert["notAfter"]
    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days

    subject = dict(x[0] for x in cert["subject"])
    issuer = dict(x[0] for x in cert["issuer"])
    san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    return {
        "host": host,
        "port": port,
        "valid": days_left > 0,
        "days_remaining": days_left,
        "expires": not_after.isoformat(),
        "cn": subject.get("commonName"),
        "san": san,
        "issuer_org": issuer.get("organizationName"),
        "issuer_cn": issuer.get("commonName"),
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
    }


async def check_tls(args: dict) -> dict:
    host = args.get("host", "").strip()
    port = int(args.get("port", 443))
    timeout = min(int(args.get("timeout", 10)), 30)

    if not host:
        return {"error": "Parameter 'host' is required"}

    validate_host_port(host, port)

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_tls_check, host, port, timeout),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        return {"error": f"TLS check timed out after {timeout}s"}
    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}"}
    except OSError as e:
        return {"error": f"Connection error: {e}"}
