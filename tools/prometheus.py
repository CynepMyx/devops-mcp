import ipaddress
import logging
import os
import re
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://host.docker.internal:9090")

_ALLOWED_STATES = frozenset({"active", "dropped", "any"})
_STEP_RE = re.compile(r'^\d+[smhdw]?$')


def _is_internal_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_private
    except ValueError:
        # Hostname — allow single-label or known internal suffixes
        return "." not in host or host.endswith(".internal") or host.endswith(".local")


if not _is_internal_url(PROMETHEUS_URL):
    log.warning(
        "PROMETHEUS_URL %r does not appear to be an internal address — "
        "set it to a localhost or private network address to prevent SSRF.",
        PROMETHEUS_URL,
    )


async def _api(path: str, params: dict) -> dict:
    url = PROMETHEUS_URL + path
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
    if data.get("status") != "success":
        raise RuntimeError(f"Prometheus error: {data.get('error', 'unknown')}")
    return data["data"]


async def prometheus_query(args: dict) -> dict:
    query = args.get("query", "").strip()
    if not query:
        return {"error": "query is required"}
    if len(query) > 2000:
        return {"error": "query too long (max 2000 chars)"}

    start = args.get("start")
    end = args.get("end")
    step = str(args.get("step", "60"))

    if not _STEP_RE.match(step):
        return {"error": f"Invalid step value: {step!r}. Use a number optionally followed by s/m/h/d/w."}

    try:
        if start and end:
            params = {"query": query, "start": start, "end": end, "step": step}
            return await _api("/api/v1/query_range", params)
        else:
            params = {"query": query}
            if "time" in args:
                params["time"] = args["time"]
            return await _api("/api/v1/query", params)
    except Exception as e:
        return {"error": f"Prometheus request failed: {e}"}


async def prometheus_targets(args: dict) -> dict:
    state = args.get("state", "any")
    if state not in _ALLOWED_STATES:
        return {"error": f"state must be one of: {sorted(_ALLOWED_STATES)}"}
    try:
        return await _api("/api/v1/targets", {"state": state})
    except Exception as e:
        return {"error": f"Prometheus request failed: {e}"}
