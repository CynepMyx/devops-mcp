import os

import httpx

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://host.docker.internal:9090")


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
    query = args.get("query")
    if not query:
        raise ValueError("query is required")

    start = args.get("start")
    end = args.get("end")

    if start and end:
        params = {
            "query": query,
            "start": start,
            "end": end,
            "step": args.get("step", "60"),
        }
        return await _api("/api/v1/query_range", params)
    else:
        params = {"query": query}
        if "time" in args:
            params["time"] = args["time"]
        return await _api("/api/v1/query", params)


async def prometheus_targets(args: dict) -> dict:
    state = args.get("state", "any")
    return await _api("/api/v1/targets", {"state": state})
