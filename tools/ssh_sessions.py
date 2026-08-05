"""Inspect and close the pooled SSH connections."""
import asyncio

from tools import ssh_pool


async def ssh_sessions(args: dict) -> dict:
    action = (args.get("action") or "status").strip().lower()
    host = (args.get("host") or "").strip()
    user = (args.get("user") or "").strip()

    if action == "status":
        return ssh_pool.status()

    if action == "close":
        closed = await asyncio.to_thread(ssh_pool.close_all, host, user)
        return {
            "closed": closed,
            "scope": {"host": host or "any", "user": user or "any"},
            "remaining": ssh_pool.status()["open"],
        }

    return {"error": f"Unknown action '{action}'. Use 'status' or 'close'.",
            "outcome": "refused"}
