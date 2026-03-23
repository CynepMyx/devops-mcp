import asyncio
import docker


def _fetch_stats(name: str) -> dict:
    client = docker.from_env(timeout=10)
    try:
        container = client.containers.get(name)
        if container.status != "running":
            return {"name": container.name, "status": container.status, "error": "Container is not running"}

        s = container.stats(stream=False)

        cpu_delta = s["cpu_stats"]["cpu_usage"]["total_usage"] - s["precpu_stats"]["cpu_usage"]["total_usage"]
        system_delta = s["cpu_stats"]["system_cpu_usage"] - s["precpu_stats"]["system_cpu_usage"]
        num_cpus = s["cpu_stats"].get("online_cpus") or len(s["cpu_stats"]["cpu_usage"].get("percpu_usage", [1]))
        cpu_percent = round((cpu_delta / system_delta) * num_cpus * 100.0, 2) if system_delta > 0 else 0.0

        mem = s["memory_stats"]
        mem_usage = mem.get("usage", 0)
        mem_limit = mem.get("limit", 1)
        mem_cache = mem.get("stats", {}).get("cache", 0)
        mem_rss = mem_usage - mem_cache

        networks = s.get("networks", {})
        net_rx = sum(v["rx_bytes"] for v in networks.values())
        net_tx = sum(v["tx_bytes"] for v in networks.values())

        return {
            "name": container.name,
            "status": container.status,
            "cpu_percent": cpu_percent,
            "memory": {
                "usage_mb": round(mem_rss / 1024 ** 2, 2),
                "limit_mb": round(mem_limit / 1024 ** 2, 2),
                "used_percent": round(mem_rss / mem_limit * 100, 2) if mem_limit else 0,
            },
            "network": {
                "rx_mb": round(net_rx / 1024 ** 2, 3),
                "tx_mb": round(net_tx / 1024 ** 2, 3),
            },
        }
    except docker.errors.NotFound:
        return {"error": f"Container not found: {name}"}
    except docker.errors.DockerException as e:
        return {"error": f"Docker error: {e}"}
    finally:
        client.close()


async def get_docker_stats(args: dict) -> dict:
    name = args.get("name")
    if not name:
        return {"error": "Parameter 'name' is required"}
    return await asyncio.to_thread(_fetch_stats, name)
