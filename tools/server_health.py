import asyncio
from datetime import datetime, timezone

import docker
import psutil
from dbus_fast import BusType
from dbus_fast.aio import MessageBus


def _disk_info() -> list:
    seen = set()
    result = []
    for part in psutil.disk_partitions():
        if part.mountpoint.startswith(("/proc", "/sys", "/dev", "/run")):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            key = (usage.total, usage.free)
            if key in seen:
                continue
            seen.add(key)
            result.append({
                "mount": part.mountpoint,
                "total_gb": round(usage.total / 1024 ** 3, 1),
                "free_gb": round(usage.free / 1024 ** 3, 1),
                "used_percent": usage.percent,
            })
        except PermissionError:
            pass
    return result


def _docker_info() -> dict:
    try:
        client = docker.from_env(timeout=10)
        try:
            containers = client.containers.list(all=True)
            running = [c.name for c in containers if c.status == "running"]
            stopped = [c.name for c in containers if c.status != "running"]
            return {"running": running, "stopped": stopped}
        finally:
            client.close()
    except Exception as e:
        return {"error": str(e)}


def _cpu_percent() -> float:
    return psutil.cpu_percent(interval=1)


async def _failed_units() -> list:
    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        mgr_intro = await bus.introspect("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
        mgr_proxy = bus.get_proxy_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1", mgr_intro)
        manager = mgr_proxy.get_interface("org.freedesktop.systemd1.Manager")
        units = await manager.call_list_units()
        failed = [u[0] for u in units if u[3] == "failed"]
        bus.disconnect()
        return failed
    except Exception as e:
        return [f"error: {e}"]


async def get_server_health(_args: dict) -> dict:
    vm = psutil.virtual_memory()
    boot_dt = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    uptime_s = int((datetime.now(timezone.utc) - boot_dt).total_seconds())
    uptime_h = round(uptime_s / 3600, 1)

    disk, docker_info, failed, cpu = await asyncio.gather(
        asyncio.to_thread(_disk_info),
        asyncio.to_thread(_docker_info),
        _failed_units(),
        asyncio.to_thread(_cpu_percent),
    )

    return {
        "uptime_hours": uptime_h,
        "cpu_percent": cpu,
        "memory": {
            "total_gb": round(vm.total / 1024 ** 3, 1),
            "used_gb": round(vm.used / 1024 ** 3, 1),
            "used_percent": vm.percent,
        },
        "disk": disk,
        "docker": docker_info,
        "systemd_failed": failed,
    }
