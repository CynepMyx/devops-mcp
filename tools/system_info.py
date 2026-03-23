import asyncio
import platform
from datetime import datetime, timezone

import psutil


def _collect() -> dict:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    cpu_freq = psutil.cpu_freq()
    boot_dt = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    uptime_s = int((datetime.now(timezone.utc) - boot_dt).total_seconds())

    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "uptime_seconds": uptime_s,
        "cpu": {
            "count_logical": psutil.cpu_count(logical=True),
            "count_physical": psutil.cpu_count(logical=False),
            "percent": psutil.cpu_percent(interval=1),
            "freq_mhz": round(cpu_freq.current, 1) if cpu_freq else None,
        },
        "memory": {
            "total_gb": round(vm.total / 1024 ** 3, 2),
            "available_gb": round(vm.available / 1024 ** 3, 2),
            "used_percent": vm.percent,
        },
        "disk_root": {
            "total_gb": round(disk.total / 1024 ** 3, 2),
            "free_gb": round(disk.free / 1024 ** 3, 2),
            "used_percent": disk.percent,
        },
        "load_avg": list(psutil.getloadavg()),
    }


async def get_system_info(_args: dict) -> dict:
    return await asyncio.to_thread(_collect)
