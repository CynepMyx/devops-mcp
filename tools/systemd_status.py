from dbus_fast import BusType
from dbus_fast.aio import MessageBus
from dbus_fast.errors import DBusError

_SYSTEMD_SERVICE = "org.freedesktop.systemd1"
_MANAGER_PATH = "/org/freedesktop/systemd1"
_MANAGER_IFACE = "org.freedesktop.systemd1.Manager"
_UNIT_IFACE = "org.freedesktop.systemd1.Unit"
_SERVICE_IFACE = "org.freedesktop.systemd1.Service"


async def _query_unit(bus: MessageBus, unit_name: str) -> dict:
    try:
        mgr_intro = await bus.introspect(_SYSTEMD_SERVICE, _MANAGER_PATH)
        mgr_proxy = bus.get_proxy_object(_SYSTEMD_SERVICE, _MANAGER_PATH, mgr_intro)
        manager = mgr_proxy.get_interface(_MANAGER_IFACE)
        unit_path = await manager.call_load_unit(unit_name)
    except DBusError as e:
        return {"unit": unit_name, "error": str(e)}

    try:
        unit_intro = await bus.introspect(_SYSTEMD_SERVICE, unit_path)
        unit_proxy = bus.get_proxy_object(_SYSTEMD_SERVICE, unit_path, unit_intro)
        unit_iface = unit_proxy.get_interface(_UNIT_IFACE)

        result = {
            "unit": unit_name,
            "load_state": await unit_iface.get_load_state(),
            "active_state": await unit_iface.get_active_state(),
            "sub_state": await unit_iface.get_sub_state(),
            "description": await unit_iface.get_description(),
        }

        try:
            mem = await unit_iface.get_memory_current()
            if mem != 2**64 - 1:
                result["memory_bytes"] = mem
        except Exception:
            pass

        try:
            svc_iface = unit_proxy.get_interface(_SERVICE_IFACE)
            pid = await svc_iface.get_main_pid()
            if pid:
                result["main_pid"] = pid
        except Exception:
            pass

        return result

    except DBusError as e:
        return {"unit": unit_name, "error": str(e)}


async def get_systemd_status(args: dict) -> dict | list:
    unit = args.get("unit")
    units = args.get("units", [])
    if unit:
        units = [unit]
    if not units:
        return {"error": "Specify 'unit' or 'units'"}

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        results = [await _query_unit(bus, u) for u in units]
    finally:
        bus.disconnect()

    return results[0] if len(results) == 1 else {"units": results}
