from __future__ import annotations

from typing import Any, Dict

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


def _resolve_coordinator(hass, entry):
    dom = hass.data.get(DOMAIN)
    if isinstance(dom, dict) and "entries" in dom:
        node = (dom.get("entries") or {}).get(entry.entry_id)
        if isinstance(node, dict) and "coordinator" in node:
            return node["coordinator"]
        if hasattr(node, "async_request_refresh") and hasattr(node, "data"):
            return node
    if isinstance(dom, dict):
        node = dom.get(entry.entry_id)
        if isinstance(node, dict) and "coordinator" in node:
            return node["coordinator"]
        if hasattr(node, "async_request_refresh") and hasattr(node, "data"):
            return node
        if "coordinator" in dom and hasattr(dom["coordinator"], "async_request_refresh"):
            return dom["coordinator"]
    runtime = getattr(entry, "runtime_data", None)
    if runtime is not None:
        if hasattr(runtime, "async_request_refresh") and hasattr(runtime, "data"):
            return runtime
        if hasattr(runtime, "coordinator"):
            return getattr(runtime, "coordinator")
    raise KeyError(entry.entry_id)


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up diagnostic sensors for the switch."""
    coordinator = _resolve_coordinator(hass, entry)
    sysinfo = (getattr(coordinator, "data", {}) or {}).get("system", {}) or {}

    entities = [
        SwitchDiagText(coordinator, entry, "manufacturer_model", "Manufacturer & Model",
                       lambda s: f"{s.get('manufacturer') or ''} {s.get('model') or ''}".strip()),
        SwitchDiagText(coordinator, entry, "firmware", "Firmware Rev",
                       lambda s: s.get("firmware")),
        SwitchDiagUptime(coordinator, entry),
        SwitchDiagText(coordinator, entry, "hostname", "Hostname",
                       lambda s: s.get("hostname")),
    ]
    async_add_entities(entities)


class _BaseDiag(CoordinatorEntity, SensorEntity):
    _attr_should_poll = False

    def __init__(self, coordinator, entry, key: str, name: str):
        super().__init__(coordinator)
        self._entry = entry
        self._key = key
        self._attr_unique_id = f"{entry.entry_id}_diag_{key}"
        self._attr_name = name

    @property
    def device_info(self) -> Dict[str, Any]:
        sysinfo = getattr(self.coordinator, "data", {}).get("system", {})
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": sysinfo.get("hostname") or (self._entry.title or "Switch"),
            "manufacturer": sysinfo.get("manufacturer"),
            "model": sysinfo.get("model"),
            "sw_version": sysinfo.get("firmware"),
        }


class SwitchDiagText(_BaseDiag):
    def __init__(self, coordinator, entry, key: str, name: str, selector):
        super().__init__(coordinator, entry, key, name)
        self._selector = selector  # function(sysinfo)->str|None

    @property
    def native_value(self):
        sysinfo = getattr(self.coordinator, "data", {}).get("system", {})
        return self._selector(sysinfo) or None

    @property
    def extra_state_attributes(self):
        return getattr(self.coordinator, "data", {}).get("system", {})


class SwitchDiagUptime(_BaseDiag):
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = "s"

    def __init__(self, coordinator, entry):
        super().__init__(coordinator, entry, "uptime", "Uptime")

    @property
    def native_value(self):
        sysinfo = getattr(self.coordinator, "data", {}).get("system", {})
        return sysinfo.get("uptime_seconds")

    @property
    def extra_state_attributes(self):
        sysinfo = getattr(self.coordinator, "data", {}).get("system", {})
        # Also expose formatted uptime for dashboards
        out = dict(sysinfo)
        if "uptime" in sysinfo:
            out["uptime_human"] = sysinfo.get("uptime")
        return out
