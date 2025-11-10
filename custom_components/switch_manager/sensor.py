from __future__ import annotations

from typing import Any, Dict, Callable

from homeassistant.components.sensor import SensorEntity
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

    entities = [
        SwitchDiagText(
            coordinator,
            entry,
            "firmware",
            "Firmware Rev",
            lambda s: s.get("firmware"),
        ),
        SwitchDiagText(
            coordinator,
            entry,
            "hostname",
            "Hostname",
            lambda s: s.get("hostname"),
        ),
        SwitchDiagText(
            coordinator,
            entry,
            "manufacturer_model",
            "Manufacturer & Model",
            lambda s: f"{(s.get('manufacturer') or '').strip()} {(s.get('model') or '').strip()}".strip(),
        ),
        SwitchDiagText(
            coordinator,
            entry,
            "uptime_human",
            "Uptime",
            # Use the pretty string computed in snmp.py
            lambda s: s.get("uptime"),
        ),
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
    def __init__(self, coordinator, entry, key: str, name: str, selector: Callable[[Dict[str, Any]], str | None]):
        super().__init__(coordinator, entry, key, name)
        self._selector = selector

    @property
    def native_value(self):
        sysinfo = getattr(self.coordinator, "data", {}).get("system", {})
        return self._selector(sysinfo) or None

    # Do NOT mirror system dict into attributes; keep sensors clean
    @property
    def extra_state_attributes(self):
        return {}
