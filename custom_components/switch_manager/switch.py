from __future__ import annotations

import logging
from typing import Any, Dict

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def _resolve_coordinator(hass, entry):
    """Return the DataUpdateCoordinator regardless of storage shape."""
    dom: Dict[str, Any] | None = hass.data.get(DOMAIN)

    # 1) Newest observed layout in your logs:
    #    hass.data[DOMAIN] -> {"entries": { entry_id: {...} }, "service_registered": True}
    if isinstance(dom, dict) and "entries" in dom:
        entries = dom.get("entries")
        if isinstance(entries, dict):
            node = entries.get(entry.entry_id)
            if node is not None:
                if isinstance(node, dict) and "coordinator" in node:
                    return node["coordinator"]
                # Some code stores the coordinator object directly
                if hasattr(node, "async_request_refresh") and hasattr(node, "data"):
                    return node

    # 2) Older common layouts
    if isinstance(dom, dict):
        node = dom.get(entry.entry_id)
        if node is not None:
            if isinstance(node, dict) and "coordinator" in node:
                return node["coordinator"]
            if hasattr(node, "async_request_refresh") and hasattr(node, "data"):
                return node
        # Single-coordinator layout
        if "coordinator" in dom and hasattr(dom["coordinator"], "async_request_refresh"):
            return dom["coordinator"]

    # 3) ConfigEntry runtime_data (some HA versions)
    runtime = getattr(entry, "runtime_data", None)
    if runtime is not None:
        if hasattr(runtime, "async_request_refresh") and hasattr(runtime, "data"):
            return runtime
        if hasattr(runtime, "coordinator"):
            return getattr(runtime, "coordinator")

    _LOGGER.error(
        "Could not resolve coordinator for entry_id=%s; hass.data keys: %s; node=None; runtime_data=%s",
        entry.entry_id,
        list((dom or {}).keys()) if isinstance(dom, dict) else type(dom).__name__,
        type(runtime).__name__ if runtime is not None else None,
    )
    raise KeyError(entry.entry_id)


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Switch Manager port switches."""
    coordinator = _resolve_coordinator(hass, entry)

    ports = coordinator.data.get("ports", {})
    entities: list[SwitchManagerPort] = []

    # Accept both dict[int, dict] and list[dict] or list[int]
    iterable = ports.values() if isinstance(ports, dict) else ports

    count = 0
    for port in iterable:
        if isinstance(port, dict):
            idx = port.get("index") or port.get("ifIndex") or 0
            name = port.get("name") or f"Port {idx}"
        else:
            idx = int(port)
            name = f"Port {idx}"
        entities.append(SwitchManagerPort(coordinator, entry, idx, name))
        count += 1

    _LOGGER.debug("Adding %s Switch Manager port entities", count)
    if not entities:
        _LOGGER.warning("No ports found in coordinator data: %s", coordinator.data)

    async_add_entities(entities)


class SwitchManagerPort(CoordinatorEntity, SwitchEntity):
    """Representation of a network switch port."""

    _attr_should_poll = False

    def __init__(self, coordinator, entry, port_index: int, friendly_name: str):
        """Initialize the switch port entity."""
        super().__init__(coordinator)
        self._entry = entry
        self._port_index = port_index
        self._attr_unique_id = f"{entry.entry_id}_{port_index}"
        self._attr_name = friendly_name

    @property
    def is_on(self) -> bool:
        """Return True if port is administratively up."""
        ports = self.coordinator.data.get("ports", {})
        port = ports.get(self._port_index) if isinstance(ports, dict) else None
        if isinstance(port, dict):
            admin = port.get("admin")
            return admin == 1
        return False

    async def async_turn_on(self, **kwargs) -> None:
        """Enable the switch port (ifAdminStatus = up(1))."""
        client = getattr(self.coordinator, "client", None)
        if client is None:
            _LOGGER.error("No SNMP client available for port %s", self._port_index)
            return
        try:
            await client.async_set_octet_string(
                f"1.3.6.1.2.1.2.2.1.7.{self._port_index}", 1
            )
            await self.coordinator.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to enable port %s: %s", self._port_index, err)

    async def async_turn_off(self, **kwargs) -> None:
        """Disable the switch port (ifAdminStatus = down(2))."""
        client = getattr(self.coordinator, "client", None)
        if client is None:
            _LOGGER.error("No SNMP client available for port %s", self._port_index)
            return
        try:
            await client.async_set_octet_string(
                f"1.3.6.1.2.1.2.2.1.7.{self._port_index}", 2
            )
            await self.coordinator.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to disable port %s: %s", self._port_index, err)

    @property
    def extra_state_attributes(self) -> dict[str, str | int]:
        """Expose additional port attributes."""
        ports = self.coordinator.data.get("ports", {})
        port = ports.get(self._port_index) if isinstance(ports, dict) else None
        if not isinstance(port, dict):
            return {"index": self._port_index}
        return {
            "index": port.get("index", self._port_index),
            "name": port.get("name"),
            "alias": port.get("alias"),
            "admin": port.get("admin"),
            "oper": port.get("oper"),
        }
