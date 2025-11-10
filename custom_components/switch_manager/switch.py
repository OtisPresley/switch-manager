from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


# ---- helpers (attributes only; do not affect flow/discovery) -----------------
def _mask_to_prefix(mask: Optional[str]) -> Optional[int]:
    """Convert dotted decimal mask (e.g., 255.255.255.252) to prefix length (e.g., 30)."""
    if not mask:
        return None
    try:
        parts = [int(x) for x in mask.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        bits = "".join(f"{p:08b}" for p in parts)
        # allow non-strict masks from quirky stacks; just count contiguous 1s from left
        return bits.find("0") if "0" in bits else 32
    except Exception:
        return None


def _format_first_ip(ips: List[Tuple[str, str, Optional[int]]]) -> Optional[str]:
    """
    `ips` tuple layout from snmp.py: [(ip, mask, prefix), ...]
    Pick the first and format as ip/prefix when available, else ip only.
    """
    if not ips:
        return None
    ip, mask, prefix = ips[0]
    pfx = prefix if prefix is not None else _mask_to_prefix(mask)
    return f"{ip}/{pfx}" if pfx is not None else ip


# ------------------------------------------------------------------------------
async def async_setup_entry(hass: HomeAssistant, entry, async_add_entities):
    """Set up Switch Manager port switches from a config entry."""
    domain_data = hass.data.get(DOMAIN, {})
    runtime = domain_data.get(entry.entry_id)
    if not runtime:
        _LOGGER.error(
            "Could not resolve coordinator for entry_id=%s; hass.data keys: %s",
            entry.entry_id,
            list(domain_data.keys()),
        )
        return

    coordinator = runtime["coordinator"]
    ports: List[Dict[str, Any]] = coordinator.data.get("ports", [])
    entities: List[SwitchManagerPort] = []

    for port in ports:
        # Port dict comes from snmp.py and already contains friendly_name etc.
        idx = port.get("index")
        if idx is None:
            continue
        entities.append(SwitchManagerPort(coordinator, entry, port))

    if entities:
        async_add_entities(entities)


class SwitchManagerPort(CoordinatorEntity, SwitchEntity):
    """HA switch representing the admin state of a switch interface."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, entry, port: Dict[str, Any]) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._port = port
        # Preserve prior naming behavior exactly
        self._attr_name = port.get("friendly_name") or port.get("descr") or f"Port {port.get('index')}"
        self._attr_unique_id = f"{entry.entry_id}-if-{port.get('index')}"

    # -------- SwitchEntity API -------------------------------------------------
    @property
    def is_on(self) -> bool:
        """Admin up == True."""
        return bool(self._port.get("admin") == 1)

    async def async_turn_on(self, **kwargs) -> None:
        client = self.coordinator.data.get("client")
        if not client:
            return
        await client.async_set_admin_state(self._port.get("index"), True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        client = self.coordinator.data.get("client")
        if not client:
            return
        await client.async_set_admin_state(self._port.get("index"), False)
        await self.coordinator.async_request_refresh()

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        """
        Only augment attributes; do not change discovery or names.
        Adds `IP address` as ip/prefix if available (works for VLAN, Loopback, PoX SVI).
        """
        attrs: Dict[str, Any] = {
            "Index": self._port.get("index"),
            "Name": self._port.get("descr"),
            "Alias": self._port.get("alias"),
            "Admin": self._port.get("admin"),
            "Oper": self._port.get("oper"),
        }

        ip_fmt = _format_first_ip(self._port.get("ips", []))
        if ip_fmt:
            attrs["IP address"] = ip_fmt

        return attrs

    # -------- Coordinator hook -------------------------------------------------
    @callback
    def _handle_coordinator_update(self) -> None:
        """Refresh local snapshot when coordinator updates."""
        idx = self._port.get("index")
        for p in self.coordinator.data.get("ports", []):
            if p.get("index") == idx:
                self._port = p
                break
        self.async_write_ha_state()
