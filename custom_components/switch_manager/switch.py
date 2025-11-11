from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN
from .snmp import SwitchSnmpClient
from .helpers import format_interface_name

_LOGGER = logging.getLogger(__name__)

ADMIN_STATE = {1: "Up", 2: "Down", 3: "Testing"}
OPER_STATE = {
    1: "Up",
    2: "Down",
    3: "Testing",
    4: "Unknown",
    5: "Dormant",
    6: "NotPresent",
    7: "LowerLayerDown",
}


async def async_setup_entry(hass, entry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    client: SwitchSnmpClient = data["client"]
    coordinator = data["coordinator"]

    entities: list[IfAdminSwitch] = []
    iftable = client.cache.get("ifTable", {})
    hostname = client.cache.get("sysName") or entry.data.get("name") or client.host

    device_info = DeviceInfo(
        identifiers={(DOMAIN, f"{client.host}:{client.port}:{client.community}")},
        name=hostname,
    )

    ip_index = client.cache.get("ipIndex", {})
    ip_mask = client.cache.get("ipMask", {})

    for idx, row in sorted(iftable.items()):
        raw_name = row.get("name") or row.get("descr") or f"if{idx}"
        alias = row.get("alias") or ""

        # Skip internal CPU pseudo-interface
        if raw_name.strip().upper() == "CPU":
            continue

        lower = (raw_name or "").lower()
        is_port_channel = lower.startswith("po") or lower.startswith("port-channel") or lower.startswith("link aggregate")
        if is_port_channel and not (_ip_for_index(idx, ip_index, ip_mask) or alias):
            # Only create PortChannel entity if configured (alias or IP present)
            continue

        # Try to parse Gi1/0/1 style to preserve unit/slot/port in display name
        unit = 1
        slot = 0
        port = None
        try:
            # e.g., "Gi1/0/1" -> parts after the first two letters
            if "/" in raw_name and raw_name[2:3].isdigit():
                parts = raw_name[2:].split("/")
                if len(parts) >= 3:
                    unit = int(parts[0])
                    slot = int(parts[1])
                    port = int(parts[2])
        except Exception:
            pass

        display = format_interface_name(raw_name, unit=unit, slot=slot, port=port)

        entities.append(
            IfAdminSwitch(
                coordinator=coordinator,
                entry_id=entry.entry_id,
                if_index=idx,
                raw_name=raw_name,
                display_name=display,
                alias=alias,
                device_info=device_info,
                client=client,
            )
        )

    async_add_entities(entities)


def _ip_for_index(if_index: int, ip_index: Dict[str, int], ip_mask: Dict[str, str]) -> Optional[str]:
    """Return IP/maskbits string for an ifIndex if present."""
    for ip, idx in ip_index.items():
        if idx == if_index:
            mask = ip_mask.get(ip)
            if not mask:
                return ip
            try:
                import ipaddress

                net = ipaddress.IPv4Network((ip, mask), strict=False)
                return f"{ip}/{net.prefixlen}"
            except Exception:
                return ip
    return None


class IfAdminSwitch(CoordinatorEntity, SwitchEntity):
    def __init__(
        self,
        coordinator,
        entry_id: str,
        if_index: int,
        raw_name: str,
        display_name: str,
        alias: str,
        device_info: DeviceInfo,
        client: SwitchSnmpClient,
    ):
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._if_index = if_index
        self._raw_name = raw_name
        self._display = display_name
        self._alias = alias
        self._client = client

        self._attr_unique_id = f"{entry_id}-if-{if_index}"
        self._attr_name = display_name
        self._attr_device_info = device_info

    @property
    def is_on(self) -> bool:
        row = self.coordinator.data.get("ifTable", {}).get(self._if_index, {})
        return row.get("admin") == 1

    async def async_turn_on(self, **kwargs):
        ok = await self._client.set_admin_status(self._if_index, 1)
        if ok:
            self.coordinator.data["ifTable"].setdefault(self._if_index, {})["admin"] = 1
            self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        ok = await self._client.set_admin_status(self._if_index, 2)
        if ok:
            self.coordinator.data["ifTable"].setdefault(self._if_index, {})["admin"] = 2
            self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        row = self.coordinator.data.get("ifTable", {}).get(self._if_index, {})
        attrs: Dict[str, Any] = {
            "Index": self._if_index,
            "Name": self._display,
            "Alias": row.get("alias") or "",
            "Admin": ADMIN_STATE.get(row.get("admin", 0), "Unknown"),
            "Oper": OPER_STATE.get(row.get("oper", 0), "Unknown"),
        }
        ip = _ip_for_index(
            self._if_index,
            self.coordinator.data.get("ipIndex", {}),
            self.coordinator.data.get("ipMask", {}),
        )
        if ip:
            attrs["IP"] = ip
        return attrs
