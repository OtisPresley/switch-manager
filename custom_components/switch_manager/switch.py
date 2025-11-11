"""Switch entities (surgical update only).

Matches __init__.py’s coordinator shape:
coordinator.data = { "ports": list[PortRow], "device_info": {...} }
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .snmp import PortRow

# --- entity description bound to PortRow ----------------------------------------
@dataclass
class PortEntityDescription:
    index: int
    name: str
    alias: str
    admin: int
    oper: int
    ip_cidr: Optional[str]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    domain = hass.data.get(DOMAIN, {})
    node = domain.get("entries", {}).get(entry.entry_id)
    if not node:
        # Let HA log/report this; avoids KeyError noise when unload/reload races happen
        return

    coordinator = node["coordinator"]
    ports: List[PortRow] = (coordinator.data or {}).get("ports", []) or []

    entities: List[SwitchPortEntity] = []
    for r in ports:
        desc = PortEntityDescription(
            index=r.index,
            name=r.name,         # keep existing device-facing name flow; rename is handled elsewhere
            alias=r.alias,
            admin=r.admin,
            oper=r.oper,
            ip_cidr=r.ip_cidr,
        )
        entities.append(SwitchPortEntity(coordinator, entry, desc))

    async_add_entities(entities, update_before_add=False)


class SwitchPortEntity(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, desc: PortEntityDescription) -> None:
        super().__init__(coordinator)
        self._desc = desc
        self._entry = entry
        self._attr_name = desc.name
        self._attr_unique_id = f"{entry.entry_id}:{desc.index}"

    # Coordinator → update our cached snapshot
    @property
    def _row(self) -> PortRow | None:
        ports: List[PortRow] = (self.coordinator.data or {}).get("ports", []) or []
        for p in ports:
            if p.index == self._desc.index:
                return p
        return None

    @property
    def is_on(self) -> bool:
        row = self._row
        return (row.admin if row else self._desc.admin) == 1

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        row = self._row
        admin = (row.admin if row else self._desc.admin)
        oper = (row.oper if row else self._desc.oper)
        name = (row.name if row else self._desc.name)

        attrs: Dict[str, Any] = {
            "Index": self._desc.index,
            "Name": name,
            "Admin": admin,
            "Oper": oper,
        }
        # Add IP (CIDR) only when present
        ip = (row.ip_cidr if row else self._desc.ip_cidr)
        if ip:
            attrs["IP address"] = ip
        return attrs

    async def async_turn_on(self, **kwargs: Any) -> None:
        # Admin up (handled through coordinator’s client)
        await self.coordinator.client.async_set_admin_status(self._desc.index, True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.client.async_set_admin_status(self._desc.index, False)
        await self.coordinator.async_request_refresh()
