from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .snmp import IANA_IFTYPE_SOFTWARE_LOOPBACK

_LOGGER = logging.getLogger(__name__)


def _resolve_coordinator(hass: HomeAssistant, entry: ConfigEntry):
    """Cope with both the new dict layout and the older flat mapping."""
    dom = hass.data.get(DOMAIN) or {}

    node = (dom.get("entries") or {}).get(entry.entry_id)
    if isinstance(node, dict) and "coordinator" in node:
        return node["coordinator"]

    node = dom.get(entry.entry_id)
    if isinstance(node, dict) and "coordinator" in node:
        return node["coordinator"]

    _LOGGER.error(
        "Could not resolve coordinator for entry_id=%s; hass.data keys: %s; node=%s; runtime_data=%s",
        entry.entry_id,
        list(dom.keys()),
        node,
        dom.get("entries"),
    )
    raise KeyError(entry.entry_id)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    coordinator = _resolve_coordinator(hass, entry)

    data = coordinator.data or {}
    ports: List[Dict[str, Any]] = data.get("ports") or []
    if not ports:
        await coordinator.async_request_refresh()
        ports = (coordinator.data or {}).get("ports") or []

    entities: List[SwitchManagerPort] = [
        SwitchManagerPort(coordinator, entry, port_dict=p)
        for p in ports
        if p.get("index") is not None
    ]
    async_add_entities(entities)


def _friendly_name_from_descr(descr: str) -> Optional[str]:
    """Translate the raw ifDescr into Gi/Te/Tw formatting (Dell-style)."""
    try:
        unit = slot = port = None
        if "Unit:" in descr:
            unit = int(descr.split("Unit:")[1].split()[0])
        if "Slot:" in descr:
            slot = int(descr.split("Slot:")[1].split()[0])
        if "Port:" in descr:
            port = int(descr.split("Port:")[1].split()[0])

        t = ""
        dlow = descr.lower()
        if " 10g" in dlow:
            t = "Te"
        elif " 20g" in dlow:
            t = "Tw"
        elif " gigabit" in dlow:
            t = "Gi"

        if t and unit is not None and slot is not None and port is not None:
            return f"{t}{unit}/{slot}/{port}"
    except Exception:
        pass
    return None


class SwitchManagerPort(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = False

    def __init__(self, coordinator, entry: ConfigEntry, *, port_dict: Dict[str, Any]):
        super().__init__(coordinator)
        self._entry = entry
        self._port = port_dict

        descr = port_dict.get("descr") or ""
        idx = port_dict.get("index")

        name = _friendly_name_from_descr(descr)

        if not name:
            alias = (port_dict.get("alias") or "").strip()
            dlow = descr.lower()

            if alias and alias.upper().startswith("VL"):
                name = alias.upper()
            elif descr.strip().lower().startswith("vl"):
                name = descr.strip()
            elif "vlan" in dlow:
                parts = dlow.replace("/", " ").split()
                try:
                    vi = parts.index("vlan")
                    for tok in parts[vi + 1 : vi + 4]:
                        if tok.isdigit():
                            name = f"Vl{int(tok)}"
                            break
                except Exception:
                    pass

        if not name and port_dict.get("type") == IANA_IFTYPE_SOFTWARE_LOOPBACK:
            name = "Lo0"

        self._name = name or f"Port {idx}"

        self._attr_unique_id = f"{self._entry.entry_id}_port_{idx}"
        self._attr_name = self._name

        sys_name = (coordinator.data.get("system") or {}).get("sysName") or self._entry.title
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=str(sys_name),
        )

    @property
    def is_on(self) -> bool:
        admin = self._port.get("admin")
        if isinstance(admin, int):
            return admin == 1
        return bool(self._port.get("oper") == 1)

    async def async_turn_on(self, **kwargs: Any) -> None:
        return

    async def async_turn_off(self, **kwargs: Any) -> None:
        return

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        attrs: Dict[str, Any] = {}

        attrs["Index"] = self._port.get("index")
        attrs["Name"] = self._port.get("descr") or ""

        alias = (self._port.get("alias") or "").strip()
        if alias:
            attrs["Alias"] = alias

        if self._port.get("admin") is not None:
            attrs["Admin"] = self._port.get("admin")
        if self._port.get("oper") is not None:
            attrs["Oper"] = self._port.get("oper")

        # IPv4: show IP/prefix if we have prefix; otherwise show just IP
        ips = self._port.get("ips") or []
        if ips:
            ip, _mask, prefix = ips[0]
            if ip:
                attrs["IP address"] = f"{ip}/{prefix}" if prefix is not None else ip

        return attrs
