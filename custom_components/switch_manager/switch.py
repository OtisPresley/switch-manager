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
    """Retrieve the coordinator regardless of how __init__ stored it."""
    dom = hass.data.get(DOMAIN) or {}
    # Newer storage: hass.data[DOMAIN]["entries"][entry_id]
    node = (dom.get("entries") or {}).get(entry.entry_id)
    if isinstance(node, dict) and "coordinator" in node:
        return node["coordinator"]

    # Back-compat storage: hass.data[DOMAIN][entry_id]
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
        # If first update arrived after platform init, refresh once and re-read
        await coordinator.async_request_refresh()
        ports = (coordinator.data or {}).get("ports") or []

    entities: List[SwitchManagerPort] = []
    for port in ports:
        idx = port.get("index")
        if idx is None:
            continue
        entities.append(SwitchManagerPort(coordinator, entry, port_dict=port))

    async_add_entities(entities)


def _friendly_name_from_descr(descr: str) -> Optional[str]:
    """
    Map vendor string to a short friendly name.
    Examples:
      "Unit: 1 Slot: 0 Port: 46 Gigabit - Level" -> "Gi1/0/46"
      "Unit: 1 Slot: 1 Port: 2 20G - Level"      -> treat as stacking -> "Tw1/0/2"
    """
    try:
        parts = {k.lower(): v for k, v in [
            (x.split(":")[0].strip(), x.split(":")[1].strip())
            for x in descr.split()  # crude fallback if commas missing
            if ":" in x
        ]}
    except Exception:
        parts = {}

    # More robust parse that works with Dell style strings
    unit = slot = port = None
    if "Unit:" in descr:
        try:
            unit = int(descr.split("Unit:")[1].split()[0])
        except Exception:
            pass
    if "Slot:" in descr:
        try:
            slot = int(descr.split("Slot:")[1].split()[0])
        except Exception:
            pass
    if "Port:" in descr:
        try:
            port = int(descr.split("Port:")[1].split()[0])
        except Exception:
            pass

    # Interface type
    type_str = ""
    if " 10G" in descr or " 10g" in descr:
        type_str = "Te"
    elif " 20G" in descr or " 20g" in descr:
        # Treat 20G as stacking Twinax -> Tw
        type_str = "Tw"
    elif " Gigabit" in descr or " gigabit" in descr:
        type_str = "Gi"

    if type_str and unit is not None and slot is not None and port is not None:
        return f"{type_str}{unit}/{slot}/{port}"

    # VLANs and Loopback names are handled from sensor data elsewhere
    return None


class SwitchManagerPort(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = False

    def __init__(self, coordinator, entry: ConfigEntry, *, port_dict: Dict[str, Any]):
        super().__init__(coordinator)
        self._entry = entry
        self._port = port_dict

        descr = port_dict.get("descr") or ""
        idx = port_dict.get("index")

        # Name
        name = None
        if descr:
            name = _friendly_name_from_descr(descr)
        if not name:
            # VLAN
            if descr.upper().startswith("VLAN") or descr.upper().startswith("VLI"):
                # Derive "VlX" from alias/descr if possible
                alias = (port_dict.get("alias") or "").strip()
                if alias.upper().startswith("VL"):
                    name = alias.upper()
            # Loopback
            if not name and port_dict.get("type") == IANA_IFTYPE_SOFTWARE_LOOPBACK:
                name = "Lo0"
        self._name = name or f"Port {idx}"

        self._attr_unique_id = f"{self._entry.entry_id}_port_{idx}"
        self._attr_name = self._name

        # Device
        sys_name = (coordinator.data.get("system") or {}).get("sysName") or self._entry.title
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=str(sys_name),
            manufacturer=None,
            model=None,
        )

    @property
    def is_on(self) -> bool:
        # Use Admin (1=up) as switch state; fall back to Oper
        admin = self._port.get("admin")
        if isinstance(admin, int):
            return admin == 1
        oper = self._port.get("oper")
        return bool(oper == 1)

    async def async_turn_on(self, **kwargs: Any) -> None:
        # TODO: set admin up via SNMP SET when implemented
        _ = kwargs

    async def async_turn_off(self, **kwargs: Any) -> None:
        # TODO: set admin down via SNMP SET when implemented
        _ = kwargs

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

        # IPv4 info (list of (ip, mask, prefix))
        ips = self._port.get("ips") or []
        if ips:
            # Attach both CIDR and mask for clarity
            first_ip, mask, prefix = ips[0]
            if first_ip:
                attrs["IP address"] = first_ip
            if mask:
                attrs["Netmask"] = mask
            if prefix is not None:
                attrs["CIDR"] = f"{first_ip}/{prefix}"

        return attrs
