
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN
from .snmp import SwitchSnmpClient
from .helpers import format_interface_name, ip_to_cidr

_LOGGER = logging.getLogger(__name__)

ADMIN_STATE = {1: "Up", 2: "Down", 3: "Testing"}
OPER_STATE = {1: "Up", 2: "Down", 3: "Testing", 4: "Unknown", 5: "Dormant", 6: "NotPresent", 7: "LowerLayerDown"}

async def async_setup_entry(hass, entry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    client: SwitchSnmpClient = data["client"]
    coordinator = data["coordinator"]

    entities = []
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

        lower = (raw_name or "").lower()
        is_port_channel = lower.startswith("po") or lower.startswith("port-channel") or lower.startswith("link aggregate")
        if is_port_channel and not (alias or _ip_for_index(idx, ip_index, ip_mask)):
            continue  # skip unconfigured aggregates

        unit = 1
        slot = 0
        port = None
        try:
            if "/" in raw_name and raw_name[2:3].isdigit():
                parts = raw_name[2:].split("/")
                if len(parts) >= 3:
                    unit = int(parts[0])
                    slot = int(parts[1])
                    port = int(parts[2])
        except Exception:
            pass

        display = format_interface_name(raw_name, unit=unit, slot=slot, port=port)

        entity = IfAdminSwitch(coordinator, entry, idx, raw_name, display, alias, device_info, client)
        entities.append(entity)

    async_add_entities(entities)


def _ip_for_index(if_index: int, ip_index: Dict[str, int], ip_mask: Dict[str, str]) -> Optional[str]:
    for ip, idx in ip_index.items():
        if idx == if_index:
            mask = ip_mask.get(ip)
            if mask:
                try:
                    import ipaddress
                    net = ipaddress.IPv4Network((ip, mask), strict=False)
                    return f"{ip}/{net.prefixlen}"
                except Exception:
                    return ip
            return ip
    return None


class IfAdminSwitch(CoordinatorEntity, SwitchEntity):
    def __init__(self, coordinator, entry, if_index: int, raw_name: str, display_name: str, alias: str, device_info: DeviceInfo, client: SwitchSnmpClient):
        super().__init__(coordinator)
        self._entry = entry
        self._if_index = if_index
        self._raw_name = raw_name
        self._display = display_name
        self._alias = alias
        self._client = client
        self._attr_unique_id = f"{entry.entry_id}-if-{if_index}"
        self._attr_name = display_name
        self._attr_device_info = device_info

    @property
    def is_on(self) -> bool:
        row = self.coordinator.data.get("ifTable", {}).get(self._if_index, {})
        admin = row.get("admin")
        return admin == 1

    async def async_turn_on(self, **kwargs):
        ok = await self._set_admin(1)
        if ok:
            self.coordinator.data["ifTable"][self._if_index]["admin"] = 1
            self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        ok = await self._set_admin(2)
        if ok:
            self.coordinator.data["ifTable"][self._if_index]["admin"] = 2
            self.async_write_ha_state()

    async def _set_admin(self, val: int) -> bool:
        from pysnmp.hlapi.asyncio import ObjectType, ObjectIdentity, setCmd, CommunityData, ContextData, UdpTransportTarget, SnmpEngine
        from pysnmp.proto.rfc1902 import Integer
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await setCmd(
                SnmpEngine(),
                CommunityData(self._client.community, mpModel=1),
                UdpTransportTarget((self._client.host, self._client.port), timeout=1.5, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.7." + str(self._if_index)), Integer(val)),
            )
            return (not errorIndication and not errorStatus)
        except Exception as e:
            _LOGGER.warning("Failed to set admin state on %s: %s", self._display, e)
            return False

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        row = self.coordinator.data.get("ifTable", {}).get(self._if_index, {})
        attrs = {
            "Index": self._if_index,
            "Name": self._display,
            "Alias": row.get("alias") or "",
            "Admin": ADMIN_STATE.get(row.get("admin", 0), "Unknown"),
            "Oper": OPER_STATE.get(row.get("oper", 0), "Unknown"),
        }
        ip = _ip_for_index(self._if_index, self.coordinator.data.get("ipIndex", {}), self.coordinator.data.get("ipMask", {}))
        if ip:
            attrs["IP"] = ip
        return attrs
