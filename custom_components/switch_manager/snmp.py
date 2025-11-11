from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .snmp import SwitchSnmpClient
from .helpers import format_interface_name

# Local-only SNMP OIDs used for a lightweight IPv4 fallback walk
_OID_ipAddressAddr = "1.3.6.1.2.1.4.34.1.2"        # OCTET STRING (IPv4: 4 bytes)
_OID_ipAddressIfIndex = "1.3.6.1.2.1.4.34.1.3"     # Integer (ifIndex)
_OID_ipCidrRoutePrefixLength = "1.3.6.1.2.1.4.24.4.1.3"  # Integer (bits)
_OID_ipCidrRouteIfIndex      = "1.3.6.1.2.1.4.24.4.1.7"  # Integer (ifIndex)

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

    for idx, row in sorted(iftable.items()):
        raw_name = row.get("name") or row.get("descr") or f"if{idx}"
        alias = row.get("alias") or ""

        # Skip internal CPU pseudo-interface
        if raw_name.strip().upper() == "CPU":
            continue

        lower = (raw_name or "").lower()
        is_port_channel = lower.startswith("po") or lower.startswith("port-channel") or lower.startswith("link aggregate")
        # For PortChannels, we may populate IPs lazily; allow creation if alias OR
        # later IP attachment exists. We'll still hide totally unconfigured Po's
        # once we know there is no alias and no IP.
        # Here we keep the original behavior: allow if alias; IP check happens lazily.
        if is_port_channel and not alias:
            # Defer final decision to attribute resolver which can attach IPs lazily
            pass

        # Try to parse Gi1/0/1 style to preserve unit/slot/port in display name
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
                hass=hass,
                is_port_channel=is_port_channel,
            )
        )

    async_add_entities(entities)


def _ip_for_index(
    if_index: int, ip_index: Dict[str, int], ip_mask: Dict[str, str]
) -> Optional[str]:
    """Return IP/maskbits string for an ifIndex if present."""
    for ip, idx in ip_index.items():
        if idx == if_index:
            mask = ip_mask.get(ip)
            if not mask:
                return ip
            # Accept either dotted mask or "/bits"
            if mask.startswith("/"):
                return f"{ip}{mask}"
            try:
                import ipaddress

                net = ipaddress.IPv4Network((ip, mask), strict=False)
                return f"{ip}/{net.prefixlen}"
            except Exception:
                return ip
    return None


def _octets_to_ipv4(val: Any) -> Optional[str]:
    """Coerce OCTET STRING to dotted IPv4 if 4 bytes."""
    try:
        bs = bytes(val)
    except Exception:
        try:
            bs = val.asOctets()  # type: ignore[attr-defined]
        except Exception:
            s = str(val)
            return s if s.count(".") == 3 else None
    if len(bs) == 4:
        return ".".join(str(b) for b in bs)
    return None


def _bits_to_mask(bits: int) -> str:
    """Convert CIDR bits to dotted mask."""
    if bits <= 0:
        return "0.0.0.0"
    if bits >= 32:
        return "255.255.255.255"
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return ".".join(str((mask >> s) & 0xFF) for s in (24, 16, 8, 0))


async def _ensure_ip_maps(
    hass: HomeAssistant, client: SwitchSnmpClient, store: Dict[str, Any]
) -> None:
    """If coordinator has no ipIndex/ipMask, build them once via a tiny SNMP walk."""
    if store.get("ipIndex") and store.get("ipMask"):
        return

    # Build maps locally and cache back into coordinator
    ip_to_index: Dict[str, int] = {}
    ip_to_mask: Dict[str, str] = {}

    def _walk(base_oid: str):
        from pysnmp.hlapi import (  # type: ignore
            CommunityData,
            SnmpEngine,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            nextCmd,
        )

        engine = SnmpEngine()
        target = UdpTransportTarget((client.host, client.port), timeout=1.5, retries=1)
        community = CommunityData(client.community, mpModel=1)
        context = ContextData()
        it = nextCmd(
            engine,
            community,
            target,
            context,
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        )
        for err_ind, err_stat, err_idx, vbs in it:
            if err_ind or err_stat:
                break
            for vb in vbs:
                yield str(vb[0]), vb[1]

    # 1) ipAddressIfIndex + ipAddressAddr -> ip -> ifIndex
    addr_suffix_to_ip: Dict[str, str] = {}
    addrs = await hass.async_add_executor_job(lambda: list(_walk(_OID_ipAddressAddr)))
    for oid, val in addrs:
        ip = _octets_to_ipv4(val)
        if not ip:
            continue
        suffix = oid[len(_OID_ipAddressAddr) + 1 :]
        addr_suffix_to_ip[suffix] = ip

    ifidx_rows = await hass.async_add_executor_job(
        lambda: list(_walk(_OID_ipAddressIfIndex))
    )
    for oid, val in ifidx_rows:
        suffix = oid[len(_OID_ipAddressIfIndex) + 1 :]
        ip = addr_suffix_to_ip.get(suffix)
        if not ip:
            continue
        try:
            ip_to_index[ip] = int(val)
        except Exception:
            continue

    # 2) ipCidrRoutePrefixLength + ipCidrRouteIfIndex -> pick most specific bits per ifIndex
    most_specific_bits: Dict[int, int] = {}
    bits_by_suffix: Dict[str, int] = {}

    prefix_rows = await hass.async_add_executor_job(
        lambda: list(_walk(_OID_ipCidrRoutePrefixLength))
    )
    for oid, val in prefix_rows:
        suffix = oid[len(_OID_ipCidrRoutePrefixLength) + 1 :]
        try:
            bits_by_suffix[suffix] = int(val)
        except Exception:
            continue

    ifindex_rows = await hass.async_add_executor_job(
        lambda: list(_walk(_OID_ipCidrRouteIfIndex))
    )
    for oid, val in ifindex_rows:
        suffix = oid[len(_OID_ipCidrRouteIfIndex) + 1 :]
        try:
            if_index = int(val)
        except Exception:
            continue
        bits = bits_by_suffix.get(suffix)
        if bits is None:
            continue
        prev = most_specific_bits.get(if_index, -1)
        if bits > prev:
            most_specific_bits[if_index] = bits

    # 3) Assign dotted masks to each IP using the most specific bits for its ifIndex
    for ip, if_index in ip_to_index.items():
        bits = most_specific_bits.get(if_index)
        if bits is not None:
            ip_to_mask[ip] = _bits_to_mask(bits)

    # Cache into coordinator for reuse
    if ip_to_index:
        store["ipIndex"] = ip_to_index
    if ip_to_mask:
        store["ipMask"] = ip_to_mask


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
        hass: HomeAssistant,
        is_port_channel: bool = False,
    ):
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._if_index = if_index
        self._raw_name = raw_name
        self._display = display_name
        self._alias = alias
        self._client = client
        self._hass = hass
        self._is_port_channel = is_port_channel

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
        # Ensure we have IP maps (legacy from coordinator or fallback via light SNMP walk)
        store = self.coordinator.data
        # We run the fallback lazily, once, and cache into coordinator
        if not (store.get("ipIndex") and store.get("ipMask")):
            # fire-and-forget schedule; HA will re-render attributes on next poll
            self._hass.async_create_task(_ensure_ip_maps(self._hass, self._client, store))

        row = store.get("ifTable", {}).get(self._if_index, {})
        attrs: Dict[str, Any] = {
            "Index": self._if_index,
            "Name": self._display,
            "Alias": row.get("alias") or "",
            "Admin": ADMIN_STATE.get(row.get("admin", 0), "Unknown"),
            "Oper": OPER_STATE.get(row.get("oper", 0), "Unknown"),
        }

        ip = _ip_for_index(self._if_index, store.get("ipIndex", {}), store.get("ipMask", {}))
        # If we still don't have an IP and this is a PortChannel with no alias or IP,
        # we keep attributes but don't add IP.
        if ip:
            attrs["IP"] = ip

        return attrs
