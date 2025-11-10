from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Dict, List, Optional, Tuple, Union

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

__all__ = [
    "SnmpError",
    "SnmpDependencyError",
    "ensure_snmp_available",
    "validate_environment_or_raise",
    "reset_backend_cache",
    "SwitchSnmpClient",
    "IANA_IFTYPE_LAG",
    "IANA_IFTYPE_SOFTWARE_LOOPBACK",
]

_LOGGER = logging.getLogger(__name__)

# --------------------------
# pysnmp import + error types
# --------------------------
class SnmpError(HomeAssistantError):
    """Generic SNMP error for this integration."""


class SnmpDependencyError(SnmpError):
    """Raised when pysnmp is not available."""


try:
    from pysnmp.hlapi import (
        CommunityData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        ContextData,
        getCmd,
        nextCmd,
    )
    _PYSNMP_IMPORT_OK = True
    _PYSNMP_IMPORT_ERR = None
except Exception as exc:  # pragma: no cover
    _PYSNMP_IMPORT_OK = False
    _PYSNMP_IMPORT_ERR = exc

# --------------------------
# Back-compat helper shims (used by config_flow and earlier code)
# --------------------------
def ensure_snmp_available() -> None:
    if not _PYSNMP_IMPORT_OK:
        raise SnmpDependencyError(f"pysnmp.hlapi import failed: {_PYSNMP_IMPORT_ERR}")


def validate_environment_or_raise() -> None:
    ensure_snmp_available()


def reset_backend_cache() -> None:
    return


# --- MIB-II OIDs (vendor-agnostic) ---
IF_TABLE = "1.3.6.1.2.1.2.2.1"
IF_DESCR = IF_TABLE + ".2"
IF_TYPE = IF_TABLE + ".3"
IF_ADMIN = IF_TABLE + ".7"
IF_OPER = IF_TABLE + ".8"
IF_LAST_CHANGE = IF_TABLE + ".9"
IF_ALIAS = IF_TABLE + ".31"  # ifAlias (RFC2863)

# IANA ifType values
IANA_IFTYPE_LAG = 161                # ieee8023adLag
IANA_IFTYPE_SOFTWARE_LOOPBACK = 24

# IPv4 address table
IP_ADDR_TABLE = "1.3.6.1.2.1.4.20.1"
IP_AD_ENT_ADDR = IP_ADDR_TABLE + ".1"
IP_AD_ENT_IFIDX = IP_ADDR_TABLE + ".2"
IP_AD_ENT_NETMASK = IP_ADDR_TABLE + ".3"

# System OIDs
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"


def _normalize_port_community(
    port_in: Union[int, str, None], community_in: Union[str, int, None]
) -> Tuple[int, str]:
    """Accept either (port, community) or (community, port); ports can be str."""
    default_port = 161

    if isinstance(port_in, str) and not port_in.isdigit():
        # port arg actually is community
        community = str(port_in)
        if isinstance(community_in, int):
            port = community_in
        elif isinstance(community_in, str) and community_in.isdigit():
            port = int(community_in)
        else:
            port = default_port
        return int(port), community

    if isinstance(port_in, str) and port_in.isdigit():
        port = int(port_in)
    elif isinstance(port_in, int):
        port = port_in
    else:
        port = default_port

    community = "" if community_in is None else str(community_in)
    return port, community


def _snmp_walk(host: str, port: int, community: str, base_oid: str) -> List[Tuple[str, object]]:
    ensure_snmp_available()
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)  # v2c
    target = UdpTransportTarget((host, port), timeout=2, retries=1)
    ctx = ContextData()
    out: List[Tuple[str, object]] = []

    for (err_ind, err_stat, err_idx, var_binds) in nextCmd(
        engine, auth, target, ctx, ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False
    ):
        if err_ind:
            raise SnmpError(f"SNMP walk error: {err_ind}")
        if err_stat:
            raise SnmpError(f"SNMP walk error: {err_stat.prettyPrint()} at {err_idx}")
        for var_bind in var_binds:
            oid, val = var_bind
            out.append((str(oid), val.prettyPrint()))
    return out


def _snmp_get(host: str, port: int, community: str, oid: str) -> Optional[str]:
    ensure_snmp_available()
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)  # v2c
    target = UdpTransportTarget((host, port), timeout=2, retries=1)
    ctx = ContextData()
    error_indication, error_status, error_index, var_binds = next(
        getCmd(engine, auth, target, ctx, ObjectType(ObjectIdentity(oid)))
    )
    if error_indication:
        _LOGGER.debug("SNMP GET %s error: %s", oid, error_indication)
        return None
    if error_status:
        _LOGGER.debug("SNMP GET %s status: %s", oid, error_status.prettyPrint())
        return None
    for vb in var_binds:
        return vb[1].prettyPrint()
    return None


def _mask_to_prefix(mask: str) -> Optional[int]:
    try:
        return ipaddress.IPv4Network("0.0.0.0/" + mask, strict=False).prefixlen
    except Exception:
        return None


class SwitchSnmpClient:
    """Tiny SNMP client tailored for the integration."""

    def __init__(
        self,
        hass: Optional[HomeAssistant],
        host: str,
        port: Union[int, str, None],
        community: Union[str, int, None],
    ) -> None:
        self._hass = hass
        norm_port, norm_comm = _normalize_port_community(port, community)
        self._host = host
        self._port = norm_port
        self._community = norm_comm

    # ----- creation -----
    @classmethod
    async def async_create(
        cls, hass: HomeAssistant, host: str, port_or_comm, comm_or_port=None
    ) -> "SwitchSnmpClient":
        """Accept both call styles: (port, community) or (community, port)."""
        await hass.async_add_executor_job(ensure_snmp_available)

        # Detect which arg is which
        if isinstance(port_or_comm, str) and (
            isinstance(comm_or_port, int) or (isinstance(comm_or_port, str) and comm_or_port.isdigit())
        ):
            community = port_or_comm
            port = comm_or_port
        else:
            port = port_or_comm
            community = comm_or_port

        return cls(hass, host, port, community)

    # run sync job on executor (works even if hass not set)
    async def _run(self, func, *args):
        if self._hass is not None:
            return await self._hass.async_add_executor_job(func, *args)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args))

    # ----- system info for sensors -----
    async def async_get_system_info(self) -> Dict[str, Optional[str]]:
        def _read():
            sys_descr = _snmp_get(self._host, self._port, self._community, SYS_DESCR) or ""
            sys_uptime = _snmp_get(self._host, self._port, self._community, SYS_UPTIME) or ""
            sys_name = _snmp_get(self._host, self._port, self._community, SYS_NAME) or ""
            return {"sysDescr": sys_descr, "sysUpTime": sys_uptime, "sysName": sys_name}

        return await self._run(_read)

    # ----- interface listing with IPv4 attribution -----
    async def async_get_interfaces(self) -> List[Dict]:
        """Return list of interface dicts with admin/oper/alias/descr/type + IPv4 info."""

        def _collect() -> List[Dict]:
            # Walk ifTable essentials
            descr_rows = _snmp_walk(self._host, self._port, self._community, IF_DESCR)
            type_rows = _snmp_walk(self._host, self._port, self._community, IF_TYPE)
            admin_rows = _snmp_walk(self._host, self._port, self._community, IF_ADMIN)
            oper_rows = _snmp_walk(self._host, self._port, self._community, IF_OPER)
            alias_rows = _snmp_walk(self._host, self._port, self._community, IF_ALIAS)
            last_rows = _snmp_walk(self._host, self._port, self._community, IF_LAST_CHANGE)

            def _idx_from_oid(oid: str) -> Optional[int]:
                try:
                    return int(oid.split(".")[-1])
                except Exception:
                    return None

            info: Dict[int, Dict] = {}
            for oid, val in descr_rows:
                idx = _idx_from_oid(oid)
                if idx is not None:
                    info.setdefault(idx, {})["descr"] = val
            for oid, val in type_rows:
                idx = _idx_from_oid(oid)
                if idx is not None:
                    try:
                        info.setdefault(idx, {})["type"] = int(val)
                    except Exception:
                        info.setdefault(idx, {})["type"] = None
            for oid, val in admin_rows:
                idx = _idx_from_oid(oid)
                if idx is not None:
                    try:
                        info.setdefault(idx, {})["admin"] = int(val)
                    except Exception:
                        info.setdefault(idx, {})["admin"] = None
            for oid, val in oper_rows:
                idx = _idx_from_oid(oid)
                if idx is not None:
                    try:
                        info.setdefault(idx, {})["oper"] = int(val)
                    except Exception:
                        info.setdefault(idx, {})["oper"] = None
            for oid, val in alias_rows:
                idx = _idx_from_oid(oid)
                if idx is not None:
                    info.setdefault(idx, {})["alias"] = val
            for oid, val in last_rows:
                idx = _idx_from_oid(oid)
                if idx is not None:
                    try:
                        info.setdefault(idx, {})["last"] = int(val)
                    except Exception:
                        info.setdefault(idx, {})["last"] = None

            # IPv4 ipAddrTable: map ifIndex -> list[(ip, mask, cidr)]
            ip_rows = _snmp_walk(self._host, self._port, self._community, IP_AD_ENT_ADDR)
            ifidx_rows = _snmp_walk(self._host, self._port, self._community, IP_AD_ENT_IFIDX)
            mask_rows = _snmp_walk(self._host, self._port, self._community, IP_AD_ENT_NETMASK)

            ip_to_ifidx: Dict[str, int] = {}
            ip_to_mask: Dict[str, str] = {}

            for oid, val in ifidx_rows:
                suffix_ip = oid.split(".")[-4:]
                try:
                    key = ".".join(str(int(x)) for x in suffix_ip)
                except Exception:
                    continue
                try:
                    ip_to_ifidx[key] = int(val)
                except Exception:
                    continue
            for oid, mask in mask_rows:
                suffix_ip = oid.split(".")[-4:]
                try:
                    key = ".".join(str(int(x)) for x in suffix_ip)
                except Exception:
                    continue
                ip_to_mask[key] = mask

            ip_map: Dict[int, List[Tuple[str, str, Optional[int]]]] = {}
            for _oid, ip_val in ip_rows:
                ip = ip_val
                idx = ip_to_ifidx.get(ip)
                if idx is None:
                    continue
                mask = ip_to_mask.get(ip, "")
                prefix = _mask_to_prefix(mask) if mask else None
                ip_map.setdefault(idx, []).append((ip, mask, prefix))

            # Build final rows + filter unconfigured PortChannels (heuristic)
            out: List[Dict] = []
            for idx, row in info.items():
                if_type = row.get("type")
                alias = (row.get("alias") or "").strip()
                last = row.get("last") or 0
                has_ip = idx in ip_map

                if if_type == IANA_IFTYPE_LAG and (not alias) and (not has_ip) and last == 0:
                    continue

                port = {
                    "index": idx,
                    "descr": row.get("descr") or "",
                    "alias": alias,
                    "admin": row.get("admin"),
                    "oper": row.get("oper"),
                    "type": if_type,
                    "ips": ip_map.get(idx, []),  # list of (ip, mask, prefix)
                }
                out.append(port)

            return out

        return await self._run(_collect)

    # ----- compatibility alias for existing __init__.py -----
    async def async_get_port_data(self) -> List[Dict]:
        """Backward-compatible name expected by __init__.py."""
        return await self.async_get_interfaces()
