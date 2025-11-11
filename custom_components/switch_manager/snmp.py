from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

# pysnmp (lextudio) imports
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
from pysnmp.smi.rfc1902 import OctetString, Integer, IpAddress

_LOGGER = logging.getLogger(__name__)

# ---------- Errors & dependency check ----------

class SnmpDependencyError(RuntimeError):
    pass


class SnmpError(RuntimeError):
    pass


def ensure_snmp_available() -> None:
    """Raise SnmpDependencyError if pysnmp (lextudio) isn't importable or usable."""
    try:
        # a minimal touch to ensure imports actually work at runtime
        _ = SnmpEngine()
    except Exception as exc:  # pragma: no cover
        raise SnmpDependencyError(f"pysnmp.hlapi import failed: {exc}") from exc


# ---------- Common OIDs we already use ----------

# System
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# Interfaces (IF-MIB)
IF_TABLE = "1.3.6.1.2.1.2.2.1"           # base
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"

# IF-MIB ifAlias (desc/description)
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# IP-MIB (legacy)
IP_ADDR_TABLE = "1.3.6.1.2.1.4.20.1"      # ipAdEntAddr (1), ipAdEntIfIndex (2), ipAdEntNetMask (3)
IP_ADDR = "1.3.6.1.2.1.4.20.1.1"
IP_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_NETMASK = "1.3.6.1.2.1.4.20.1.3"

# ---------- small helpers (NEW for ip_display only) ----------

def _mask_to_prefix(mask: Optional[str]) -> Optional[int]:
    """Convert dotted mask to prefix length, tolerating odd encodings."""
    if not mask:
        return None
    try:
        parts = [int(x) for x in mask.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        bits = "".join(f"{p:08b}" for p in parts)
        # Count of '1' bits is enough; we ignore non-contiguous masks
        return bits.count("1")
    except Exception:
        return None


def _format_ip_display(ips: List[Tuple[str, Optional[str], Optional[int]]]) -> Optional[str]:
    """
    Given a list of (ip, mask, prefix_len) rows, format the first value as 'a.b.c.d/yy'
    using prefix if provided, otherwise deriving from dotted mask when possible.
    """
    if not ips:
        return None
    ip, mask, pfx = ips[0]
    if pfx is None:
        pfx = _mask_to_prefix(mask)
    return f"{ip}/{pfx}" if pfx is not None else ip


# ---------- low-level SNMP helpers ----------

def _snmp_get(host: str, port: int, community: str, oid: str) -> Optional[str]:
    """Return the SNMP value as a string for a single OID or None on error."""
    try:
        engine = SnmpEngine()
        target = UdpTransportTarget((host, port), timeout=2, retries=1)
        community_data = CommunityData(community, mpModel=1)  # SNMPv2c
        context = ContextData()

        error_indication, error_status, error_index, var_binds = next(
            getCmd(engine, community_data, target, context, ObjectType(ObjectIdentity(oid)))
        )

        if error_indication or error_status:
            return None

        for name, val in var_binds:
            return str(val.prettyPrint())

    except Exception as exc:  # pragma: no cover
        _LOGGER.debug("SNMP get error for %s: %s", oid, exc)
        return None

    return None


def _snmp_walk(host: str, port: int, community: str, base_oid: str) -> List[Tuple[str, str]]:
    """Walk an OID subtree and return [(oid, value_str), ...]."""
    out: List[Tuple[str, str]] = []
    try:
        engine = SnmpEngine()
        target = UdpTransportTarget((host, port), timeout=2, retries=1)
        community_data = CommunityData(community, mpModel=1)
        context = ContextData()

        for (error_indication, error_status, error_index, var_binds) in nextCmd(
            engine,
            community_data,
            target,
            context,
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for name, val in var_binds:
                out.append((str(name.prettyPrint()), str(val.prettyPrint())))
    except Exception as exc:  # pragma: no cover
        _LOGGER.debug("SNMP walk error for %s: %s", base_oid, exc)

    return out


# ---------- Client ----------

class SwitchSnmpClient:
    """Thin SNMP client used by the integration."""

    def __init__(self, hass, host: str, port: int, community: str) -> None:
        self._hass = hass
        self._host = host
        self._port = port
        self._community = community

    # Factory
    @classmethod
    async def async_create(cls, hass, host: str, port: int, community: str) -> "SwitchSnmpClient":
        ensure_snmp_available()
        return cls(hass, host, port, community)

    # --------- Lightweight system info for sensors ---------

    async def async_get_system_info(self) -> Dict[str, Any]:
        def _read() -> Dict[str, Any]:
            sys_descr = _snmp_get(self._host, self._port, self._community, SYS_DESCR) or ""
            sys_name = _snmp_get(self._host, self._port, self._community, SYS_NAME) or ""
            sys_uptime = _snmp_get(self._host, self._port, self._community, SYS_UPTIME) or ""
            # extract firmware + vendor/model from sysDescr when possible (best-effort)
            firmware = ""
            manufacturer_model = ""
            if sys_descr:
                # Dell example: "Dell EMC Networking N3048EP-ON, 6.7.1.31, Linux ..."
                parts = [p.strip() for p in sys_descr.split(",")]
                if len(parts) >= 2:
                    manufacturer_model = parts[0]
                    firmware = parts[1]
                else:
                    manufacturer_model = sys_descr
            return {
                "sysDescr": sys_descr,
                "hostname": sys_name,
                "uptime_raw": sys_uptime,
                "firmware": firmware,
                "manufacturer_model": manufacturer_model,
            }

        return await self._hass.async_add_executor_job(_read)

    # --------- Interfaces / ports ---------

    async def async_get_interfaces(self) -> List[Dict[str, Any]]:
        """Return a list of port dicts. We keep the structure you already consume."""
        def _collect() -> List[Dict[str, Any]]:
            # Walk IF-MIB columns we use
            descr_rows = _snmp_walk(self._host, self._port, self._community, IF_DESCR)
            admin_rows = _snmp_walk(self._host, self._port, self._community, IF_ADMIN)
            oper_rows = _snmp_walk(self._host, self._port, self._community, IF_OPER)
            alias_rows = _snmp_walk(self._host, self._port, self._community, IF_ALIAS)

            # Legacy IP table (address, ifIndex, netmask)
            ip_rows = _snmp_walk(self._host, self._port, self._community, IP_ADDR)
            ifindex_rows = _snmp_walk(self._host, self._port, self._community, IP_IFINDEX)
            mask_rows = _snmp_walk(self._host, self._port, self._community, IP_NETMASK)

            # Index lookups
            def idx_from_oid(oid: str) -> Optional[int]:
                # IF-MIB uses ...1.X.index; last token is index
                try:
                    return int(oid.split(".")[-1])
                except Exception:
                    return None

            descr: Dict[int, str] = {idx_from_oid(oid): val for oid, val in descr_rows if idx_from_oid(oid) is not None}
            admin: Dict[int, int] = {idx_from_oid(oid): int(val) for oid, val in admin_rows if idx_from_oid(oid) is not None}
            oper: Dict[int, int] = {idx_from_oid(oid): int(val) for oid, val in oper_rows if idx_from_oid(oid) is not None}
            alias: Dict[int, str] = {idx_from_oid(oid): val for oid, val in alias_rows if idx_from_oid(oid) is not None}

            # Build ip -> (ifIndex, mask)
            ip_to_ifindex: Dict[str, int] = {}
            ip_to_mask: Dict[str, str] = {}
            for oid, val in ifindex_rows:
                # ...4.20.1.2.<ip> = ifIndex
                try:
                    ip = ".".join(oid.split(".")[len(IP_IFINDEX.split(".")) :])
                    ip_to_ifindex[ip] = int(val)
                except Exception:
                    continue
            for oid, val in mask_rows:
                try:
                    ip = ".".join(oid.split(".")[len(IP_NETMASK.split(".")) :])
                    ip_to_mask[ip] = val
                except Exception:
                    continue

            # Map ifIndex -> [(ip, mask, prefix_or_None)]
            idx_to_ips: Dict[int, List[Tuple[str, Optional[str], Optional[int]]]] = {}
            for _, ip in ip_rows:
                if ip in ip_to_ifindex:
                    idx = ip_to_ifindex[ip]
                    mask = ip_to_mask.get(ip)
                    idx_to_ips.setdefault(idx, []).append((ip, mask, None))

            # Compose final ports
            all_indexes = sorted(descr.keys())
            ports: List[Dict[str, Any]] = []
            for idx in all_indexes:
                d = descr.get(idx, "")
                # Skip CPU interface index 661 if present (per your earlier rule)
                if idx == 661:
                    continue

                p: Dict[str, Any] = {
                    "index": idx,
                    "descr": d,
                    "alias": alias.get(idx),
                    "admin": admin.get(idx),
                    "oper": oper.get(idx),
                    # friendly_name is built elsewhere in your repo; if you also build it here, keep it consistent
                    "friendly_name": None,
                    "ips": idx_to_ips.get(idx, []),  # list of (ip, mask, prefix_or_None)
                }

                # --- NEW: preformat a display string so UI layer doesn't infer masks ---
                p["ip_display"] = _format_ip_display(p["ips"])

                ports.append(p)

            return ports

        return await self._hass.async_add_executor_job(_collect)

    # --------- Admin state change ---------

    async def async_set_admin_state(self, if_index: int, admin_up: bool) -> None:
        """
        Set ifAdminStatus (1=up, 2=down).  Best-effort; many devices require write community.
        """
        value = 1 if admin_up else 2

        def _write() -> None:
            try:
                engine = SnmpEngine()
                target = UdpTransportTarget((self._host, self._port), timeout=2, retries=1)
                community = CommunityData(self._community, mpModel=1)  # v2c write community must match config
                context = ContextData()
                oid = f"{IF_ADMIN}.{if_index}"
                error_indication, error_status, error_index, _ = next(
                    getCmd(
                        engine,
                        community,
                        target,
                        context,
                        # Some devices allow set on IF-MIB::ifAdminStatus.<index>
                        ObjectType(ObjectIdentity(oid), Integer(value)),
                    )
                )
                if error_indication or error_status:
                    _LOGGER.debug("SNMP set ifAdminStatus failed: %s %s", error_indication, error_status)
            except Exception as exc:  # pragma: no cover
                _LOGGER.debug("SNMP set error: %s", exc)

        await self._hass.async_add_executor_job(_write)
