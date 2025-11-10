from __future__ import annotations

import asyncio
import importlib
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "SnmpError",
    "SnmpDependencyError",
    "SwitchSnmpClient",
    "ensure_snmp_available",
    "validate_environment_or_raise",
    "reset_backend_cache",
    "snmp_get",
    "snmp_walk",
    "snmp_set_octet_string",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SnmpError(RuntimeError):
    """Base SNMP error for this integration."""


class SnmpDependencyError(SnmpError):
    """Raised when pysnmp cannot be imported/used."""


# ---------------------------------------------------------------------------
# Lazy HLAPI import with a tiny in-module cache
# ---------------------------------------------------------------------------

_IMPORTS_CACHE: Optional[Tuple[Any, ...]] = None


def _imports() -> Tuple[Any, ...]:
    """Lazy-import pysnmp HLAPI so HA can install requirements first."""
    global _IMPORTS_CACHE
    if _IMPORTS_CACHE is not None:
        return _IMPORTS_CACHE

    try:
        pysnmp_mod = importlib.import_module("pysnmp")
        _LOGGER.debug(
            "Switch Manager using pysnmp from %s (version=%s)",
            getattr(pysnmp_mod, "__file__", "?"),
            getattr(pysnmp_mod, "__version__", "?"),
        )

        from pysnmp.hlapi import (  # type: ignore
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            getCmd,
            nextCmd,
            setCmd,
        )
    except Exception as exc:
        raise SnmpDependencyError(f"pysnmp.hlapi import failed: {exc}")

    _IMPORTS_CACHE = (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        nextCmd,
        setCmd,
    )
    return _IMPORTS_CACHE


def reset_backend_cache() -> None:
    """Clear our small import cache (mainly for tests)."""
    global _IMPORTS_CACHE
    _IMPORTS_CACHE = None


# ---------------------------------------------------------------------------
# Low-level helpers (sync)
# ---------------------------------------------------------------------------

def ensure_snmp_available() -> None:
    """Verify HLAPI is importable (raises SnmpDependencyError on failure)."""
    _imports()


def validate_environment_or_raise() -> None:
    """Back-compat alias used by older code paths."""
    ensure_snmp_available()


def snmp_get(host: str, community: str, port: int, oid: str) -> Any:
    (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        _nextCmd,
        _setCmd,
    ) = _imports()

    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # SNMP v2c
        UdpTransportTarget((host, int(port))),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )

    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication:
        raise SnmpError(error_indication)
    if error_status:
        where = var_binds[int(error_index) - 1][0] if error_index else "?"
        raise SnmpError(f"{error_status.prettyPrint()} at {where}")
    return var_binds[0][1]


def snmp_walk(host: str, community: str, port: int, base_oid: str) -> Iterable[Tuple[str, Any]]:
    (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        _getCmd,
        nextCmd,
        _setCmd,
    ) = _imports()

    for (err_ind, err_stat, err_idx, var_binds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, int(port))),
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    ):
        if err_ind:
            raise SnmpError(err_ind)
        if err_stat:
            where = var_binds[int(err_idx) - 1][0] if err_idx else "?"
            raise SnmpError(f"{err_stat.prettyPrint()} at {where}")
        for name, val in var_binds:
            yield (str(name), val)


def snmp_set_octet_string(host: str, community: str, port: int, oid: str, value: Any) -> None:
    (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        _getCmd,
        _nextCmd,
        setCmd,
    ) = _imports()

    err_ind, err_stat, err_idx, var_binds = next(
        setCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, int(port))),
            ContextData(),
            ObjectType(ObjectIdentity(oid), value),
        )
    )
    if err_ind:
        raise SnmpError(err_ind)
    if err_stat:
        where = var_binds[int(err_idx) - 1][0] if err_idx else "?"
        raise SnmpError(f"{err_stat.prettyPrint()} at {where}")


# ---------------------------------------------------------------------------
# High-level client (sync + async wrappers)
# ---------------------------------------------------------------------------

class SwitchSnmpClient:
    """
    Thin wrapper preserved for compatibility with the integration.

    Provides simple get/walk/set methods bound to a host/community/port, plus
    async wrappers (executor-offloaded) for Home Assistant.
    """

    # IF-MIB OIDs
    OID_ifDescr = "1.3.6.1.2.1.2.2.1.2"
    OID_ifAdminStatus = "1.3.6.1.2.1.2.2.1.7"
    OID_ifOperStatus = "1.3.6.1.2.1.2.2.1.8"
    OID_ifAlias = "1.3.6.1.2.1.31.1.1.1.18"  # IF-MIB::ifAlias (port description)

    # SNMPv2-MIB::system OIDs
    OID_sysDescr = "1.3.6.1.2.1.1.1.0"
    OID_sysObjectID = "1.3.6.1.2.1.1.2.0"
    OID_sysUpTime = "1.3.6.1.2.1.1.3.0"  # hundredths of a second
    OID_sysName = "1.3.6.1.2.1.1.5.0"

    # IP-MIB (IPv4 classic table)
    OID_ipAdEntAddr = "1.3.6.1.2.1.4.20.1.1"
    OID_ipAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2"
    OID_ipAdEntNetMask = "1.3.6.1.2.1.4.20.1.3"

    def __init__(self, hass: Any, host: str, community: str, port: int = 161) -> None:
        self._hass = hass  # may be None
        self._host = host
        self._community = community
        self._port = int(port)

    # ----- tolerant factory: (hass, host, community, port) OR (host, community, port[, hass])

    @classmethod
    async def async_create(cls, *args: Any) -> "SwitchSnmpClient":
        if not args:
            raise SnmpError("async_create requires arguments")

        hass: Any = None
        host: str
        community: str
        port: int = 161

        first = args[0]
        if hasattr(first, "async_add_executor_job"):
            # (hass, host, community, port)
            hass = first
            host = args[1]
            community = args[2]
            port = int(args[3]) if len(args) > 3 else 161
        else:
            # (host, community, port[, hass])
            host = args[0]
            community = args[1]
            port = int(args[2]) if len(args) > 2 else 161
            hass = args[3] if len(args) > 3 and hasattr(args[3], "async_add_executor_job") else None

        if hass is not None:
            await hass.async_add_executor_job(ensure_snmp_available)
        else:
            ensure_snmp_available()

        return cls(hass, host, community, port)

    # ----- sync helpers ------------------------------------------------------

    def get(self, oid: str) -> Any:
        return snmp_get(self._host, self._community, self._port, oid)

    def walk(self, base_oid: str) -> Iterable[Tuple[str, Any]]:
        return snmp_walk(self._host, self._community, self._port, base_oid)

    def set_octet_string(self, oid: str, value: Any) -> None:
        snmp_set_octet_string(self._host, self._community, self._port, oid, value)

    # ----- async helpers -----------------------------------------------------

    async def async_get(self, oid: str) -> Any:
        if self._hass is not None:
            return await self._hass.async_add_executor_job(
                snmp_get, self._host, self._community, self._port, oid
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, snmp_get, self._host, self._community, self._port, oid)

    async def async_walk(self, base_oid: str) -> Iterable[Tuple[str, Any]]:
        if self._hass is not None:
            return await self._hass.async_add_executor_job(
                lambda: list(snmp_walk(self._host, self._community, self._port, base_oid))
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: list(snmp_walk(self._host, self._community, self._port, base_oid))
        )

    async def async_set_octet_string(self, oid: str, value: Any) -> None:
        if self._hass is not None:
            await self._hass.async_add_executor_job(
                snmp_set_octet_string, self._host, self._community, self._port, oid, value
            )
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, snmp_set_octet_string, self._host, self._community, self._port, oid, value)

    # ----- higher-level helpers used by coordinator --------------------------

    def _get_ipv4_table(self) -> Dict[int, List[Dict[str, str]]]:
        """Build {ifIndex: [{address, netmask}, ...]} from legacy IP-MIB ipAddrTable."""
        by_addr_if = {str(addr): int(idx) for addr, idx in self.walk(self.OID_ipAdEntIfIndex)}
        by_addr_mask = {str(addr): str(mask) for addr, mask in self.walk(self.OID_ipAdEntNetMask)}
        result: Dict[int, List[Dict[str, str]]] = {}
        for addr, ifindex in by_addr_if.items():
            result.setdefault(ifindex, []).append(
                {"address": addr, "netmask": by_addr_mask.get(addr, "")}
            )
        return result

    def _get_ipv4_table_v2(self) -> Dict[int, List[Dict[str, str]]]:
        """
        Fallback for devices that only populate IP-MIBv2 ipAddressTable (RFC 4293).

        We parse:
          ipAddressIfIndex:      1.3.6.1.2.1.4.34.1.3
          ipAddressPrefixLength: 1.3.6.1.2.1.4.34.1.5    (for IPv4 rows)

        Index is (addrType, addrBytes...). We only keep addrType==2 (IPv4).
        """
        IFIDX_OID = "1.3.6.1.2.1.4.34.1.3"
        PLEN_OID = "1.3.6.1.2.1.4.34.1.5"

        def _parse_ipv4_from_index(oid_str: str) -> str | None:
            try:
                parts = [int(x) for x in oid_str.split(".")]
                # choose shorter base of the two OIDs above (they share the same suffix format)
                base_len = len([int(x) for x in IFIDX_OID.split(".")])
                suffix = parts[base_len:]
                if not suffix:
                    return None
                addr_type = suffix[0]  # InetAddressType: 2 == ipv4
                if addr_type != 2 or len(suffix) < 5:
                    return None
                # some stacks add a length=4 before the octets, some don't
                if len(suffix) >= 6 and suffix[1] == 4:
                    octets = suffix[2:6]
                else:
                    octets = suffix[1:5]
                return ".".join(str(b) for b in octets)
            except Exception:
                return None

        by_addr_if: Dict[str, int] = {}
        for oid, ifidx in self.walk(IFIDX_OID):
            addr = _parse_ipv4_from_index(oid)
            if addr:
                try:
                    by_addr_if[addr] = int(ifidx)
                except Exception:
                    continue

        by_addr_plen: Dict[str, int] = {}
        for oid, plen in self.walk(PLEN_OID):
            addr = _parse_ipv4_from_index(oid)
            if addr:
                try:
                    by_addr_plen[addr] = int(plen)
                except Exception:
                    continue

        result: Dict[int, List[Dict[str, str]]] = {}
        for addr, ifindex in by_addr_if.items():
            plen = by_addr_plen.get(addr)
            netmask = ""
            if plen is not None and 0 <= plen <= 32:
                try:
                    import ipaddress as _ip
                    netmask = str(_ip.IPv4Network(f"0.0.0.0/{plen}").netmask)
                except Exception:
                    netmask = ""
            result.setdefault(ifindex, []).append({"address": addr, "netmask": netmask})
        return result

    def get_port_data(self) -> Dict[int, Dict[str, Any]]:
        """
        Gather port data from IF-MIB and merge IPv4 addresses where present.

        Returns dict keyed by ifIndex with fields: index,name,admin,oper,alias,ipv4(list)
        """
        descr = {int(oid.split(".")[-1]): str(val) for oid, val in self.walk(self.OID_ifDescr)}
        admin = {int(oid.split(".")[-1]): int(val) for oid, val in self.walk(self.OID_ifAdminStatus)}
        oper = {int(oid.split(".")[-1]): int(val) for oid, val in self.walk(self.OID_ifOperStatus)}
        alias = {int(oid.split(".")[-1]): str(val) for oid, val in self.walk(self.OID_ifAlias)}

        ipv4 = self._get_ipv4_table()
        if not ipv4:
            try:
                ipv4 = self._get_ipv4_table_v2()
            except Exception as exc:
                _LOGGER.debug("ipAddressTable (v2) parse failed: %s", exc)

        indices = set(descr) | set(admin) | set(oper) | set(alias) | set(ipv4)
        out: Dict[int, Dict[str, Any]] = {}
        for idx in sorted(indices):
            out[idx] = {
                "index": idx,
                "name": descr.get(idx, ""),
                "admin": admin.get(idx, 0),
                "oper": oper.get(idx, 0),
                "alias": alias.get(idx, ""),
                "ipv4": ipv4.get(idx, []),
            }
        return out

    async def async_get_port_data(self) -> Dict[int, Dict[str, Any]]:
        if self._hass is not None:
            return await self._hass.async_add_executor_job(self.get_port_data)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.get_port_data)

    @staticmethod
    def _parse_sys_fields(sys_descr: str) -> Dict[str, str]:
        """
        Parse manufacturer/model/firmware out of a general sysDescr string.

        Example:
          "Dell EMC Networking N3048EP-ON, 6.7.1.31, Linux 4.14.174, v1.0.5"
          -> manufacturer="Dell EMC Networking", model="N3048EP-ON", firmware="6.7.1.31"
        """
        manufacturer = ""
        model = ""
        firmware = ""

        head = sys_descr.split(",", 1)[0].strip()
        if head:
            parts = head.split()
            if len(parts) >= 2:
                manufacturer = " ".join(parts[:-1])
                model = parts[-1]
            else:
                manufacturer = head

        m_fw = re.search(r"\b\d+\.\d+(?:\.\d+){0,2}\b", sys_descr)
        if m_fw:
            firmware = m_fw.group(0)

        return {"manufacturer": manufacturer, "model": model, "firmware": firmware}

    @staticmethod
    def _format_uptime(ticks: int) -> str:
        """Return a pretty uptime from Timeticks (1/100s)."""
        total_centis = int(ticks)
        total_secs = total_centis // 100
        days, rem = divmod(total_secs, 86400)
        hours, rem = divmod(rem, 3600)
        mins, secs = divmod(rem, 60)
        centis = total_centis % 100
        return f"{days} days, {hours:02d}:{mins:02d}:{secs:02d}.{centis:02d}"

    def get_system_info(self) -> Dict[str, Any]:
        """Collect basic system info from SNMPv2-MIB::system."""
        sys_descr = str(self.get(self.OID_sysDescr))
        sys_object_id = str(self.get(self.OID_sysObjectID))
        sys_name = str(self.get(self.OID_sysName))
        uptime_ticks = int(self.get(self.OID_sysUpTime))  # hundredths
        uptime_seconds = int(uptime_ticks // 100)

        fields = self._parse_sys_fields(sys_descr)

        return {
            **fields,
            "hostname": sys_name,
            "uptime_seconds": uptime_seconds,
            "uptime_ticks": uptime_ticks,
            "uptime": self._format_uptime(uptime_ticks),
            "sys_descr": sys_descr,
            "sys_object_id": sys_object_id,
        }

    async def async_get_system_info(self) -> Dict[str, Any]:
        if self._hass is not None:
            return await self._hass.async_add_executor_job(self.get_system_info)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.get_system_info)
