from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Dict, List, Optional, Tuple

from homeassistant.core import HomeAssistant


# -------------------------------------------------------------------
# Exceptions used by config_flow
# -------------------------------------------------------------------
class SnmpError(Exception):
    """Generic SNMP runtime error."""


class SnmpDependencyError(SnmpError):
    """Raised when pysnmp (or required symbols) is unavailable."""


__all__ = [
    "SnmpError",
    "SnmpDependencyError",
    "ensure_snmp_available",
    "SwitchSnmpClient",
    "IANA_IFTYPE_SOFTWARE_LOOPBACK",
    "IANA_IFTYPE_IEEE8023AD_LAG",
]

# -------------------------------------------------------------------
# Lazy pysnmp imports (no heavy/IO work at import time)
# -------------------------------------------------------------------
try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
        nextCmd,
    )
except Exception:  # pragma: no cover
    CommunityData = ContextData = ObjectIdentity = ObjectType = None  # type: ignore
    SnmpEngine = UdpTransportTarget = getCmd = nextCmd = None  # type: ignore

# -------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------
IANA_IFTYPE_SOFTWARE_LOOPBACK = 24
IANA_IFTYPE_IEEE8023AD_LAG = 161  # Port-Channel/LAG on many vendors

# IF-MIB
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IFTYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IFSPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IFADMIN = "1.3.6.1.2.1.2.2.1.7"
OID_IFOPER = "1.3.6.1.2.1.2.2.1.8"
OID_IFALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# IP-MIB (IPv4)
OID_IPADDRTABLE = "1.3.6.1.2.1.4.20.1"
OID_IPADDR_IFINDEX = OID_IPADDRTABLE + ".2"  # ipAdEntIfIndex.<addr> = ifIndex
OID_IPADDR_NETMASK = OID_IPADDRTABLE + ".3"  # ipAdEntNetMask.<addr> = netmask

# SNMPv2-MIB – system
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"


def _pysnmp_ok() -> bool:
    return all(
        (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
            nextCmd,
        )
    )


def ensure_snmp_available() -> None:
    if not _pysnmp_ok():
        raise SnmpDependencyError("pysnmp is not available")


@dataclass
class SwitchPort:
    index: int
    name: str
    alias: str
    admin: int
    oper: int
    iftype: int


class SwitchSnmpClient:
    """Minimal SNMP client. All blocking calls run in executor threads."""

    def __init__(self, hass: HomeAssistant, host: str, port: int, community: str) -> None:
        self._hass = hass
        self._host = host
        self._port = port
        # IMPORTANT: use _community_str so we never shadow a helper method
        self._community_str = community

    @classmethod
    async def async_create(
        cls, hass: HomeAssistant, host: str, port: int, community: str
    ) -> "SwitchSnmpClient":
        ensure_snmp_available()
        return cls(hass, host, port, community)

    # ----------------- low-level helpers (sync; called in executor) -----------------
    def _target(self) -> UdpTransportTarget:
        return UdpTransportTarget((self._host, self._port), timeout=2, retries=1)

    def _community_data(self) -> CommunityData:
        """Return pysnmp CommunityData from stored string."""
        return CommunityData(self._community_str, mpModel=0)

    def _get(self, oid: str) -> Optional[str]:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                self._community_data(),
                self._target(),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )
        if errorIndication or errorStatus:
            return None
        for _, val in varBinds:
            return str(val)
        return None

    def _walk(self, base_oid: str) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for (errInd, errStat, errIdx, varBinds) in nextCmd(
            SnmpEngine(),
            self._community_data(),
            self._target(),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if errInd or errStat:
                break
            for name, val in varBinds:
                out.append((str(name), str(val)))
        return out

    # ------------------------------ readers (async) --------------------------------
    async def async_get_system_info(self) -> Dict[str, str]:
        def _read() -> Dict[str, str]:
            sys_descr = self._get(OID_SYS_DESCR) or ""
            hostname = self._get(OID_SYS_NAME) or ""
            uptime_ticks = self._get(OID_SYS_UPTIME) or ""

            firmware = ""
            manuf_model = ""
            if sys_descr:
                parts = [p.strip() for p in sys_descr.split(",")]
                if parts:
                    manuf_model = parts[0]
                for p in parts[1:]:
                    if sum(ch.isdigit() for ch in p) >= 3 and "." in p:
                        firmware = p
                        break

            seconds = ""
            if uptime_ticks.isdigit():
                seconds = str(int(uptime_ticks) // 100)

            return {
                "firmware": firmware or "",
                "hostname": hostname or "",
                "manuf_model": manuf_model or "",
                "uptime": seconds or "",
            }

        return await self._hass.async_add_executor_job(_read)

    async def async_get_ports(self) -> List[SwitchPort]:
        def _read() -> List[SwitchPort]:
            descr = {oid.split(".")[-1]: val for oid, val in self._walk(OID_IFDESCR)}
            alias = {oid.split(".")[-1]: val for oid, val in self._walk(OID_IFALIAS)}
            admin = {oid.split(".")[-1]: val for oid, val in self._walk(OID_IFADMIN)}
            oper = {oid.split(".")[-1]: val for oid, val in self._walk(OID_IFOPER)}
            iftype = {oid.split(".")[-1]: val for oid, val in self._walk(OID_IFTYPE)}

            out: List[SwitchPort] = []
            for idx_str, name in descr.items():
                try:
                    idx = int(idx_str)
                except ValueError:
                    continue
                port = SwitchPort(
                    index=idx,
                    name=name,
                    alias=alias.get(idx_str, ""),
                    admin=int(admin.get(idx_str, "0") or 0),
                    oper=int(oper.get(idx_str, "0") or 0),
                    iftype=int(iftype.get(idx_str, "0") or 0),
                )
                if port.index == 661:  # skip CPU pseudo-port
                    continue
                out.append(port)
            return out

        return await self._hass.async_add_executor_job(_read)

    async def async_get_ipv4_map(self) -> Dict[int, str]:
        """Return {ifIndex: 'a.b.c.d/len'} for interfaces that have IPv4."""
        def _read() -> Dict[int, str]:
            idx_map: Dict[str, int] = {}
            for oid, val in self._walk(OID_IPADDR_IFINDEX):
                ip_parts = oid.split(".")[-4:]
                try:
                    addr = str(IPv4Address(".".join(ip_parts)))
                except Exception:
                    continue
                try:
                    idx_map[addr] = int(val)
                except ValueError:
                    continue

            mask_map: Dict[str, str] = {}
            for oid, val in self._walk(OID_IPADDR_NETMASK):
                ip_parts = oid.split(".")[-4:]
                try:
                    addr = str(IPv4Address(".".join(ip_parts)))
                except Exception:
                    continue
                mask_map[addr] = val

            out: Dict[int, str] = {}
            for addr, ifidx in idx_map.items():
                mask = mask_map.get(addr)
                if not mask:
                    continue
                try:
                    plen = IPv4Network(f"{addr}/{mask}", strict=False).prefixlen
                except Exception:
                    continue
                out[ifidx] = f"{addr}/{plen}"
            return out

        return await self._hass.async_add_executor_job(_read)

    # ------------------------------ adapter (NEW) ----------------------------------
    async def async_get_port_data(self) -> List[Dict[str, Any]]:
        """
        Adapter expected by the existing coordinator/platform.

        Returns a list of dicts with keys:
          - index, name, alias, admin, oper, iftype
          - ip  (CIDR)
          - ip_address (same CIDR, for backward compatibility)
        """
        ports = await self.async_get_ports()
        ip_map = await self.async_get_ipv4_map()

        out: List[Dict[str, Any]] = []
        for p in ports:
            ip = ip_map.get(p.index)
            item: Dict[str, Any] = {
                "index": p.index,
                "name": p.name,
                "alias": p.alias,
                "admin": p.admin,
                "oper": p.oper,
                "iftype": p.iftype,
            }
            if ip:
                item["ip"] = ip
                item["ip_address"] = ip
            out.append(item)
        return out
