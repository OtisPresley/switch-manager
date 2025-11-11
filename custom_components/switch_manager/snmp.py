from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Dict, List, Optional, Tuple

from homeassistant.core import HomeAssistant

# NOTE: keep imports lightweight at module import time (avoid SnmpEngine() etc)
try:
    # pysnmp (lextudio) – classic sync hlapi
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

# --- IANA ifType values we need to filter/nickname (DO NOT remove) ----------------
IANA_IFTYPE_SOFTWARE_LOOPBACK = 24
IANA_IFTYPE_IEEE8023AD_LAG = 161  # port-channel/LAG on many vendors

# --- MIB/OIDs used (kept local to avoid const churn) ------------------------------
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


def _ok() -> bool:
    """Return True if pysnmp imports are available."""
    return all((CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, getCmd, nextCmd))


@dataclass
class SwitchPort:
    index: int
    name: str
    alias: str
    admin: int
    oper: int
    iftype: int


class SnmpError(Exception):
    pass


class SwitchSnmpClient:
    """Very small SNMP helper. Keep all blocking calls inside executor jobs."""

    def __init__(self, hass: HomeAssistant, host: str, port: int, community: str) -> None:
        self._hass = hass
        self._host = host
        self._port = port
        self._community = community

    # ---------------------------- Factory -------------------------------------
    @classmethod
    async def async_create(cls, hass: HomeAssistant, host: str, port: int, community: str) -> "SwitchSnmpClient":
        if not _ok():
            raise SnmpError("pysnmp not available")
        return cls(hass, host, port, community)

    # ----------------------------- Low level ----------------------------------
    def _target(self) -> UdpTransportTarget:
        return UdpTransportTarget((self._host, self._port), timeout=2, retries=1)

    def _community(self) -> CommunityData:
        return CommunityData(self._community, mpModel=0)

    def _get(self, oid: str) -> Optional[str]:
        """Sync GET – returns stringified value or None."""
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                self._community(),
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
        """Sync WALK – returns list of (oid,indexed), value as strings."""
        out: List[Tuple[str, str]] = []
        for (errInd, errStat, errIdx, varBinds) in nextCmd(
            SnmpEngine(),
            self._community(),
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

    # ------------------------------ Readers -----------------------------------
    async def async_get_system_info(self) -> Dict[str, str]:
        """Return firmware, hostname, manufacturer+model, uptime (seconds)."""
        def _read() -> Dict[str, str]:
            sys_descr = self._get(OID_SYS_DESCR) or ""
            hostname = self._get(OID_SYS_NAME) or ""
            uptime_ticks = self._get(OID_SYS_UPTIME) or ""
            firmware = ""
            manuf_model = ""

            # Cheap & resilient parser: "Vendor Model, 6.7.1.31, ..." -> split by ','
            if sys_descr:
                parts = [p.strip() for p in sys_descr.split(",")]
                if parts:
                    manuf_model = parts[0]
                for p in parts[1:]:
                    # first token that looks like x.y.z or similar
                    if sum(ch.isdigit() for ch in p) >= 3 and "." in p:
                        firmware = p
                        break

            # uptime in seconds (from Timeticks)
            seconds = ""
            if uptime_ticks.isdigit():
                # Timeticks are 1/100s
                seconds = str(int(uptime_ticks) // 100)

            return {
                "firmware": firmware or "",
                "hostname": hostname or "",
                "manuf_model": manuf_model or "",
                "uptime": seconds or "",
            }

        return await self._hass.async_add_executor_job(_read)

    async def async_get_ports(self) -> List[SwitchPort]:
        """Walk interface table and return normalized ports."""
        def _read() -> List[SwitchPort]:
            # index -> fields
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
                p = SwitchPort(
                    index=idx,
                    name=name,
                    alias=alias.get(idx_str, ""),
                    admin=int(admin.get(idx_str, "0") or 0),
                    oper=int(oper.get(idx_str, "0") or 0),
                    iftype=int(iftype.get(idx_str, "0") or 0),
                )
                # Skip known "CPU" pseudo-ifIndex seen on some stacks (661 was reported)
                if p.index == 661:
                    continue
                out.append(p)
            return out

        return await self._hass.async_add_executor_job(_read)

    async def async_get_ipv4_map(self) -> Dict[int, str]:
        """Return {ifIndex: 'a.b.c.d/len'} for interfaces that have IPv4."""
        def _read() -> Dict[int, str]:
            # ipAdEntIfIndex.<addr> => ifIndex
            idx_map: Dict[str, int] = {}
            for oid, val in self._walk(OID_IPADDR_IFINDEX):
                ip = oid.split(".")[-4:]  # last 4 components are the IPv4
                try:
                    addr = str(IPv4Address(".".join(ip)))
                except Exception:
                    continue
                try:
                    idx_map[addr] = int(val)
                except ValueError:
                    continue

            # ipAdEntNetMask.<addr> => netmask
            mask_map: Dict[str, str] = {}
            for oid, val in self._walk(OID_IPADDR_NETMASK):
                ip = oid.split(".")[-4:]
                try:
                    addr = str(IPv4Address(".".join(ip)))
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
