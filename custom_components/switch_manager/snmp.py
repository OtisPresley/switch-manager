"""
SNMP helpers for Switch Manager.

This version is intentionally conservative:
- keeps the public API/exports used elsewhere in the integration
- adds IPv4 address collection (CIDR) and system info parsing
- skips the CPU pseudo-interface (index 661)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
)
from homeassistant.core import HomeAssistant

# ---- Public exceptions kept for config_flow / callers ------------------------

class SnmpError(Exception):
    """Generic SNMP error."""

class SnmpDependencyError(SnmpError):
    """Raised if pysnmp is not available (kept for backward compat)."""


def ensure_snmp_available() -> None:
    """Compatibility shim: just ensure we can construct an engine."""
    # Do NOT scan mib folders (that caused listdir/open warnings before)
    _ = SnmpEngine()


# ---- IANA ifType values that other files import ------------------------------
IANA_IFTYPE_ETHERNET_CSMACD = 6
IANA_IFTYPE_L2VLAN = 135
IANA_IFTYPE_SOFTWARE_LOOPBACK = 24
IANA_IFTYPE_IEEE8023AD_LAG = 161
IANA_IFTYPE_PROP_MULTILINK_BUNDLE = 54  # seen on some stacks as TenGig group

CPU_IFINDEX = 661  # skip this pseudo interface


# ---- Small helpers -----------------------------------------------------------

def _walk(host: str, port: int, community: str, oid: str) -> List[Tuple[str, str]]:
    """SNMP walk that returns (oid, value) strings."""
    engine = SnmpEngine()
    result: List[Tuple[str, str]] = []
    for (err_ind, err_stat, err_idx, var_binds) in nextCmd(
        engine,
        CommunityData(community, mpModel=1),  # v2c
        UdpTransportTarget((host, port), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    ):
        if err_ind:
            raise SnmpError(str(err_ind))
        if err_stat:
            raise SnmpError(f"{err_stat.prettyPrint()} at {err_idx}")
        for vb in var_binds:
            result.append((str(vb[0]), str(vb[1])))
    return result


def _get(host: str, port: int, community: str, oid: str) -> Optional[str]:
    """SNMP get that returns the string value or None."""
    engine = SnmpEngine()
    err_ind, err_stat, err_idx, var_binds = next(
        getCmd(
            engine,
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
    )
    if err_ind:
        raise SnmpError(str(err_ind))
    if err_stat:
        raise SnmpError(f"{err_stat.prettyPrint()} at {err_idx}")
    return str(var_binds[0][1]) if var_binds else None


def _ticks_to_hms(ticks: int) -> str:
    # sysUpTime is hundredths of a second
    seconds = ticks // 100
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{days} days, {hours:02d}:{minutes:02d}:{seconds:02d}"


@dataclass
class PortRow:
    index: int
    name: str
    alias: str
    admin: int
    oper: int
    iftype: int
    ip_cidr: Optional[str] = None


# ---- Client ------------------------------------------------------------------

class SwitchSnmpClient:
    """Simple SNMP client used by the integration."""

    def __init__(self, hass: HomeAssistant, host: str, port: int, community: str) -> None:
        self._hass = hass
        self._host = host
        self._port = port
        self._community = community

    # Factory used by config_flow and setup
    @classmethod
    async def async_create(
        cls, hass: HomeAssistant, host: str, port: int, community: str
    ) -> "SwitchSnmpClient":
        ensure_snmp_available()
        return cls(hass, host, port, community)

    # ------------- System info (for sensors) ----------------------------------

    async def async_get_system_info(self) -> Dict[str, Optional[str]]:
        def _read() -> Dict[str, Optional[str]]:
            sys_descr = _get(self._host, self._port, self._community, "1.3.6.1.2.1.1.1.0") or ""
            sys_name = _get(self._host, self._port, self._community, "1.3.6.1.2.1.1.5.0") or ""
            uptime_raw = _get(self._host, self._port, self._community, "1.3.6.1.2.1.1.3.0") or "0"

            # Parse manufacturer/model & firmware from sysDescr if it resembles:
            # "Dell EMC Networking N3048EP-ON, 6.7.1.31, Linux 4..., v1..."
            manufacturer_model = None
            firmware = None
            parts = [p.strip() for p in sys_descr.split(",")]
            if parts:
                # first part is usually vendor + model
                manufacturer_model = parts[0] or None
                # second part is often firmware
                if len(parts) > 1 and parts[1] and any(ch.isdigit() for ch in parts[1]):
                    firmware = parts[1]

            # uptime
            try:
                uptime_ticks = int(uptime_raw.split(")")[0].split("(")[1]) if "(" in uptime_raw else int(uptime_raw)
            except Exception:
                uptime_ticks = 0
            uptime = _ticks_to_hms(uptime_ticks)

            return {
                "hostname": sys_name or None,
                "firmware": firmware,
                "manufacturer_model": manufacturer_model,
                "uptime": uptime,
            }

        return await self._hass.async_add_executor_job(_read)

    # ------------- Port table + IPv4 addresses --------------------------------

    async def async_get_port_data(self) -> List[PortRow]:
        """Return a list of PortRow with optional ip_cidr filled in."""
        def _read() -> List[PortRow]:
            # Base tables
            ifdescr = _walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.2")
            ifalias = _walk(self._host, self._port, self._community, "1.3.6.1.2.1.31.1.1.1.18")
            ifadmin = _walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.7")
            ifoper  = _walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.8")
            iftype  = _walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.3")

            # IPv4 addresses (try IP-MIBv2 first, then legacy ipAddrTable)
            # ipAddressIfIndex.ipv4.<a>.<b>.<c>.<d>
            ip_ifindex_by_addr: Dict[str, int] = {}
            try:
                for oid, val in _walk(self._host, self._port, self._community, "1.3.6.1.2.1.4.34.1.3"):
                    # oid ends with ".1.4.A.B.C.D" for IPv4
                    tail = oid.split(".")[-5:]
                    if tail[0] == "1" and tail[1] == "4":
                        addr = ".".join(tail[2:])
                        ip_ifindex_by_addr[addr] = int(val)
            except Exception:
                pass

            # ipAddressPrefix.ipv4.<a>.<b>.<c>.<d> -> ipAddressPrefixTable index (we then read prefix length)
            # Fall back to legacy ipAddrTable if needed
            prefix_by_addr: Dict[str, int] = {}
            try:
                # ipAddressPrefix table: 1.3.6.1.2.1.4.34.1.5 => OID to inetCidrRoute / but vendors vary.
                # Many devices lack this; we’ll try legacy mask table below.
                pass
            except Exception:
                pass

            if not prefix_by_addr:
                # Legacy ipAdEntIfIndex/ipAdEntNetMask
                idx_by_addr_legacy = dict(
                    (oid.split(".")[-4:], (oid.split(".")[-4:], val)) for oid, val in []
                )  # placeholder—just to keep shape if someone reads later
                try:
                    for oid, val in _walk(self._host, self._port, self._community, "1.3.6.1.2.1.4.20.1.2"):
                        addr = ".".join(oid.split(".")[-4:])
                        ip_ifindex_by_addr.setdefault(addr, int(val))
                except Exception:
                    pass
                try:
                    for oid, val in _walk(self._host, self._port, self._community, "1.3.6.1.2.1.4.20.1.3"):
                        addr = ".".join(oid.split(".")[-4:])
                        # Convert dotted mask to prefix bits
                        try:
                            bits = sum(bin(int(octet)).count("1") for octet in addr_mask_split(val))
                        except Exception:
                            bits = dotted_mask_to_bits(val)
                        prefix_by_addr[addr] = bits
                except Exception:
                    pass

            # Build map ifIndex -> best IPv4/CIDR string
            ipcidr_by_ifindex: Dict[int, str] = {}
            for addr, ifidx in ip_ifindex_by_addr.items():
                bits = prefix_by_addr.get(addr)
                if bits is not None:
                    ipcidr_by_ifindex[ifidx] = f"{addr}/{bits}"

            # Index helpers
            def idx_from_oid(oid: str) -> int:
                return int(oid.split(".")[-1])

            alias_by_idx = {idx_from_oid(o): v for o, v in ifalias}
            name_by_idx  = {idx_from_oid(o): v for o, v in ifdescr}
            admin_by_idx = {idx_from_oid(o): int(v) for o, v in ifadmin}
            oper_by_idx  = {idx_from_oid(o): int(v) for o, v in ifoper}
            type_by_idx  = {idx_from_oid(o): int(v) for o, v in iftype}

            rows: List[PortRow] = []
            for idx, name in name_by_idx.items():
                if idx == CPU_IFINDEX:
                    continue  # skip CPU pseudo interface

                row = PortRow(
                    index=idx,
                    name=name,
                    alias=alias_by_idx.get(idx, "") or "",
                    admin=admin_by_idx.get(idx, 0),
                    oper=oper_by_idx.get(idx, 0),
                    iftype=type_by_idx.get(idx, 0),
                    ip_cidr=ipcidr_by_ifindex.get(idx),
                )

                # Filter out default/unconfigured Port-Channels (LAG) with no alias + no IP
                if row.iftype == IANA_IFTYPE_IEEE8023AD_LAG and not row.alias and not row.ip_cidr:
                    # Many stacks ship Po1..Po128 precreated; hide them unless they have some config signal
                    continue

                rows.append(row)

            return rows

        return await self._hass.async_add_executor_job(_read)


# ---- tiny utilities used above (pure functions, fast) ------------------------

def dotted_mask_to_bits(mask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except Exception:
        return 0

def addr_mask_split(mask: str) -> List[str]:  # keeps typing happy in the executor
    return mask.split(".")
