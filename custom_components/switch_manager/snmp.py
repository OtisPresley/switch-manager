"""SNMP helpers for Switch Manager (surgical update).

What this provides (and is relied upon elsewhere):
- Exceptions: SnmpError, SnmpDependencyError
- reset_backend_cache()
- class SwitchSnmpClient with:
    async_create(host, community, port)
    async_close()
    async_get_system_info() -> dict
    async_get_port_data()  -> list[PortRow]
    async_set_alias(ifIndex, text)
    async_set_admin_status(ifIndex, enabled)

Surgical changes vs. prior iterations:
- Signature of async_create(host, community, port) matches config_flow/__init__.
- All pysnmp calls run in a thread executor to avoid blocking warnings.
- Collect IPv4 + mask and render as CIDR; works with IPv4 ipAddrTable (legacy) and
  tolerates devices lacking IP-MIBv2.
- Skip CPU pseudo-interface (index 661).
- Hide default/unconfigured Port-Channels (LAG) that have no alias and no IP.
- Return uptime *seconds* (sensor formats to human string).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import asyncio

# pysnmp 4.x HLAPI only (your manifest pins <5)
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
    setCmd,
    Integer,
    OctetString,
)

# ---- Exceptions kept for callers -------------------------------------------------
class SnmpError(Exception):
    """Generic SNMP error."""


class SnmpDependencyError(SnmpError):
    """Raised if pysnmp is not available/usable."""


def reset_backend_cache() -> None:
    """Compatibility shim used by config_flow/__init__ (no-op)."""
    return


# ---- IANA ifType values used by switch.py ---------------------------------------
IANA_IFTYPE_ETHERNET_CSMACD = 6
IANA_IFTYPE_SOFTWARE_LOOPBACK = 24
IANA_IFTYPE_IEEE8023AD_LAG = 161

# Some stacks expose a CPU pseudo-interface; skip it.
CPU_IFINDEX = 661

# ---- Small synchronous SNMP helpers (run in executor) ---------------------------


def _snmp_walk(host: str, port: int, community: str, oid: str) -> List[Tuple[str, str]]:
    """Basic walk returning (oid, value) as strings."""
    engine = SnmpEngine()
    out: List[Tuple[str, str]] = []
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
            out.append((str(vb[0]), str(vb[1])))
    return out


def _snmp_get(host: str, port: int, community: str, oid: str) -> Optional[str]:
    """Basic get returning the pretty-printed value or None."""
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


def _snmp_set_octetstring(host: str, port: int, community: str, oid: str, text: str) -> None:
    engine = SnmpEngine()
    err_ind, err_stat, err_idx, _ = next(
        setCmd(
            engine,
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid), OctetString(text)),
        )
    )
    if err_ind:
        raise SnmpError(str(err_ind))
    if err_stat:
        raise SnmpError(f"{err_stat.prettyPrint()} at {err_idx}")


def _snmp_set_integer(host: str, port: int, community: str, oid: str, value: int) -> None:
    engine = SnmpEngine()
    err_ind, err_stat, err_idx, _ = next(
        setCmd(
            engine,
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid), Integer(value)),
        )
    )
    if err_ind:
        raise SnmpError(str(err_ind))
    if err_stat:
        raise SnmpError(f"{err_stat.prettyPrint()} at {err_idx}")


def _mask_to_prefix(mask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except Exception:
        return 0


# ---- Public data structures ------------------------------------------------------
@dataclass
class PortRow:
    index: int
    name: str
    alias: str
    admin: int
    oper: int
    iftype: int
    ip_cidr: Optional[str] = None


# ---- Client ---------------------------------------------------------------------
class SwitchSnmpClient:
    """Simple SNMP client; all network work is offloaded to a thread."""

    def __init__(self, host: str, community: str, port: int) -> None:
        self._host = host
        self._community = community
        self._port = port

    # factory used by config_flow/__init__
    @classmethod
    async def async_create(cls, host: str, community: str, port: int) -> "SwitchSnmpClient":
        # Try constructing an engine *in the executor* so we don’t block the loop.
        def _probe() -> None:
            _ = SnmpEngine()

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, _probe)
        except Exception as err:
            raise SnmpDependencyError(f"pysnmp.hlapi import failed: {err}") from err
        return cls(host, community, port)

    async def async_close(self) -> None:
        return

    # ---------- System sensors -------------------------------------------------
    async def async_get_system_info(self) -> Dict[str, Optional[str]]:
        """Return {'hostname','firmware','manuf_model','uptime'}; uptime in SECONDS."""
        loop = asyncio.get_running_loop()

        def _read() -> Dict[str, Optional[str]]:
            sys_descr = _snmp_get(self._host, self._port, self._community, "1.3.6.1.2.1.1.1.0") or ""
            sys_name = _snmp_get(self._host, self._port, self._community, "1.3.6.1.2.1.1.5.0") or ""
            uptime_raw = _snmp_get(self._host, self._port, self._community, "1.3.6.1.2.1.1.3.0") or "0"

            # Parse firmware & manufacturer/model (best-effort, generic)
            manuf_model: Optional[str] = None
            firmware: Optional[str] = None
            parts = [p.strip() for p in sys_descr.split(",")]
            if parts:
                manuf_model = parts[0] or None
                if len(parts) > 1 and any(ch.isdigit() for ch in parts[1]):
                    firmware = parts[1]

            # sysUpTime is hundredths of seconds; convert to seconds
            try:
                ticks = int(uptime_raw.split(")")[0].split("(")[1]) if "(" in uptime_raw else int(uptime_raw)
            except Exception:
                ticks = 0
            uptime_seconds = ticks // 100

            return {
                "hostname": sys_name or None,
                "firmware": firmware,
                "manuf_model": manuf_model,
                "uptime": str(uptime_seconds),
            }

        return await loop.run_in_executor(None, _read)

    # ---------- Ports (incl. IPv4) --------------------------------------------
    async def async_get_port_data(self) -> List[PortRow]:
        """Return PortRow list; includes ip_cidr when interface has IPv4."""
        loop = asyncio.get_running_loop()

        def _read() -> List[PortRow]:
            # Base ifTable/ifXTable
            ifdescr = _snmp_walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.2")
            ifalias = _snmp_walk(self._host, self._port, self._community, "1.3.6.1.2.1.31.1.1.1.18")
            ifadmin = _snmp_walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.7")
            ifoper = _snmp_walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.8")
            iftype = _snmp_walk(self._host, self._port, self._community, "1.3.6.1.2.1.2.2.1.3")

            # Legacy IPv4 tables (widely present): ipAdEntIfIndex / ipAdEntNetMask
            ip_ifindex_by_addr: Dict[str, int] = {}
            try:
                for oid, val in _snmp_walk(self._host, self._port, self._community, "1.3.6.1.2.1.4.20.1.2"):
                    addr = ".".join(oid.split(".")[-4:])
                    ip_ifindex_by_addr[addr] = int(val)
            except Exception:
                pass

            prefix_by_addr: Dict[str, int] = {}
            try:
                for oid, val in _snmp_walk(self._host, self._port, self._community, "1.3.6.1.2.1.4.20.1.3"):
                    addr = ".".join(oid.split(".")[-4:])
                    prefix_by_addr[addr] = _mask_to_prefix(val)
            except Exception:
                pass

            # Build maps
            def idx_from_oid(oid: str) -> int:
                return int(oid.split(".")[-1])

            alias_by_idx = {idx_from_oid(o): v for o, v in ifalias}
            name_by_idx = {idx_from_oid(o): v for o, v in ifdescr}
            admin_by_idx = {idx_from_oid(o): int(v) for o, v in ifadmin}
            oper_by_idx = {idx_from_oid(o): int(v) for o, v in ifoper}
            type_by_idx = {idx_from_oid(o): int(v) for o, v in iftype}

            # Compute IPv4/CIDR per ifIndex
            ipcidr_by_ifidx: Dict[int, str] = {}
            for addr, ifidx in ip_ifindex_by_addr.items():
                bits = prefix_by_addr.get(addr)
                if bits is not None:
                    ipcidr_by_ifidx[ifidx] = f"{addr}/{bits}"

            rows: List[PortRow] = []
            for idx, name in name_by_idx.items():
                if idx == CPU_IFINDEX:
                    continue  # skip CPU pseudo-interface

                row = PortRow(
                    index=idx,
                    name=name,
                    alias=alias_by_idx.get(idx, "") or "",
                    admin=admin_by_idx.get(idx, 0),
                    oper=oper_by_idx.get(idx, 0),
                    iftype=type_by_idx.get(idx, 0),
                    ip_cidr=ipcidr_by_ifidx.get(idx),
                )

                # Hide default/unconfigured Port-Channels (IEEE8023ad LAG) that have no alias & no IP
                if row.iftype == IANA_IFTYPE_IEEE8023AD_LAG and not row.alias and not row.ip_cidr:
                    continue

                rows.append(row)

            return rows

        return await loop.run_in_executor(None, _read)

    # ---------- Mutations ------------------------------------------------------
    async def async_set_alias(self, ifindex: int, text: str) -> None:
        """Set ifAlias."""
        loop = asyncio.get_running_loop()

        def _write() -> None:
            _snmp_set_octetstring(
                self._host,
                self._port,
                self._community,
                f"1.3.6.1.2.1.31.1.1.1.18.{ifindex}",
                text,
            )

        await loop.run_in_executor(None, _write)

    async def async_set_admin_status(self, ifindex: int, enabled: bool) -> None:
        """Set ifAdminStatus: 1=up, 2=down."""
        loop = asyncio.get_running_loop()
        value = 1 if enabled else 2

        def _write() -> None:
            _snmp_set_integer(
                self._host, self._port, self._community, f"1.3.6.1.2.1.2.2.1.7.{ifindex}", value
            )

        await loop.run_in_executor(None, _write)
