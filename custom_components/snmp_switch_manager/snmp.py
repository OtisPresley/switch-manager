from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Iterable, Tuple, List

from homeassistant.core import HomeAssistant

from .snmp_compat import (
    CommunityData,
    SnmpEngine,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    next_cmd,
    set_cmd,
    OctetString,
    Integer,
)

# Canonical OIDs from const.py (original repo)
from .const import (
    OID_sysDescr,
    OID_sysName,
    OID_sysUpTime,
    OID_ifIndex,
    OID_ifDescr,
    OID_ifAdminStatus,
    OID_ifOperStatus,
    OID_ifName,
    OID_ifAlias,
    OID_ipAdEntAddr,
    OID_ipAdEntIfIndex,
    OID_ipAdEntNetMask,
    OID_entPhysicalModelName,
)

_LOGGER = logging.getLogger(__name__)

# Extra OIDs used in the original repo’s IP logic (not in const.py)
# (2) ipAddressIfIndex index suffix encodes IPv4 as: 1.4.a.b.c.d
OID_ipAddressIfIndex = "1.3.6.1.2.1.4.34.1.3"
# (3) OSPF-MIB ip address (suffix carries a.b.c.d.<ifIndex>.<area...>)
OID_ospfIfIpAddress = "1.3.6.1.2.1.14.8.1.1"
# (4) IP-FORWARD-MIB route column – instance includes dest + prefixLen (vendor-variant index)
# we read column 9 (.9) because any column shares the same index layout
OID_routeCol = "1.3.6.1.2.1.4.24.7.1.9"


# ---------- low-level sync helpers offloaded by compat -------------

async def _do_get_one(engine, community, target, context, oid: str) -> Optional[str]:
    err_ind, err_stat, err_idx, vbs = await get_cmd(
        engine,
        community,
        target,
        context,
        ObjectType(ObjectIdentity(oid)),
        lookupMib=False,  # <<< prevent FS MIB access
    )
    if err_ind or err_stat:
        return None
    for vb in vbs:
        return str(vb[1])
    return None


async def _do_next_walk(
    engine, community, target, context, base_oid: str
) -> Iterable[Tuple[str, Any]]:
    current_oid = base_oid
    seen: set[str] = set()
    while True:
        err_ind, err_stat, err_idx, vbs = await next_cmd(
            engine,
            community,
            target,
            context,
            ObjectType(ObjectIdentity(current_oid)),
            lexicographicMode=False,
            lookupMib=False,  # <<< prevent FS MIB access
        )
        if err_ind or err_stat or not vbs:
            break

        advanced = False
        for vb in vbs:
            oid_obj, val = vb
            oid_str = str(oid_obj)
            if not (oid_str == base_oid or oid_str.startswith(base_oid + ".")):
                return
            if oid_str in seen:
                return
            seen.add(oid_str)
            yield oid_str, val
            current_oid = oid_str
            advanced = True

        if not advanced:
            break


async def _do_set_alias(
    engine, community, target, context, if_index: int, alias: str
) -> bool:
    err_ind, err_stat, err_idx, _ = await set_cmd(
        engine,
        community,
        target,
        context,
        ObjectType(ObjectIdentity(f"{OID_ifAlias}.{if_index}"), OctetString(alias)),
        lookupMib=False,  # <<< prevent FS MIB access
    )
    return (not err_ind) and (not err_stat)


async def _do_set_admin_status(
    engine, community, target, context, if_index: int, value: int
) -> bool:
    err_ind, err_stat, err_idx, _ = await set_cmd(
        engine,
        community,
        target,
        context,
        ObjectType(ObjectIdentity(f"{OID_ifAdminStatus}.{if_index}")), Integer(value),
        lookupMib=False,  # <<< prevent FS MIB access
    )
    return (not err_ind) and (not err_stat)


# ---------- client ----------

class SwitchSnmpClient:
    """SNMP client using PySNMP v7 asyncio API."""

    def __init__(self, hass: HomeAssistant, host: str, community: str, port: int) -> None:
        self.hass = hass
        self.host = host
        self.community = community
        self.port = port

        self.engine = None
        self.target = None
        self._target_args = ((host, port),)
        self._target_kwargs = dict(timeout=1.5, retries=1)

        self.community_data = CommunityData(community, mpModel=1)  # v2c
        self.context = ContextData()

        self.cache: Dict[str, Any] = {
            "sysDescr": None,
            "sysName": None,
            "sysUpTime": None,
            "ifTable": {},
            "ipIndex": {},
            "ipMask": {},
            "manufacturer": None,
            "model": None,
            "firmware": None,
        }

    async def _ensure_engine(self) -> None:
        if self.engine is not None:
            return

        def _build_engine_with_minimal_preload():
            eng = SnmpEngine()
            try:
                mib_builder = eng.getMibBuilder()
                try:
                    mib_builder.setMibSources()  # clear FS sources
                except TypeError:
                    pass
                try:
                    mib_builder.loadModules("SNMPv2-SMI", "SNMPv2-MIB", "__SNMPv2-MIB", "PYSNMP-SOURCE-MIB")
                except Exception:
                    pass
            except Exception:
                pass
            return eng

        self.engine = await self.hass.async_add_executor_job(_build_engine_with_minimal_preload)

    async def _ensure_target(self) -> None:
        if self.target is None:
            self.target = await UdpTransportTarget.create(*self._target_args, **self._target_kwargs)

    # ---------- lifecycle / fetch ----------

    async def async_initialize(self) -> None:
        await self._ensure_engine()
        await self._ensure_target()

        # Build interface table and state first (names, alias, admin/oper)
        await self._async_walk_interfaces(dynamic_only=False)

        # Build IPv4 maps and attach to interfaces (original repo logic)
        await self._async_walk_ipv4()
        self._attach_ipv4_to_interfaces()

        # System fields
        self.cache["sysDescr"] = await self._async_get_one(OID_sysDescr)
        self.cache["sysName"] = await self._async_get_one(OID_sysName)
        self.cache["sysUpTime"] = await self._async_get_one(OID_sysUpTime)

        # Model hint (optional)
        ent_models = await self._async_walk(OID_entPhysicalModelName)
        model_hint = None
        for _oid, val in ent_models:
            s = str(val).strip()
            if s:
                model_hint = s
                break
        self.cache["model"] = model_hint

        # Manufacturer / firmware parsing from sysDescr (unchanged behavior)
        sd = (self.cache.get("sysDescr") or "").strip()
        manufacturer = None
        firmware = None
        if sd:
            parts = [p.strip() for p in sd.split(",")]
            if len(parts) >= 2:
                firmware = parts[1] or None
            head = parts[0]
            if model_hint and model_hint in head:
                manufacturer = head.replace(model_hint, "").strip()
            else:
                toks = head.split()
                if len(toks) > 1:
                    manufacturer = " ".join(toks[:-1])
        self.cache["manufacturer"] = manufacturer
        self.cache["firmware"] = firmware

    async def _async_get_one(self, oid: str) -> Optional[str]:
        await self._ensure_engine()
        await self._ensure_target()
        return await _do_get_one(self.engine, self.community_data, self.target, self.context, oid)

    async def _async_walk(self, base_oid: str) -> list[tuple[str, Any]]:
        await self._ensure_engine()
        await self._ensure_target()
        out: list[tuple[str, Any]] = []
        async for oid_str, val in _do_next_walk(self.engine, self.community_data, self.target, self.context, base_oid):
            out.append((oid_str, val))
        return out

    async def _async_walk_interfaces(self, dynamic_only: bool = False) -> None:
        if not dynamic_only:
            self.cache["ifTable"] = {}

            # Indexes
            for oid, val in await self._async_walk(OID_ifIndex):
                idx = int(oid.split(".")[-1])
                self.cache["ifTable"][idx] = {"index": idx}

            # Descriptions
            for oid, val in await self._async_walk(OID_ifDescr):
                idx = int(oid.split(".")[-1])
                self.cache["ifTable"].setdefault(idx, {})["descr"] = str(val)

            # Names
            for oid, val in await self._async_walk(OID_ifName):
                idx = int(oid.split(".")[-1])
                self.cache["ifTable"].setdefault(idx, {})["name"] = str(val)

            # Aliases
            for oid, val in await self._async_walk(OID_ifAlias):
                idx = int(oid.split(".")[-1])
                self.cache["ifTable"].setdefault(idx, {})["alias"] = str(val)

            # Display name preference from original repo
            for idx, rec in list(self.cache["ifTable"].items()):
                nm = (rec.get("name") or "").strip()
                ds = (rec.get("descr") or "").strip()
                rec["display_name"] = nm or ds or f"ifIndex {idx}"

        # Dynamic state only
        for oid, val in await self._async_walk(OID_ifAdminStatus):
            idx = int(oid.split(".")[-1])
            self.cache["ifTable"].setdefault(idx, {})["admin"] = int(val)

        for oid, val in await self._async_walk(OID_ifOperStatus):
            idx = int(oid.split(".")[-1])
            self.cache["ifTable"].setdefault(idx, {})["oper"] = int(val)

    async def _async_walk_ipv4(self) -> None:
        """
        ORIGINAL REPO LOGIC, adapted to asyncio:
        1) Legacy IP-MIB ipAdEnt* for IPv4 list + masks when present.
        2) IP-MIB ipAddressIfIndex: parse IPv4 from instance suffix (1.4.a.b.c.d).
        3) OSPF-MIB ospfIfIpAddress: also yields a.b.c.d with suffix carrying ifIndex.
        4) Derive mask bits by parsing IP-FORWARD-MIB route instances (.7.1.9) and
           choosing the most specific network that contains each discovered IP.
        """
        ip_index: Dict[str, int] = {}
        ip_mask: Dict[str, str] = {}  # primarily from (1) and (4)

        def _normalize_ipv4(val: Any) -> str:
            """Convert SNMP IPv4 values to dotted-quad strings.

            Some vendors (e.g., Cisco CBS series) return ipAdEntAddr/ipAdEntNetMask
            as raw octets instead of a printable IpAddress. This helper keeps existing
            behavior for vendors that already return dotted strings."""
            s = str(val)
            parts = s.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return s

            # Try to interpret as 4 raw octets
            b: Optional[bytes] = None
            try:
                b = bytes(val)  # pysnmp types often support __bytes__
            except Exception:
                try:
                    b = val.asOctets()  # type: ignore[attr-defined]
                except Exception:
                    b = None

            if b and len(b) == 4:
                return ".".join(str(x) for x in b)

            return s

        # ---- (1) Legacy table: ipAdEnt* ----
        legacy_addrs = await self._async_walk(OID_ipAdEntAddr)
        if legacy_addrs:
            for _oid, val in legacy_addrs:
                ip_index[_normalize_ipv4(val)] = None  # type: ignore[assignment]

            for oid, val in await self._async_walk(OID_ipAdEntIfIndex):
                parts = oid.split(".")[-4:]
                ip = ".".join(parts)
                try:
                    ip_index[ip] = int(val)
                except Exception:
                    continue

            for oid, val in await self._async_walk(OID_ipAdEntNetMask):
                parts = oid.split(".")[-4:]
                ip = ".".join(parts)
                ip_mask[ip] = _normalize_ipv4(val)

        # ---- (2) IP-MIB ipAddressIfIndex: parse instance suffix (1.4.a.b.c.d)
        try:
            for oid, val in await self._async_walk(OID_ipAddressIfIndex):
                suffix = oid[len(OID_ipAddressIfIndex) + 1 :]
                parts = [int(x) for x in suffix.split(".") if x]
                for i in range(len(parts) - 6 + 1):
                    if parts[i] == 1 and parts[i + 1] == 4:
                        a, b, c, d = parts[i + 2 : i + 6]
                        ip = f"{a}.{b}.{c}.{d}"
                        try:
                            idx = int(val)
                            ip_index.setdefault(ip, idx)
                        except Exception:
                            pass
                        break
        except Exception:
            pass  # IP-MIB may be absent

        # ---- (3) OSPF-MIB ospfIfIpAddress: suffix a.b.c.d.<ifIndex>.<area...>
        try:
            for oid, val in await self._async_walk(OID_ospfIfIpAddress):
                try:
                    suffix = oid[len(OID_ospfIfIpAddress) + 1 :]
                    parts = [int(x) for x in suffix.split(".")]
                    if len(parts) >= 5:
                        a, b, c, d = parts[0], parts[1], parts[2], parts[3]
                        if_index = parts[4]
                        ip = f"{a}.{b}.{c}.{d}"
                        ip_index.setdefault(ip, int(if_index))
                except Exception:
                    continue
        except Exception:
            pass  # OSPF-MIB may be absent

        # ---- (4) Derive mask bits from IP-FORWARD-MIB route instances (.7.1.9)
        route_prefixes: List[Tuple[int, int]] = []

        def _bits_to_mask(bits: int) -> str:
            if bits <= 0:
                return "0.0.0.0"
            if bits >= 32:
                return "255.255.255.255"
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            return ".".join(str((mask >> s) & 0xFF) for s in (24, 16, 8, 0))

        def _ip_to_int(ip: str) -> int:
            a, b, c, d = (int(x) for x in ip.split("."))
            return (a << 24) | (b << 16) | (c << 8) | d

        try:
            for oid, _val in await self._async_walk(OID_routeCol):
                try:
                    suffix = oid[len(OID_routeCol) + 1 :]
                    parts = [int(x) for x in suffix.split(".") if x]

                    for i in range(len(parts) - 7):
                        if parts[i] == 1 and parts[i + 1] == 4:
                            a, b, c, d = parts[i + 2 : i + 6]
                            bits = parts[i + 6] if i + 6 < len(parts) else None
                            if bits is None or bits < 0 or bits > 32:
                                continue
                            net_int = _ip_to_int(f"{a}.{b}.{c}.{d}")
                            route_prefixes.append((net_int, bits))
                            break
                except Exception:
                    continue
        except Exception:
            pass  # table may be absent on some vendors

        if route_prefixes and ip_index:
            route_prefixes.sort(key=lambda t: t[1], reverse=True)
            for ip in list(ip_index.keys()):
                ip_int = _ip_to_int(ip)
                for net_int, bits in route_prefixes:
                    mask_int = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
                    if bits == 0 or (ip_int & mask_int) == (net_int & mask_int):
                        ip_mask[ip] = _bits_to_mask(bits)
                        break

        # Commit maps to cache
        if ip_index:
            self.cache["ipIndex"] = ip_index
        if ip_mask:
            self.cache["ipMask"] = ip_mask

    def _attach_ipv4_to_interfaces(self) -> None:
        if_table: Dict[int, Dict[str, Any]] = self.cache.get("ifTable", {})
        ip_idx: Dict[str, Optional[int]] = self.cache.get("ipIndex", {})
        ip_mask: Dict[str, str] = self.cache.get("ipMask", {})

        # Clear prior fields to avoid stale data
        for rec in if_table.values():
            for k in (
                "ipv4", "ip", "netmask", "cidr",
                "ip_address", "ipv4_address", "ipv4_netmask", "ipv4_cidr",
                "ip_cidr_str",
            ):
                rec.pop(k, None)

        def _mask_to_prefix(mask: str | None) -> Optional[int]:
            if not mask:
                return None
            try:
                parts = [int(p) for p in mask.split(".")]
                if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
                    return None
                bits = "".join(f"{p:08b}" for p in parts)
                if "01" in bits:
                    return None
                return bits.count("1")
            except Exception:
                return None

        # Attach; if mask present convert to prefix bits for /cidr string
        for ip, idx in ip_idx.items():
            if not idx:
                continue
            rec = if_table.get(idx)
            if not rec:
                continue
            mask = ip_mask.get(ip)
            prefix = _mask_to_prefix(mask)
            rec.setdefault("ipv4", []).append({"ip": ip, "netmask": mask, "cidr": prefix})

        # Convenience single-address fields for UI (unchanged behavior)
        for rec in if_table.values():
            addrs = rec.get("ipv4") or []
            if len(addrs) == 1:
                ip = addrs[0]["ip"]
                mask = addrs[0]["netmask"]
                prefix = addrs[0]["cidr"]
                rec["ip"] = ip
                rec["netmask"] = mask
                rec["cidr"] = prefix
                rec["ip_address"] = ip
                rec["ipv4_address"] = ip
                rec["ipv4_netmask"] = mask
                rec["ipv4_cidr"] = prefix
                if prefix is not None:
                    rec["ip_cidr_str"] = f"{ip}/{prefix}"

    async def async_refresh_all(self) -> None:
        await self._ensure_engine()
        await self._ensure_target()
        await self._async_walk_interfaces(dynamic_only=False)
        await self._async_walk_ipv4()
        self._attach_ipv4_to_interfaces()

    async def async_refresh_dynamic(self) -> None:
        await self._ensure_engine()
        await self._ensure_target()
        await self._async_walk_interfaces(dynamic_only=True)
        await self._async_walk_ipv4()
        self._attach_ipv4_to_interfaces()

    # ---------- coordinator hook ----------
    async def async_poll(self) -> Dict[str, Any]:
        await self.async_refresh_dynamic()
        return self.cache

    # ---------- mutations ----------
    async def set_alias(self, if_index: int, alias: str) -> bool:
        await self._ensure_engine()
        await self._ensure_target()
        ok = await _do_set_alias(self.engine, self.community_data, self.target, self.context, if_index, alias)
        if ok:
            self.cache.setdefault("ifTable", {}).setdefault(if_index, {})["alias"] = alias
        else:
            _LOGGER.warning("Failed to set alias via SNMP on ifIndex %s", if_index)
        return ok

    async def set_admin_status(self, if_index: int, value: int) -> bool:
        await self._ensure_engine()
        await self._ensure_target()
        return await _do_set_admin_status(self.engine, self.community_data, self.target, self.context, if_index, value)


# ---------- helpers for config_flow ----------

async def test_connection(hass: HomeAssistant, host: str, community: str, port: int) -> bool:
    client = SwitchSnmpClient(hass, host, community, port)
    sysname = await client._async_get_one(OID_sysName)
    return sysname is not None


async def get_sysname(hass: HomeAssistant, host: str, community: str, port: int) -> Optional[str]:
    client = SwitchSnmpClient(hass, host, community, port)
    return await client._async_get_one(OID_sysName)
