"""SNMP helper for Switch Manager."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import timedelta
from importlib import import_module
from typing import Any, Dict, List

from .const import SNMP_OIDS

_LOGGER = logging.getLogger(__name__)


class SnmpError(Exception):
    """Raised when an SNMP operation fails."""


class SnmpDependencyError(SnmpError):
    """Raised when pysnmp helpers cannot be loaded."""


HELPER_SYMBOLS = (
    "CommunityData",
    "ContextData",
    "ObjectIdentity",
    "ObjectType",
    "SnmpEngine",
    "UdpTransportTarget",
    "getCmd",
    "nextCmd",
    "setCmd",
)

HELPER_MODULES = (
    "pysnmp.hlapi",
    "pysnmp.hlapi.cmdgen",
    "pysnmp.hlapi.sync",
    "pysnmp.hlapi.sync.cmdgen",
    "pysnmp.hlapi.api",
    "pysnmp.hlapi.api.cmdgen",
    "pysnmp.hlapi.api.sync",
    "pysnmp.hlapi.api.sync.cmdgen",
    "pysnmp.hlapi.v1arch",
    "pysnmp.hlapi.v1arch.cmdgen",
    "pysnmp.hlapi.v3arch",
    "pysnmp.hlapi.v3arch.cmdgen",
)


def _load_helper_symbols() -> Dict[str, Any]:
    """Locate pysnmp helper attributes across multiple module layouts."""

    helpers: Dict[str, Any] = {}
    errors: List[Exception] = []

    for module_name in HELPER_MODULES:
        try:
            module = import_module(module_name)
        except Exception as err:  # pragma: no cover - depends on runtime layout
            errors.append(err)
            continue

        for symbol in HELPER_SYMBOLS:
            if symbol in helpers:
                continue
            attr = getattr(module, symbol, None)
            if attr is not None:
                helpers[symbol] = attr

        if len(helpers) == len(HELPER_SYMBOLS):
            break

    missing = [symbol for symbol in HELPER_SYMBOLS if symbol not in helpers]
    if missing:
        if errors:
            last_error = errors[-1]
        else:  # pragma: no cover - defensive
            last_error = ImportError("pysnmp helpers unavailable")
        raise SnmpDependencyError(
            "pysnmp missing attributes: " + ", ".join(missing)
        ) from last_error

    return helpers


try:  # pragma: no cover - import depends on Home Assistant runtime
    _HELPERS = _load_helper_symbols()
    CommunityData = _HELPERS["CommunityData"]
    ContextData = _HELPERS["ContextData"]
    ObjectIdentity = _HELPERS["ObjectIdentity"]
    ObjectType = _HELPERS["ObjectType"]
    SnmpEngine = _HELPERS["SnmpEngine"]
    UdpTransportTarget = _HELPERS["UdpTransportTarget"]
    getCmd = _HELPERS["getCmd"]
    nextCmd = _HELPERS["nextCmd"]
    setCmd = _HELPERS["setCmd"]
    from pysnmp.proto.rfc1902 import Integer, OctetString
except Exception as import_err:  # pragma: no cover - handled at runtime
    IMPORT_ERROR: Exception | None = import_err
else:  # pragma: no cover - simple assignments
    IMPORT_ERROR = None


def _raise_on_error(err_indication, err_status, err_index) -> None:
    """Validate pysnmp response and raise a friendly error."""

    if err_indication:
        raise SnmpError(err_indication)
    if err_status:
        raise SnmpError(
            f"SNMP error {err_status.prettyPrint()} at index {err_index}"
        )


class SwitchSnmpClient:
    """Simple SNMP v2 client for polling switch information."""

    def __init__(self, host: str, community: str, port: int = 161) -> None:
        if IMPORT_ERROR is not None:
            raise SnmpDependencyError("pysnmp is not available") from IMPORT_ERROR

        self._host = host
        self._community = community
        self._port = port
        self._engine = SnmpEngine()
        self._target = UdpTransportTarget((self._host, self._port), timeout=2.0, retries=3)
        self._auth = CommunityData(self._community, mpModel=1)
        self._context = ContextData()
        self._lock = asyncio.Lock()

    async def async_close(self) -> None:
        """Close the SNMP engine dispatcher."""

        async with self._lock:
            dispatcher = getattr(self._engine, "transportDispatcher", None)
            if dispatcher is not None:
                dispatcher.closeDispatcher()

    async def _async_get_value(self, oid: str) -> Any:
        """Fetch a raw SNMP value while holding the shared lock."""

        async with self._lock:
            return await asyncio.to_thread(self._sync_get_value, oid)

    async def async_get(self, oid: str) -> str:
        """Perform an SNMP GET and return the value as a string."""

        value = await self._async_get_value(oid)
        return _format_snmp_value(value)

    def _sync_get_value(self, oid: str) -> Any:
        err_indication, err_status, err_index, var_binds = next(
            getCmd(
                self._engine,
                self._auth,
                self._target,
                self._context,
                ObjectType(ObjectIdentity(oid)),
            )
        )
        _raise_on_error(err_indication, err_status, err_index)
        return var_binds[0][1]

    async def async_set_admin_status(self, index: int, up: bool) -> None:
        """Set the administrative status of an interface."""

        base_oid = SNMP_OIDS.get("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7")
        oid = f"{base_oid}.{index}"
        value = Integer(1 if up else 2)
        await self._async_set(oid, value)

    async def async_set_alias(self, index: int, alias: str) -> None:
        """Set the alias (description) of an interface."""

        base_oid = SNMP_OIDS.get("ifAlias", "1.3.6.1.2.1.31.1.1.1.18")
        oid = f"{base_oid}.{index}"
        value = OctetString(alias)
        await self._async_set(oid, value)

    async def _async_set(self, oid: str, value: Any) -> None:
        async with self._lock:
            await asyncio.to_thread(self._sync_set, oid, value)

    def _sync_set(self, oid: str, value: Any) -> None:
        err_indication, err_status, err_index, _ = next(
            setCmd(
                self._engine,
                self._auth,
                self._target,
                self._context,
                ObjectType(ObjectIdentity(oid), value),
            )
        )
        _raise_on_error(err_indication, err_status, err_index)

    async def async_get_table(self, oid: str) -> Dict[int, str]:
        """Fetch an SNMP table and return a dictionary keyed by index."""

        async with self._lock:
            return await asyncio.to_thread(self._sync_get_table, oid)

    def _sync_get_table(self, oid: str) -> Dict[int, str]:
        result: Dict[int, str] = {}
        start_oid = oid

        for err_indication, err_status, err_index, var_binds in nextCmd(
            self._engine,
            self._auth,
            self._target,
            self._context,
            ObjectType(ObjectIdentity(start_oid)),
            lexicographicMode=False,
        ):
            _raise_on_error(err_indication, err_status, err_index)
            if not var_binds:
                break
            for fetched_oid, value in var_binds:
                fetched_oid_str = str(fetched_oid)
                if not fetched_oid_str.startswith(start_oid):
                    return result
                try:
                    index = int(fetched_oid_str.split(".")[-1])
                except ValueError:
                    _LOGGER.debug("Skipping non-integer OID %s", fetched_oid_str)
                    continue
                result[index] = _format_snmp_value(value)

        return result

    async def async_get_port_data(self) -> List[Dict[str, str]]:
        """Fetch information for each interface."""

        descr = await self.async_get_table(SNMP_OIDS.get("ifDescr", "1.3.6.1.2.1.2.2.1.2"))
        alias = await self.async_get_table(SNMP_OIDS.get("ifAlias", "1.3.6.1.2.1.31.1.1.1.18"))
        speed = await self.async_get_table(SNMP_OIDS.get("ifSpeed", "1.3.6.1.2.1.2.2.1.5"))
        admin = await self.async_get_table(SNMP_OIDS.get("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7"))
        oper = await self.async_get_table(SNMP_OIDS.get("ifOperStatus", "1.3.6.1.2.1.2.2.1.8"))

        ports: List[Dict[str, str]] = []
        for index, description in descr.items():
            ports.append(
                {
                    "index": index,
                    "description": alias.get(index) or description,
                    "raw_description": description,
                    "speed": speed.get(index, "0"),
                    "admin_status": admin.get(index, "2"),
                    "oper_status": oper.get(index, "2"),
                }
            )
        ports.sort(key=lambda item: item["index"])
        return ports

    async def async_get_system_info(self) -> Dict[str, Any]:
        """Collect metadata about the switch itself."""

        info: Dict[str, Any] = {}
        mapping = {
            "description": SNMP_OIDS.get("sysDescr"),
            "name": SNMP_OIDS.get("sysName"),
            "object_id": SNMP_OIDS.get("sysObjectID"),
            "uptime": SNMP_OIDS.get("sysUpTime"),
        }

        for key, oid in mapping.items():
            if not oid:
                continue
            try:
                value = await self._async_get_value(oid)
            except SnmpError as err:
                _LOGGER.debug("Unable to read %s (%s): %s", key, oid, err)
                continue

            info[key] = _format_snmp_value(value)

            if key == "uptime":
                ticks = _extract_ticks(value)
                if ticks is not None:
                    info["uptime_ticks"] = ticks
                    seconds = ticks / 100
                    info["uptime_seconds"] = seconds
                    info["uptime_human"] = str(timedelta(seconds=int(seconds)))

        description = info.get("description")
        object_id = info.get("object_id")
        parsed = _parse_system_details(description, object_id)
        info.update(parsed)

        return info


def _format_snmp_value(value: Any) -> str:
    """Convert a pysnmp value into a human-readable string."""

    if hasattr(value, "prettyPrint"):
        return value.prettyPrint()
    return str(value)


def _extract_ticks(value: Any) -> int | None:
    """Extract TimeTicks from a pysnmp value if available."""

    try:
        return int(value)
    except (TypeError, ValueError):
        if hasattr(value, "prettyPrint"):
            match = re.search(r"\((\d+)\)", value.prettyPrint())
            if match:
                return int(match.group(1))
    return None


_KNOWN_VENDOR_PREFIXES = {
    "1.3.6.1.4.1.9": "Cisco",
    "1.3.6.1.4.1.11": "HPE",
    "1.3.6.1.4.1.2636": "Juniper",
    "1.3.6.1.4.1.1991": "Foundry",
    "1.3.6.1.4.1.8072": "Net-SNMP",
    "1.3.6.1.4.1.11863": "Ubiquiti",
}


def _parse_system_details(description: str | None, object_id: str | None) -> Dict[str, Any]:
    """Derive manufacturer, model, and firmware details from SNMP data."""

    manufacturer: str | None = None
    model: str | None = None
    firmware: str | None = None

    if object_id:
        for prefix, vendor in _KNOWN_VENDOR_PREFIXES.items():
            if object_id.startswith(prefix):
                manufacturer = vendor
                break

    if description:
        # Look for firmware versions such as "Version 15.2(2)E9"
        version_match = re.search(r"Version\s+([\w\.\-()]+)", description, re.IGNORECASE)
        if version_match:
            firmware = version_match.group(1).rstrip(",")

        # Search for model-like tokens (alphanumeric with at least one digit)
        candidate_tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9\-_.]{2,}", description)
        for token in candidate_tokens:
            if any(ch.isdigit() for ch in token) and not token.lower().startswith("version"):
                model = token
                break

        if not manufacturer:
            first_word = description.split()[0].strip(",")
            if len(first_word) > 1:
                manufacturer = first_word

    return {
        "manufacturer": manufacturer,
        "model": model,
        "firmware": firmware,
    }
