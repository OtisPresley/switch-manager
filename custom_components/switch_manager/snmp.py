"""SNMP helper for Switch Manager."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import timedelta
from importlib import import_module
from typing import Any, Dict, List, Sequence

from .const import SNMP_OIDS

_LOGGER = logging.getLogger(__name__)


class SnmpError(Exception):
    """Raised when an SNMP operation fails."""


class SnmpDependencyError(SnmpError):
    """Raised when pysnmp helpers cannot be loaded."""


HELPER_SYMBOLS: Sequence[str] = (
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

HELPER_MODULES: Sequence[str] = (
    # Core synchronous helpers shipped with pysnmp 4.x.
    "pysnmp.hlapi",
    "pysnmp.hlapi.v3arch",
    "pysnmp.hlapi.v1arch",
    "pysnmp.hlapi.cmdgen",
    # Asyncio shims introduced in newer pysnmp releases expose the same helpers
    # but under different module paths. We probe them here so installations that
    # only ship the asyncio layout still work without forcing a downgrade.
    "pysnmp.hlapi.asyncio",
    "pysnmp.hlapi.v3arch.asyncio",
    "pysnmp.hlapi.asyncio.cmdgen",
)

PROTO_MODULES: Sequence[str] = (
    "pysnmp.proto.rfc1902",
    "pysnmp.smi.rfc1902",
)


def _import_optional(module_name: str) -> Any | None:
    """Attempt to import the given module, returning None if unavailable."""

    try:
        return import_module(module_name)
    except ImportError as err:  # pragma: no cover - depends on runtime env
        _LOGGER.debug("Unable to import %s: %s", module_name, err)
        return None


def _import_first_available(module_names: Sequence[str], error: str) -> Any:
    """Return the first successfully imported module from the candidates."""

    for module_name in module_names:
        module = _import_optional(module_name)
        if module is not None:
            return module
    raise SnmpDependencyError(error)


def _fill_helpers_from_module(
    module: Any, missing: List[str], helpers: Dict[str, Any]
) -> None:
    """Populate helper attributes from the provided module."""

    for symbol in list(missing):
        attr = getattr(module, symbol, None)
        if attr is None:
            continue
        helpers[symbol] = attr
        missing.remove(symbol)

def _load_helper_symbols() -> Dict[str, Any]:
    """Import the pysnmp helper attributes from available modules."""

    helpers: Dict[str, Any] = {}
    missing: List[str] = list(HELPER_SYMBOLS)

    for module_name in HELPER_MODULES:
        module = _import_optional(module_name)
        if module is None:
            continue
        _fill_helpers_from_module(module, missing, helpers)
        if not missing:
            break

    if missing:
        raise SnmpDependencyError(
            "pysnmp missing attributes: " + ", ".join(sorted(missing))
        )

    proto = _import_first_available(PROTO_MODULES, "pysnmp proto helpers unavailable")
    helpers["Integer"] = getattr(proto, "Integer")
    helpers["OctetString"] = getattr(proto, "OctetString")

    return helpers


_HELPERS: Dict[str, Any] | None = None
IMPORT_ERROR: Exception | None = None


def _ensure_helpers() -> Dict[str, Any]:
    """Ensure pysnmp helpers are available after requirements install."""

    global _HELPERS, IMPORT_ERROR

    if _HELPERS is not None:
        return _HELPERS

    try:  # pragma: no cover - depends on runtime environment
        helpers = _load_helper_symbols()
    except SnmpDependencyError as err:  # pragma: no cover - handled by config flow
        IMPORT_ERROR = err
        raise
    except Exception as err:  # pragma: no cover - defensive fallback
        IMPORT_ERROR = err
        raise SnmpDependencyError("pysnmp is not available") from err

    IMPORT_ERROR = None
    _HELPERS = helpers
    return helpers


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

    def __init__(
        self,
        helpers: Dict[str, Any],
        host: str,
        community: str,
        port: int = 161,
    ) -> None:
        self._CommunityData = helpers["CommunityData"]
        self._ContextData = helpers["ContextData"]
        self._ObjectIdentity = helpers["ObjectIdentity"]
        self._ObjectType = helpers["ObjectType"]
        self._SnmpEngine = helpers["SnmpEngine"]
        self._UdpTransportTarget = helpers["UdpTransportTarget"]
        self._get_cmd = helpers["getCmd"]
        self._next_cmd = helpers["nextCmd"]
        self._set_cmd = helpers["setCmd"]
        self._Integer = helpers["Integer"]
        self._OctetString = helpers["OctetString"]

        self._host = host
        self._community = community
        self._port = port
        self._engine = self._SnmpEngine()
        self._target = self._UdpTransportTarget(
            (self._host, self._port), timeout=2.0, retries=3
        )
        self._auth = self._CommunityData(self._community, mpModel=1)
        self._context = self._ContextData()
        self._lock = asyncio.Lock()

    @classmethod
    async def async_create(
        cls, host: str, community: str, port: int = 161
    ) -> "SwitchSnmpClient":
        """Build a client after loading pysnmp helpers off the event loop."""

        helpers = await asyncio.to_thread(_ensure_helpers)
        return cls(helpers, host, community, port)

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
            self._get_cmd(
                self._engine,
                self._auth,
                self._target,
                self._context,
                self._ObjectType(self._ObjectIdentity(oid)),
            )
        )
        _raise_on_error(err_indication, err_status, err_index)
        return var_binds[0][1]

    async def async_set_admin_status(self, index: int, up: bool) -> None:
        """Set the administrative status of an interface."""

        base_oid = SNMP_OIDS.get("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7")
        oid = f"{base_oid}.{index}"
        value = self._Integer(1 if up else 2)
        await self._async_set(oid, value)

    async def async_set_alias(self, index: int, alias: str) -> None:
        """Set the alias (description) of an interface."""

        base_oid = SNMP_OIDS.get("ifAlias", "1.3.6.1.2.1.31.1.1.1.18")
        oid = f"{base_oid}.{index}"
        value = self._OctetString(alias)
        await self._async_set(oid, value)

    async def _async_set(self, oid: str, value: Any) -> None:
        async with self._lock:
            await asyncio.to_thread(self._sync_set, oid, value)

    def _sync_set(self, oid: str, value: Any) -> None:
        err_indication, err_status, err_index, _ = next(
            self._set_cmd(
                self._engine,
                self._auth,
                self._target,
                self._context,
                self._ObjectType(self._ObjectIdentity(oid), value),
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

        for err_indication, err_status, err_index, var_binds in self._next_cmd(
            self._engine,
            self._auth,
            self._target,
            self._context,
            self._ObjectType(self._ObjectIdentity(start_oid)),
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
