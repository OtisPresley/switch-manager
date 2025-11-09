"""SNMP helper for Switch Manager."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import timedelta
from importlib import import_module
from typing import Any, Dict, Iterable, List, Tuple

from .const import SNMP_OIDS

_LOGGER = logging.getLogger(__name__)


class SnmpError(Exception):
    """Raised when an SNMP operation fails."""


class SnmpDependencyError(SnmpError):
    """Raised when pysnmp helpers cannot be loaded."""


class _SnmpBackend:
    """Shared interface for SNMP helper backends."""

    integer_cls: Any
    octet_string_cls: Any

    def create_context(self, host: str, port: int, community: str) -> Any:
        raise NotImplementedError

    def get(self, ctx: Any, oid: str) -> Any:
        raise NotImplementedError

    def set(self, ctx: Any, oid: str, value: Any) -> None:
        raise NotImplementedError

    def walk(self, ctx: Any, oid: str) -> Iterable[Tuple[Any, Any]]:
        raise NotImplementedError

    def make_integer(self, value: int) -> Any:
        return self.integer_cls(value)

    def make_octet_string(self, value: str) -> Any:
        return self.octet_string_cls(value)

    def close(self, ctx: Any) -> None:  # pragma: no cover - optional for backends
        return None


class _HlapiBackend(_SnmpBackend):
    """Backend using the pysnmp high level API."""

    _MODULE_CANDIDATES = (
        "pysnmp.hlapi",
        "pysnmp.hlapi.v3arch",
        "pysnmp.hlapi.v1arch",
    )

    def __init__(self) -> None:
        modules = []
        for name in self._MODULE_CANDIDATES:
            try:
                modules.append(import_module(name))
            except ImportError:
                continue

        if not modules:  # pragma: no cover - depends on runtime env
            raise SnmpDependencyError("pysnmp.hlapi is not available")

        def resolve_helper(symbol: str, *aliases: str, required: bool = True) -> Any:
            names = (symbol, *aliases)
            for module in modules:
                for attr in names:
                    value = getattr(module, attr, None)
                    if value is not None:
                        return value
            if required:
                raise SnmpDependencyError(
                    "pysnmp.hlapi missing helper: " + "/".join(names)
                )
            return None

        self._SnmpEngine = resolve_helper("SnmpEngine")
        self._CommunityData = resolve_helper("CommunityData")
        self._UdpTransportTarget = resolve_helper("UdpTransportTarget")
        self._ContextData = resolve_helper("ContextData", required=False)
        self._ObjectType = resolve_helper("ObjectType")
        self._ObjectIdentity = resolve_helper("ObjectIdentity")
        self._getCmd = resolve_helper("getCmd", "get")
        self._nextCmd = resolve_helper("nextCmd", "next")
        self._setCmd = resolve_helper("setCmd", "set")

        try:
            from pysnmp.proto.rfc1902 import Integer, OctetString
        except ImportError as err:  # pragma: no cover - depends on runtime env
            raise SnmpDependencyError("pysnmp.proto.rfc1902 missing value helpers") from err

        self.integer_cls = Integer
        self.octet_string_cls = OctetString

    def create_context(self, host: str, port: int, community: str) -> Tuple[Any, ...]:
        engine = self._SnmpEngine()
        auth = self._CommunityData(community, mpModel=1)
        target = self._UdpTransportTarget((host, port), timeout=2.0, retries=3)
        context = self._ContextData() if self._ContextData is not None else None
        return engine, auth, target, context

    def _build_args(self, ctx: Tuple[Any, ...]) -> List[Any]:
        engine, auth, target, context = ctx
        args: List[Any] = [engine, auth, target]
        if context is not None:
            args.append(context)
        return args

    def get(self, ctx: Tuple[Any, ...], oid: str) -> Any:
        args = self._build_args(ctx)
        object_type = self._ObjectType(self._ObjectIdentity(oid))
        iterator = self._getCmd(
            *args,
            object_type,
            lookupNames=False,
            lookupValues=False,
        )
        try:
            err_indication, err_status, err_index, var_binds = next(iterator)
        except StopIteration as err:  # pragma: no cover - defensive
            raise SnmpError("SNMP GET returned no data") from err
        _raise_on_error(err_indication, err_status, err_index)
        return var_binds[0][1]

    def set(self, ctx: Tuple[Any, ...], oid: str, value: Any) -> None:
        args = self._build_args(ctx)
        object_type = self._ObjectType(self._ObjectIdentity(oid), value)
        iterator = self._setCmd(
            *args,
            object_type,
            lookupNames=False,
            lookupValues=False,
        )
        try:
            err_indication, err_status, err_index, _ = next(iterator)
        except StopIteration as err:  # pragma: no cover - defensive
            raise SnmpError("SNMP SET returned no data") from err
        _raise_on_error(err_indication, err_status, err_index)

    def walk(self, ctx: Tuple[Any, ...], oid: str) -> Iterable[Tuple[Any, Any]]:
        args = self._build_args(ctx)
        object_type = self._ObjectType(self._ObjectIdentity(oid))
        iterator = self._nextCmd(
            *args,
            object_type,
            lexicographicMode=False,
            lookupNames=False,
            lookupValues=False,
        )
        for err_indication, err_status, err_index, var_binds in iterator:
            _raise_on_error(err_indication, err_status, err_index)
            for item in var_binds:
                yield item

    def close(self, ctx: Tuple[Any, ...]) -> None:
        engine = ctx[0]
        dispatcher = getattr(engine, "transportDispatcher", None)
        if dispatcher is not None:  # pragma: no branch - attribute may be missing
            dispatcher.closeDispatcher()


class _CmdGenBackend(_SnmpBackend):
    """Fallback backend using CommandGenerator helpers."""

    def __init__(self) -> None:
        try:
            module = import_module("pysnmp.entity.rfc3413.oneliner.cmdgen")
        except ImportError as err:  # pragma: no cover - depends on runtime env
            raise SnmpDependencyError("pysnmp CommandGenerator helpers unavailable") from err

        missing = [
            symbol
            for symbol in ("CommandGenerator", "CommunityData", "UdpTransportTarget")
            if getattr(module, symbol, None) is None
        ]
        if missing:
            raise SnmpDependencyError(
                "pysnmp command generator missing helpers: " + ", ".join(missing)
            )

        proto = import_module("pysnmp.proto.rfc1902")
        self.integer_cls = getattr(proto, "Integer")
        self.octet_string_cls = getattr(proto, "OctetString")

        self._CommandGenerator = module.CommandGenerator
        self._CommunityData = module.CommunityData
        self._UdpTransportTarget = module.UdpTransportTarget

    def create_context(self, host: str, port: int, community: str) -> Tuple[Any, Any]:
        auth = self._CommunityData(community, mpModel=1)
        target = self._UdpTransportTarget((host, port), timeout=2.0, retries=3)
        return auth, target

    def _run(self, method: str, ctx: Tuple[Any, Any], *args: Any) -> Tuple[Any, ...]:
        auth, target = ctx
        generator = self._CommandGenerator()
        func = getattr(generator, method)
        return func(auth, target, *args, lookupNames=False, lookupValues=False)

    def get(self, ctx: Tuple[Any, Any], oid: str) -> Any:
        err_indication, err_status, err_index, var_binds = self._run("getCmd", ctx, oid)
        _raise_on_error(err_indication, err_status, err_index)
        return var_binds[0][1]

    def set(self, ctx: Tuple[Any, Any], oid: str, value: Any) -> None:
        err_indication, err_status, err_index, _ = self._run(
            "setCmd", ctx, (oid, value)
        )
        _raise_on_error(err_indication, err_status, err_index)

    def walk(self, ctx: Tuple[Any, Any], oid: str) -> Iterable[Tuple[Any, Any]]:
        auth, target = ctx
        generator = self._CommandGenerator()
        iterator = generator.nextCmd(
            auth,
            target,
            oid,
            lexicographicMode=False,
            lookupNames=False,
            lookupValues=False,
        )
        for err_indication, err_status, err_index, var_binds in iterator:
            _raise_on_error(err_indication, err_status, err_index)
            for item in var_binds:
                yield item


_BACKEND: _SnmpBackend | None = None
_BACKEND_ERROR: Exception | None = None


def reset_backend_cache() -> None:
    """Clear any cached backend or import error state."""

    global _BACKEND, _BACKEND_ERROR
    _BACKEND = None
    _BACKEND_ERROR = None


def _get_backend() -> _SnmpBackend:
    """Return a cached backend, discovering helpers if necessary."""

    global _BACKEND, _BACKEND_ERROR

    if _BACKEND is not None:
        return _BACKEND
    if _BACKEND_ERROR is not None:
        raise SnmpDependencyError(str(_BACKEND_ERROR)) from _BACKEND_ERROR

    first_error: Exception | None = None

    try:
        backend = _HlapiBackend()
    except SnmpDependencyError as err:
        first_error = err
    else:
        _LOGGER.debug("Using pysnmp.hlapi backend")
        _BACKEND = backend
        return backend

    try:
        backend = _CmdGenBackend()
    except SnmpDependencyError as err:
        if first_error is not None:
            combined = SnmpDependencyError(
                f"pysnmp helpers unavailable: {first_error}; {err}"
            )
            _BACKEND_ERROR = combined
            raise combined
        _BACKEND_ERROR = err
        raise err

    _LOGGER.debug("Using pysnmp CommandGenerator backend")
    _BACKEND = backend
    return backend


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
        backend: _SnmpBackend,
        context: Any,
    ) -> None:
        self._backend = backend
        self._ctx = context
        self._lock = asyncio.Lock()

    @classmethod
    async def async_create(
        cls, host: str, community: str, port: int = 161
    ) -> "SwitchSnmpClient":
        """Build a client after loading pysnmp helpers off the event loop."""

        backend = await asyncio.to_thread(_get_backend)
        context = await asyncio.to_thread(backend.create_context, host, port, community)
        return cls(backend, context)

    async def async_close(self) -> None:
        """Close the client (placeholder for parity with previous API)."""

        close = getattr(self._backend, "close", None)
        if close is not None:
            await asyncio.to_thread(close, self._ctx)

    async def _async_get_value(self, oid: str) -> Any:
        """Fetch a raw SNMP value while holding the shared lock."""

        async with self._lock:
            return await asyncio.to_thread(self._backend.get, self._ctx, oid)

    async def async_get(self, oid: str) -> str:
        """Perform an SNMP GET and return the value as a string."""

        value = await self._async_get_value(oid)
        return _format_snmp_value(value)

    async def async_set_admin_status(self, index: int, up: bool) -> None:
        """Set the administrative status of an interface."""

        base_oid = SNMP_OIDS.get("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7")
        oid = f"{base_oid}.{index}"
        value = self._backend.make_integer(1 if up else 2)
        await self._async_set(oid, value)

    async def async_set_alias(self, index: int, alias: str) -> None:
        """Set the alias (description) of an interface."""

        base_oid = SNMP_OIDS.get("ifAlias", "1.3.6.1.2.1.31.1.1.1.18")
        oid = f"{base_oid}.{index}"
        value = self._backend.make_octet_string(alias)
        await self._async_set(oid, value)

    async def _async_set(self, oid: str, value: Any) -> None:
        async with self._lock:
            await asyncio.to_thread(self._backend.set, self._ctx, oid, value)

    async def async_get_table(self, oid: str) -> Dict[int, str]:
        """Fetch an SNMP table and return a dictionary keyed by index."""

        async with self._lock:
            return await asyncio.to_thread(self._sync_get_table, oid)

    def _sync_get_table(self, oid: str) -> Dict[int, str]:
        result: Dict[int, str] = {}
        start_oid = oid

        for fetched_oid, value in self._backend.walk(self._ctx, oid):
            fetched_oid_str = str(fetched_oid)
            if not fetched_oid_str.startswith(start_oid):
                break
            try:
                index = int(fetched_oid_str.split(".")[-1])
            except ValueError:
                _LOGGER.debug("Skipping non-integer OID %s", fetched_oid_str)
                continue
            result[index] = _format_snmp_value(value)

        return result

    async def async_get_port_data(self) -> List[Dict[str, str]]:
        """Fetch information for each interface."""

        descr = await self.async_get_table(
            SNMP_OIDS.get("ifDescr", "1.3.6.1.2.1.2.2.1.2")
        )
        alias = await self.async_get_table(
            SNMP_OIDS.get("ifAlias", "1.3.6.1.2.1.31.1.1.1.18")
        )
        speed = await self.async_get_table(
            SNMP_OIDS.get("ifSpeed", "1.3.6.1.2.1.2.2.1.5")
        )
        admin = await self.async_get_table(
            SNMP_OIDS.get("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7")
        )
        oper = await self.async_get_table(
            SNMP_OIDS.get("ifOperStatus", "1.3.6.1.2.1.2.2.1.8")
        )

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

        if not manufacturer and description.split():
            first_word = description.split()[0].strip(",")
            if len(first_word) > 1:
                manufacturer = first_word

    return {
        "manufacturer": manufacturer,
        "model": model,
        "firmware": firmware,
    }
