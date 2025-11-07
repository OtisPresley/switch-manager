"""Async SNMP helper for Switch Manager."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib import import_module
import logging
from types import ModuleType
from typing import Any, Dict, Iterable, List, Tuple

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class _SnmpHelpers:
    """Holds callable references for either async or sync pysnmp backends."""

    is_async: bool
    community_cls: Any
    context_cls: Any
    object_identity_cls: Any
    object_type_cls: Any
    snmp_engine_cls: Any
    transport_target_cls: Any
    get_cmd: Any
    next_cmd: Any
    set_cmd: Any
    integer_cls: Any
    octet_string_cls: Any


_HELPERS: _SnmpHelpers | None = None


class SnmpError(Exception):
    """Raised when an SNMP operation fails."""


class SnmpDependencyError(SnmpError):
    """Raised when pysnmp helpers cannot be loaded."""


ASYNC_IMPORT_ERROR: Exception | None = None
SYNC_IMPORT_ERROR: Exception | None = None
INTEGER_IMPORT_ERROR: Exception | None = None

def _import_helper_module(
    module_candidates: Iterable[str],
    required_attributes: Tuple[str, ...],
) -> Tuple[ModuleType | None, Exception | None]:
    """Try importing helper modules, returning the first that satisfies requirements."""

    last_error: Exception | None = None
    for module_name in module_candidates:
        try:
            module = import_module(module_name)
        except Exception as err:  # pragma: no cover - runtime environment dependent
            last_error = err
            continue

        missing = [attr for attr in required_attributes if not hasattr(module, attr)]
        if missing:
            last_error = AttributeError(
                f"{module_name} missing attributes: {', '.join(missing)}"
            )
            continue

        return module, None

    return None, last_error


def _extract_attributes(module: ModuleType | None, names: Tuple[str, ...]) -> Dict[str, Any]:
    """Return attribute mapping from module or a dict of None when unavailable."""

    if module is None:
        return {name: None for name in names}

    return {name: getattr(module, name) for name in names}


ASYNC_MODULE, ASYNC_IMPORT_ERROR = _import_helper_module(
    (
        "pysnmp.hlapi.asyncio",
        "pysnmp.hlapi.v1arch.asyncio",
    ),
    (
        "CommunityData",
        "ContextData",
        "ObjectIdentity",
        "ObjectType",
        "SnmpEngine",
        "UdpTransportTarget",
        "getCmd",
        "nextCmd",
        "setCmd",
    ),
)

ASYNC_ATTRS = _extract_attributes(
    ASYNC_MODULE,
    (
        "CommunityData",
        "ContextData",
        "ObjectIdentity",
        "ObjectType",
        "SnmpEngine",
        "UdpTransportTarget",
        "getCmd",
        "nextCmd",
        "setCmd",
    ),
)

AsyncCommunityData = ASYNC_ATTRS["CommunityData"]
AsyncContextData = ASYNC_ATTRS["ContextData"]
AsyncObjectIdentity = ASYNC_ATTRS["ObjectIdentity"]
AsyncObjectType = ASYNC_ATTRS["ObjectType"]
AsyncSnmpEngine = ASYNC_ATTRS["SnmpEngine"]
AsyncUdpTransportTarget = ASYNC_ATTRS["UdpTransportTarget"]
async_getCmd = ASYNC_ATTRS["getCmd"]
async_nextCmd = ASYNC_ATTRS["nextCmd"]
async_setCmd = ASYNC_ATTRS["setCmd"]
ASYNC_HELPERS_AVAILABLE = ASYNC_MODULE is not None


SYNC_MODULE, SYNC_IMPORT_ERROR = _import_helper_module(
    (
        "pysnmp.hlapi",
        "pysnmp.hlapi.v1arch",
    ),
    (
        "CommunityData",
        "ContextData",
        "ObjectIdentity",
        "ObjectType",
        "SnmpEngine",
        "UdpTransportTarget",
        "getCmd",
        "nextCmd",
        "setCmd",
    ),
)

SYNC_ATTRS = _extract_attributes(
    SYNC_MODULE,
    (
        "CommunityData",
        "ContextData",
        "ObjectIdentity",
        "ObjectType",
        "SnmpEngine",
        "UdpTransportTarget",
        "getCmd",
        "nextCmd",
        "setCmd",
    ),
)

SyncCommunityData = SYNC_ATTRS["CommunityData"]
SyncContextData = SYNC_ATTRS["ContextData"]
SyncObjectIdentity = SYNC_ATTRS["ObjectIdentity"]
SyncObjectType = SYNC_ATTRS["ObjectType"]
SyncSnmpEngine = SYNC_ATTRS["SnmpEngine"]
SyncUdpTransportTarget = SYNC_ATTRS["UdpTransportTarget"]
sync_getCmd = SYNC_ATTRS["getCmd"]
sync_nextCmd = SYNC_ATTRS["nextCmd"]
sync_setCmd = SYNC_ATTRS["setCmd"]
SYNC_HELPERS_AVAILABLE = SYNC_MODULE is not None


INTEGER_CLS: Any | None = None
OCTET_STRING_CLS: Any | None = None

try:  # pragma: no cover - availability shim
    from pysnmp.proto.rfc1902 import Integer as ProtoInteger, OctetString as ProtoOctetString

    INTEGER_CLS = ProtoInteger
    OCTET_STRING_CLS = ProtoOctetString
except Exception as err:  # pragma: no cover - availability shim
    INTEGER_IMPORT_ERROR = err
    try:
        from pysnmp.smi.rfc1902 import (  # type: ignore[no-redef]
            Integer as SmiInteger,
            OctetString as SmiOctetString,
        )

        INTEGER_CLS = SmiInteger
        OCTET_STRING_CLS = SmiOctetString
        INTEGER_IMPORT_ERROR = None
    except Exception as inner_err:  # pragma: no cover - availability shim
        INTEGER_IMPORT_ERROR = inner_err
        INTEGER_CLS = None
        OCTET_STRING_CLS = None


def _load_helpers() -> _SnmpHelpers:
    """Load pysnmp helpers, preferring asyncio and falling back to sync."""

    global _HELPERS
    if _HELPERS is not None:
        return _HELPERS

    if INTEGER_CLS is None or OCTET_STRING_CLS is None:
        raise SnmpDependencyError(
            "pysnmp type helpers are unavailable"
        ) from INTEGER_IMPORT_ERROR

    if ASYNC_HELPERS_AVAILABLE:
        helpers = _SnmpHelpers(
            is_async=True,
            community_cls=AsyncCommunityData,
            context_cls=AsyncContextData,
            object_identity_cls=AsyncObjectIdentity,
            object_type_cls=AsyncObjectType,
            snmp_engine_cls=AsyncSnmpEngine,
            transport_target_cls=AsyncUdpTransportTarget,
            get_cmd=async_getCmd,
            next_cmd=async_nextCmd,
            set_cmd=async_setCmd,
            integer_cls=INTEGER_CLS,
            octet_string_cls=OCTET_STRING_CLS,
        )
        _HELPERS = helpers
        return helpers

    if SYNC_HELPERS_AVAILABLE:
        if ASYNC_IMPORT_ERROR is not None:
            _LOGGER.debug("pysnmp asyncio helpers unavailable: %s", ASYNC_IMPORT_ERROR)
        helpers = _SnmpHelpers(
            is_async=False,
            community_cls=SyncCommunityData,
            context_cls=SyncContextData,
            object_identity_cls=SyncObjectIdentity,
            object_type_cls=SyncObjectType,
            snmp_engine_cls=SyncSnmpEngine,
            transport_target_cls=SyncUdpTransportTarget,
            get_cmd=sync_getCmd,
            next_cmd=sync_nextCmd,
            set_cmd=sync_setCmd,
            integer_cls=INTEGER_CLS,
            octet_string_cls=OCTET_STRING_CLS,
        )
        _HELPERS = helpers
        _LOGGER.warning(
            "pysnmp asyncio helpers unavailable; falling back to threaded SNMP calls"
        )
        return helpers

    raise SnmpDependencyError(
        "pysnmp getCmd helpers are unavailable in both asyncio and sync variants"
    ) from (ASYNC_IMPORT_ERROR or SYNC_IMPORT_ERROR)


class SwitchSnmpClient:
    """Simple SNMP v2 client for polling switch information."""

    def __init__(self, host: str, community: str, port: int = 161) -> None:
        helpers = _load_helpers()

        self._host = host
        self._community = community
        self._port = port
        self._helpers = helpers
        self._engine = helpers.snmp_engine_cls()
        self._target = helpers.transport_target_cls(
            (self._host, self._port), timeout=2.0, retries=3
        )
        self._auth = helpers.community_cls(self._community, mpModel=1)
        self._context = helpers.context_cls()
        self._lock = asyncio.Lock()

    async def async_close(self) -> None:
        """Close the SNMP engine."""
        async with self._lock:
            if self._engine.transportDispatcher is not None:
                self._engine.transportDispatcher.closeDispatcher()

    async def async_get(self, oid: str) -> str:
        """Perform an SNMP GET and return the value as a string."""
        async with self._lock:
            if self._helpers.is_async:
                err_indication, err_status, err_index, var_binds = await self._helpers.get_cmd(
                    self._engine,
                    self._auth,
                    self._target,
                    self._context,
                    self._helpers.object_type_cls(
                        self._helpers.object_identity_cls(oid)
                    ),
                )
            else:
                loop = asyncio.get_running_loop()

                def _worker():
                    return next(
                        self._helpers.get_cmd(
                            self._engine,
                            self._auth,
                            self._target,
                            self._context,
                            self._helpers.object_type_cls(
                                self._helpers.object_identity_cls(oid)
                            ),
                        )
                    )

                err_indication, err_status, err_index, var_binds = await loop.run_in_executor(
                    None, _worker
                )

        _raise_on_error(err_indication, err_status, err_index)
        return str(var_binds[0][1])

    async def async_set_admin_status(self, index: int, up: bool) -> None:
        """Set the administrative status of an interface."""
        oid = f"1.3.6.1.2.1.2.2.1.7.{index}"
        value = self._helpers.integer_cls(1 if up else 2)
        await self._async_set(oid, value)

    async def async_set_alias(self, index: int, alias: str) -> None:
        """Set the alias (description) of an interface."""
        oid = f"1.3.6.1.2.1.31.1.1.1.18.{index}"
        value = self._helpers.octet_string_cls(alias)
        await self._async_set(oid, value)

    async def async_get_table(self, oid: str) -> Dict[int, str]:
        """Fetch an SNMP table and return a dictionary keyed by index."""
        result: Dict[int, str] = {}
        start_oid = oid

        async with self._lock:
            if self._helpers.is_async:
                next_oid = self._helpers.object_identity_cls(start_oid)

                while next_oid is not None:
                    (
                        err_indication,
                        err_status,
                        err_index,
                        var_binds,
                    ) = await self._helpers.next_cmd(
                        self._engine,
                        self._auth,
                        self._target,
                        self._context,
                        self._helpers.object_type_cls(next_oid),
                        lexicographicMode=False,
                    )

                    _raise_on_error(err_indication, err_status, err_index)

                    if not var_binds:
                        break

                    for fetched_oid, value in var_binds:
                        fetched_oid_str = str(fetched_oid)
                        if not fetched_oid_str.startswith(start_oid):
                            next_oid = None
                            break
                        try:
                            index = int(fetched_oid_str.split(".")[-1])
                        except ValueError:
                            _LOGGER.debug("Skipping non-integer OID %s", fetched_oid_str)
                            continue
                        result[index] = str(value)
                        next_oid = self._helpers.object_identity_cls(fetched_oid)
            else:
                loop = asyncio.get_running_loop()

                def _worker() -> Dict[int, str]:
                    sync_result: Dict[int, str] = {}
                    for (
                        err_indication,
                        err_status,
                        err_index,
                        var_binds,
                    ) in self._helpers.next_cmd(
                        self._engine,
                        self._auth,
                        self._target,
                        self._context,
                        self._helpers.object_type_cls(
                            self._helpers.object_identity_cls(start_oid)
                        ),
                        lexicographicMode=False,
                    ):
                        _raise_on_error(err_indication, err_status, err_index)
                        if not var_binds:
                            break
                        for fetched_oid, value in var_binds:
                            fetched_oid_str = str(fetched_oid)
                            if not fetched_oid_str.startswith(start_oid):
                                return sync_result
                            try:
                                index = int(fetched_oid_str.split(".")[-1])
                            except ValueError:
                                _LOGGER.debug(
                                    "Skipping non-integer OID %s", fetched_oid_str
                                )
                                continue
                            sync_result[index] = str(value)
                    return sync_result

                result = await loop.run_in_executor(None, _worker)

        return result

    async def async_get_port_data(self) -> List[Dict[str, str]]:
        """Fetch information for each interface."""
        descr = await self.async_get_table("1.3.6.1.2.1.2.2.1.2")
        alias = await self.async_get_table("1.3.6.1.2.1.31.1.1.1.18")
        speed = await self.async_get_table("1.3.6.1.2.1.2.2.1.5")
        admin = await self.async_get_table("1.3.6.1.2.1.2.2.1.7")
        oper = await self.async_get_table("1.3.6.1.2.1.2.2.1.8")

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

    async def _async_set(self, oid: str, value) -> None:
        async with self._lock:
            if self._helpers.is_async:
                (
                    err_indication,
                    err_status,
                    err_index,
                    _,
                ) = await self._helpers.set_cmd(
                    self._engine,
                    self._auth,
                    self._target,
                    self._context,
                    self._helpers.object_type_cls(
                        self._helpers.object_identity_cls(oid), value
                    ),
                )
            else:
                loop = asyncio.get_running_loop()

                def _worker() -> Tuple[Any, Any, Any, Any]:
                    return next(
                        self._helpers.set_cmd(
                            self._engine,
                            self._auth,
                            self._target,
                            self._context,
                            self._helpers.object_type_cls(
                                self._helpers.object_identity_cls(oid), value
                            ),
                        )
                    )

                (
                    err_indication,
                    err_status,
                    err_index,
                    _,
                ) = await loop.run_in_executor(None, _worker)

        _raise_on_error(err_indication, err_status, err_index)


def _raise_on_error(err_indication, err_status, err_index) -> None:
    if err_indication:
        raise SnmpError(err_indication)
    if err_status:
        raise SnmpError(
            f"SNMP error {err_status.prettyPrint()} at index {err_index}"
        )


