"""Async SNMP helper for Switch Manager."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib import import_module
import logging
from typing import Any, Dict, List, Sequence, Tuple

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


def _import_first_available(module_names: Sequence[str], attribute: str | None = None) -> Any:
    """Try importing modules until one succeeds."""

    last_error: Exception | None = None
    for module_name in module_names:
        try:
            module = import_module(module_name)
        except Exception as err:  # pragma: no cover - import shim
            last_error = err
            continue
        if attribute is None:
            return module
        try:
            return getattr(module, attribute)
        except AttributeError as err:  # pragma: no cover - import shim
            last_error = err
            continue
    raise SnmpDependencyError(
        f"Unable to import {attribute or 'module'} from {module_names!r}"
    ) from last_error


def _load_helpers() -> _SnmpHelpers:
    """Load pysnmp helpers, preferring asyncio and falling back to sync."""

    global _HELPERS
    if _HELPERS is not None:
        return _HELPERS

    try:
        module = import_module("pysnmp.hlapi.asyncio")
        helpers = _SnmpHelpers(
            is_async=True,
            community_cls=module.CommunityData,
            context_cls=module.ContextData,
            object_identity_cls=module.ObjectIdentity,
            object_type_cls=module.ObjectType,
            snmp_engine_cls=module.SnmpEngine,
            transport_target_cls=module.UdpTransportTarget,
            get_cmd=getattr(module, "getCmd"),
            next_cmd=getattr(module, "nextCmd"),
            set_cmd=getattr(module, "setCmd"),
            integer_cls=_import_first_available(
                ("pysnmp.proto.rfc1902", "pysnmp.smi.rfc1902"), "Integer"
            ),
            octet_string_cls=_import_first_available(
                ("pysnmp.proto.rfc1902", "pysnmp.smi.rfc1902"), "OctetString"
            ),
        )
        _HELPERS = helpers
        return helpers
    except Exception as err:  # pragma: no cover - import shim
        _LOGGER.debug("pysnmp asyncio helpers unavailable: %s", err)

    try:
        module = import_module("pysnmp.hlapi")
        helpers = _SnmpHelpers(
            is_async=False,
            community_cls=module.CommunityData,
            context_cls=module.ContextData,
            object_identity_cls=module.ObjectIdentity,
            object_type_cls=module.ObjectType,
            snmp_engine_cls=module.SnmpEngine,
            transport_target_cls=module.UdpTransportTarget,
            get_cmd=getattr(module, "getCmd"),
            next_cmd=getattr(module, "nextCmd"),
            set_cmd=getattr(module, "setCmd"),
            integer_cls=_import_first_available(
                ("pysnmp.proto.rfc1902", "pysnmp.smi.rfc1902"), "Integer"
            ),
            octet_string_cls=_import_first_available(
                ("pysnmp.proto.rfc1902", "pysnmp.smi.rfc1902"), "OctetString"
            ),
        )
        _HELPERS = helpers
        _LOGGER.warning(
            "pysnmp asyncio helpers unavailable; falling back to threaded SNMP calls"
        )
        return helpers
    except Exception as err:  # pragma: no cover - import shim
        raise SnmpDependencyError(
            "pysnmp getCmd helpers are unavailable in both asyncio and sync variants"
        ) from err


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


