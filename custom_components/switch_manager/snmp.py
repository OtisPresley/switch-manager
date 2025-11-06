"""Async SNMP helper for Switch Manager."""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

try:
    from pysnmp.hlapi.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd as async_getCmd,
        nextCmd as async_nextCmd,
        setCmd as async_setCmd,
    )
    _ASYNC_SNMP = True
except ImportError as exc:
    if getattr(exc, "name", None) != "bulkCmd":
        raise

    from pysnmp.hlapi import (  # type: ignore[no-redef]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd as sync_getCmd,
        nextCmd as sync_nextCmd,
        setCmd as sync_setCmd,
    )

    _ASYNC_SNMP = False

from pysnmp.smi.rfc1902 import Integer, OctetString

_LOGGER = logging.getLogger(__name__)

if not _ASYNC_SNMP:
    _LOGGER.warning(
        "pysnmp.asyncio bulkCmd unavailable; falling back to threaded SNMP calls"
    )


class SnmpError(Exception):
    """Raised when an SNMP operation fails."""


class SwitchSnmpClient:
    """Simple SNMP v2 client for polling switch information."""

    def __init__(self, host: str, community: str, port: int = 161) -> None:
        self._host = host
        self._community = community
        self._port = port
        self._engine = SnmpEngine()
        self._target = UdpTransportTarget((self._host, self._port), timeout=2.0, retries=3)
        self._auth = CommunityData(self._community, mpModel=1)
        self._context = ContextData()
        self._lock = asyncio.Lock()

    async def async_close(self) -> None:
        """Close the SNMP engine."""
        async with self._lock:
            if self._engine.transportDispatcher is not None:
                self._engine.transportDispatcher.closeDispatcher()

    async def async_get(self, oid: str) -> str:
        """Perform an SNMP GET and return the value as a string."""
        async with self._lock:
            if _ASYNC_SNMP:
                err_indication, err_status, err_index, var_binds = await async_getCmd(
                    self._engine,
                    self._auth,
                    self._target,
                    self._context,
                    ObjectType(ObjectIdentity(oid)),
                )
            else:
                loop = asyncio.get_running_loop()

                def _worker():
                    return next(
                        sync_getCmd(
                            self._engine,
                            self._auth,
                            self._target,
                            self._context,
                            ObjectType(ObjectIdentity(oid)),
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
        value = Integer(1 if up else 2)
        await self._async_set(oid, value)

    async def async_set_alias(self, index: int, alias: str) -> None:
        """Set the alias (description) of an interface."""
        oid = f"1.3.6.1.2.1.31.1.1.1.18.{index}"
        value = OctetString(alias)
        await self._async_set(oid, value)

    async def async_get_table(self, oid: str) -> Dict[int, str]:
        """Fetch an SNMP table and return a dictionary keyed by index."""
        result: Dict[int, str] = {}
        start_oid = oid

        async with self._lock:
            if _ASYNC_SNMP:
                next_oid: ObjectIdentity | None = ObjectIdentity(start_oid)

                while next_oid is not None:
                    err_indication, err_status, err_index, var_binds = await async_nextCmd(
                        self._engine,
                        self._auth,
                        self._target,
                        self._context,
                        ObjectType(next_oid),
                        lexicographicMode=False,
                    )

                    _raise_on_error(err_indication, err_status, err_index)

                    if not var_binds:
                        break

                    next_oid = None

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
                        next_oid = ObjectIdentity(fetched_oid)
            else:
                loop = asyncio.get_running_loop()

                def _worker() -> Dict[int, str]:
                    sync_result: Dict[int, str] = {}
                    for err_indication, err_status, err_index, var_binds in sync_nextCmd(
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
            if _ASYNC_SNMP:
                err_indication, err_status, err_index, _ = await async_setCmd(
                    self._engine,
                    self._auth,
                    self._target,
                    self._context,
                    ObjectType(ObjectIdentity(oid), value),
                )
            else:
                loop = asyncio.get_running_loop()

                def _worker():
                    return next(
                        sync_setCmd(
                            self._engine,
                            self._auth,
                            self._target,
                            self._context,
                            ObjectType(ObjectIdentity(oid), value),
                        )
                    )

                err_indication, err_status, err_index, _ = await loop.run_in_executor(
                    None, _worker
                )

        _raise_on_error(err_indication, err_status, err_index)


def _raise_on_error(err_indication, err_status, err_index) -> None:
    if err_indication:
        raise SnmpError(err_indication)
    if err_status:
        raise SnmpError(
            f"SNMP error {err_status.prettyPrint()} at index {err_index}"
        )


