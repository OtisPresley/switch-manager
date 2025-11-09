# custom_components/switch_manager/snmp.py
from __future__ import annotations

from typing import Iterable, Tuple, Any


class SnmpDependencyError(RuntimeError):
    """Raised when pysnmp cannot be imported/used."""


def _imports():
    """Lazy-import pysnmp HLAPI so HA can install requirements first.

    Works with pysnmp-lextudio 5.x (maintained) and classic pysnmp 4.x,
    but we *only* rely on the HLAPI symbols that both provide.
    """
    try:
        from pysnmp.hlapi import (  # type: ignore
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            getCmd,
            nextCmd,
            setCmd,
        )
    except Exception as e:  # pragma: no cover
        # Keep the message terse; config_flow surfaces a generic UI error.
        raise SnmpDependencyError(f"pysnmp.hlapi import failed: {e}")

    return (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        nextCmd,
        setCmd,
    )


def ensure_snmp_available() -> None:
    """Used by config_flow to verify HLAPI availability once."""
    _imports()  # raises SnmpDependencyError on failure


def snmp_get(host: str, community: str, port: int, oid: str) -> Any:
    """Perform a single GET and return the value for the OID."""
    (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        _nextCmd,
        _setCmd,
    ) = _imports()

    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # SNMP v2c
        UdpTransportTarget((host, int(port))),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )

    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication:
        raise RuntimeError(error_indication)
    if error_status:
        where = var_binds[int(error_index) - 1][0] if error_index else "?"
        raise RuntimeError(f"{error_status.prettyPrint()} at {where}")
    # Return the value part of the first var-bind
    return var_binds[0][1]


def snmp_walk(
    host: str, community: str, port: int, base_oid: str
) -> Iterable[Tuple[str, Any]]:
    """Walk (nextCmd) starting at base_oid and yield (oid, value) pairs."""
    (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        _getCmd,
        nextCmd,
        _setCmd,
    ) = _imports()

    for (err_ind, err_stat, err_idx, var_binds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, int(port))),
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    ):
        if err_ind:
            raise RuntimeError(err_ind)
        if err_stat:
            where = var_binds[int(err_idx) - 1][0] if err_idx else "?"
            raise RuntimeError(f"{err_stat.prettyPrint()} at {where}")

        for name, val in var_binds:
            yield (str(name), val)


def snmp_set_octet_string(
    host: str, community: str, port: int, oid: str, value
) -> None:
    """Set an OCTET STRING (or compatible) value."""
    (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        _getCmd,
        _nextCmd,
        setCmd,
    ) = _imports()

    err_ind, err_stat, err_idx, var_binds = next(
        setCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, int(port))),
            ContextData(),
            ObjectType(ObjectIdentity(oid), value),
        )
    )
    if err_ind:
        raise RuntimeError(err_ind)
    if err_stat:
        where = var_binds[int(err_idx) - 1][0] if err_idx else "?"
        raise RuntimeError(f"{err_stat.prettyPrint()} at {where}")
