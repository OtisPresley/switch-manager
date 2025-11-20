import asyncio

# Prefer new API (PySNMP >= 7, v3arch asyncio)
try:
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        OctetString,
        Integer,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
        set_cmd,
        next_cmd,
        bulk_cmd,
        walk_cmd,
        bulk_walk_cmd,
        is_end_of_mib,
        UsmUserData,  # noqa: F401 (reserved for future v3 support)
    )
    HAS_V7 = True
except Exception:
    HAS_V7 = False

if not HAS_V7:
    # Legacy fallback (older HA bases). Kept for portability.
    from pysnmp.hlapi.asyncio import (  # type: ignore
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        OctetString,
        Integer,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd as _get_cmd,
        set_cmd as _set_cmd,
        next_cmd as _next_cmd,
        bulk_cmd as _bulk_cmd,
        walk_cmd as _walk_cmd,
        bulk_walk_cmd as _bulk_walk_cmd,
        is_end_of_mib,
    )

    async def get_cmd(*a, **k):
        return await _get_cmd(*a, **k)

    async def set_cmd(*a, **k):
        return await _set_cmd(*a, **k)

    async def next_cmd(*a, **k):
        return await _next_cmd(*a, **k)

    async def bulk_cmd(*a, **k):
        return await _bulk_cmd(*a, **k)

    async def walk_cmd(*a, **k):
        return await _walk_cmd(*a, **k)

    async def bulk_walk_cmd(*a, **k):
        return await _bulk_walk_cmd(*a, **k)
