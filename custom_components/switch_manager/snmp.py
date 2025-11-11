
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from homeassistant.core import HomeAssistant
from pysnmp.hlapi.asyncio import (
    CommunityData,
    SnmpEngine,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
    setCmd,
)
from pysnmp.proto.rfc1902 import OctetString, Integer

from .const import (
    OID_sysDescr, OID_sysName, OID_sysUpTime,
    OID_ifIndex, OID_ifDescr, OID_ifAdminStatus, OID_ifOperStatus, OID_ifName, OID_ifAlias,
    OID_ipAdEntAddr, OID_ipAdEntIfIndex, OID_ipAdEntNetMask,
)

_LOGGER = logging.getLogger(__name__)

class SwitchSnmpClient:
    def __init__(self, hass: HomeAssistant, host: str, community: str, port: int) -> None:
        self.hass = hass
        self.host = host
        self.community = community
        self.port = port
        self.engine = SnmpEngine()
        self.target = UdpTransportTarget((host, port), timeout=1.5, retries=1)
        self.community_data = CommunityData(community, mpModel=1)  # v2c
        self.context = ContextData()

        self.cache: Dict[str, Any] = {
            "sysDescr": None,
            "sysName": None,
            "sysUpTime": None,
            "ifTable": {},     # index -> dict
            "ipIndex": {},     # ip -> ifIndex
            "ipMask": {},      # ip -> netmask
        }

    async def async_initialize(self) -> None:
        # fetch sys* values once
        self.cache["sysDescr"] = await self._get_one(OID_sysDescr)
        self.cache["sysName"] = await self._get_one(OID_sysName)
        self.cache["sysUpTime"] = await self._get_one(OID_sysUpTime)
        await self._walk_interfaces()
        await self._walk_ipv4()

    async def async_poll(self) -> Dict[str, Any]:
        # refresh dynamic parts
        await self._walk_interfaces(dynamic_only=True)
        await self._walk_ipv4()
        return self.cache

    async def _get_one(self, oid: str) -> Optional[str]:
        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            self.engine, self.community_data, self.target, self.context, ObjectType(ObjectIdentity(oid))
        )
        if errorIndication or errorStatus:
            _LOGGER.debug("SNMP get error for %s: %s %s", oid, errorIndication, errorStatus)
            return None
        return str(varBinds[0][1])

    async def _walk(self, oid: str):
        async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            self.engine, self.community_data, self.target, self.context, ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if errorIndication or errorStatus:
                _LOGGER.debug("SNMP walk error at %s: %s %s", oid, errorIndication, errorStatus)
                break
            for varBind in varBinds:
                yield str(varBind[0]), varBind[1]

    async def _walk_interfaces(self, dynamic_only: bool=False):
        if not dynamic_only:
            self.cache["ifTable"] = {}
            # indices & base properties
            async for oid, val in self._walk(OID_ifIndex):
                idx = int(str(val))
                self.cache["ifTable"][idx] = {"index": idx}

            async for oid, val in self._walk(OID_ifDescr):
                idx = int(oid.split(".")[-1])
                self.cache["ifTable"].setdefault(idx, {})["descr"] = str(val)

            async for oid, val in self._walk(OID_ifName):
                idx = int(oid.split(".")[-1])
                self.cache["ifTable"].setdefault(idx, {})["name"] = str(val)

            async for oid, val in self._walk(OID_ifAlias):
                idx = int(oid.split(".")[-1])
                self.cache["ifTable"].setdefault(idx, {})["alias"] = str(val)

        # dynamic
        async for oid, val in self._walk(OID_ifAdminStatus):
            idx = int(oid.split(".")[-1])
            self.cache["ifTable"].setdefault(idx, {})["admin"] = int(val)

        async for oid, val in self._walk(OID_ifOperStatus):
            idx = int(oid.split(".")[-1])
            self.cache["ifTable"].setdefault(idx, {})["oper"] = int(val)

    async def _walk_ipv4(self):
        ip_to_index = {}
        ip_to_mask = {}
        async for oid, val in self._walk(OID_ipAdEntAddr):
            ip_to_index[str(val)] = None
        async for oid, val in self._walk(OID_ipAdEntIfIndex):
            # last 4 numbers form the IPv4
            parts = oid.split(".")[-4:]
            ip = ".".join(parts)
            ip_to_index[ip] = int(val)
        async for oid, val in self._walk(OID_ipAdEntNetMask):
            parts = oid.split(".")[-4:]
            ip = ".".join(parts)
            ip_to_mask[ip] = str(val)
        self.cache["ipIndex"] = ip_to_index
        self.cache["ipMask"] = ip_to_mask

    async def set_alias(self, if_index: int, alias: str) -> bool:
        errorIndication, errorStatus, errorIndex, varBinds = await setCmd(
            self.engine, self.community_data, self.target, self.context,
            ObjectType(ObjectIdentity(f"{OID_ifAlias}.{if_index}"), OctetString(alias)),
        )
        ok = not errorIndication and not errorStatus
        if ok:
            self.cache["ifTable"].setdefault(if_index, {})["alias"] = alias
        else:
            _LOGGER.warning("Failed to set alias: %s %s", errorIndication, errorStatus)
        return ok

# helpers for config_flow
async def test_connection(hass: HomeAssistant, host: str, community: str, port: int) -> bool:
    client = SwitchSnmpClient(hass, host, community, port)
    return (await client._get_one(OID_sysName)) is not None

async def get_sysname(hass: HomeAssistant, host: str, community: str, port: int) -> Optional[str]:
    client = SwitchSnmpClient(hass, host, community, port)
    return await client._get_one(OID_sysName)
