"""Home Assistant integration to manage network switches via SNMP."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.requirements import async_process_requirements

from .const import (
    CONF_COMMUNITY,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    PLATFORMS,
    REQUIREMENTS,
    SERVICE_FIELD_DESCRIPTION,
    SERVICE_FIELD_ENTITY_ID,
    SERVICE_SET_PORT_DESCRIPTION,
)
from .snmp import SnmpError, SwitchSnmpClient

_LOGGER = logging.getLogger(__name__)

SwitchManagerConfigEntry = ConfigEntry


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the integration via YAML (not supported)."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: SwitchManagerConfigEntry) -> bool:
    """Set up Switch Manager from a config entry."""
    domain_data = hass.data.setdefault(DOMAIN, {"entries": {}, "service_registered": False})

    try:
        await async_process_requirements(hass, DOMAIN, REQUIREMENTS)
    except Exception as err:  # pragma: no cover - depends on runtime
        raise ConfigEntryNotReady(f"Unable to install pysnmp requirements: {err}") from err

    client = await SwitchSnmpClient.async_create(
        entry.data[CONF_HOST],
        entry.data[CONF_COMMUNITY],
        entry.data.get(CONF_PORT, DEFAULT_PORT),
    )

    coordinator = SwitchCoordinator(hass, client, entry)
    await coordinator.async_config_entry_first_refresh()

    domain_data["entries"][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    if not domain_data["service_registered"]:
        domain_data["service_registered"] = True

        async def _set_description(call: ServiceCall) -> None:
            entity_id = call.data[SERVICE_FIELD_ENTITY_ID]
            description = call.data[SERVICE_FIELD_DESCRIPTION]

            from homeassistant.helpers import entity_registry as er

            ent_reg = er.async_get(hass)
            entity_entry = ent_reg.async_get(entity_id)
            if not entity_entry:
                raise ValueError(f"Entity {entity_id} not found")
            entry_id = entity_entry.config_entry_id
            if not entry_id or entry_id not in hass.data[DOMAIN]["entries"]:
                raise ValueError("Entity is not managed by Switch Manager")

            coordinator: SwitchCoordinator = hass.data[DOMAIN]["entries"][entry_id][
                "coordinator"
            ]
            await coordinator.async_set_description(entity_id, description)

        hass.services.async_register(
            DOMAIN,
            SERVICE_SET_PORT_DESCRIPTION,
            _set_description,
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: SwitchManagerConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    domain_data = hass.data[DOMAIN]
    data = domain_data["entries"].pop(entry.entry_id)
    await data["client"].async_close()

    if not domain_data["entries"]:
        domain_data["service_registered"] = False
        hass.services.async_remove(DOMAIN, SERVICE_SET_PORT_DESCRIPTION)

    return True


class SwitchCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator fetching SNMP data for a switch."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: SwitchSnmpClient,
        entry: SwitchManagerConfigEntry,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"Switch Manager {entry.title}",
            update_interval=timedelta(
                seconds=entry.options.get("scan_interval", DEFAULT_SCAN_INTERVAL)
            ),
        )
        self.client = client
        self.entry = entry

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            ports = await self.client.async_get_port_data()
            system = await self.client.async_get_system_info()
        except SnmpError as err:
            raise UpdateFailed(f"Failed to update switch data: {err}") from err

        return {
            "ports": ports,
            "device_info": system,
        }

    async def async_set_description(self, entity_id: str, description: str) -> None:
        """Update the alias of a port from a service call."""
        from homeassistant.helpers.entity_registry import async_get

        ent_reg = async_get(self.hass)
        entry = ent_reg.async_get(entity_id)
        if not entry:
            raise ValueError(f"Entity {entity_id} not found")

        index = entry.unique_id.split(":")[-1]
        await self.client.async_set_alias(int(index), description)
        await self.async_request_refresh()

    async def async_set_admin_state(self, index: int, enabled: bool) -> None:
        await self.client.async_set_admin_status(index, enabled)
        await self.async_request_refresh()
