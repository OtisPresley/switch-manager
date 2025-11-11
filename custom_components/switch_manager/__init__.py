
from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN, PLATFORMS, DEFAULT_POLL_INTERVAL
from .snmp import SwitchSnmpClient

_LOGGER = logging.getLogger(__name__)

type SwitchManagerConfigEntry = ConfigEntry

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    return True

async def async_setup_entry(hass: HomeAssistant, entry: SwitchManagerConfigEntry) -> bool:
    host = entry.data.get("host")
    port = entry.data.get("port")
    community = entry.data.get("community")

    client = SwitchSnmpClient(hass, host, community, port)
    await client.async_initialize()

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"{DOMAIN}-coordinator-{host}",
        update_interval=timedelta(seconds=DEFAULT_POLL_INTERVAL),
        update_method=client.async_poll,
    )
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
    }

    # Register services (idempotent)
    await async_register_services(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: SwitchManagerConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded

async def async_register_services(hass: HomeAssistant):
    from homeassistant.helpers import entity_registry as er

    async def handle_set_alias(call):
        entity_id = call.data.get("entity_id")
        description = call.data.get("description", "")

        ent_reg = er.async_get(hass)
        ent = ent_reg.async_get(entity_id)
        if not ent:
            return

        # Resolve platform entity object to access if_index
        for platform in hass.data.get("entity_platforms", []):
            pass  # not used, HA helper below

        # Look up entity object via hass.states
        state = hass.states.get(entity_id)
        if not state:
            return

        # Entities created by this integration expose a hidden attribute "_if_index" via registry_id
        entry_id = ent.config_entry_id
        data = hass.data[DOMAIN][entry_id]
        client = data["client"]

        # Parse if_index from unique_id pattern "<entry>-if-<index>"
        unique_id = ent.unique_id or ""
        if unique_id.endswith(")"):
            # not expected
            return
        try:
            if_index = int(unique_id.split("-if-")[-1])
        except Exception:
            return

        await client.set_alias(if_index, description)
        await data["coordinator"].async_request_refresh()

    if not hass.services.has_service(DOMAIN, "set_port_description"):
        hass.services.async_register(DOMAIN, "set_port_description", handle_set_alias)
