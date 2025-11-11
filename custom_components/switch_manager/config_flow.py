
from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_NAME
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, CONF_COMMUNITY, DEFAULT_PORT
from .snmp import test_connection, get_sysname

STEP_USER_DATA_SCHEMA = vol.Schema({
    vol.Required(CONF_HOST): str,
    vol.Required(CONF_COMMUNITY): str,
    vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
    vol.Optional(CONF_NAME): str,
})

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None) -> FlowResult:
        errors = {}
        if user_input is not None:
            host = user_input[CONF_HOST]
            port = user_input.get(CONF_PORT, DEFAULT_PORT)
            community = user_input[CONF_COMMUNITY]

            ok = await test_connection(self.hass, host, community, port)
            if not ok:
                errors["base"] = "cannot_connect"
            else:
                # Use sysName for device naming if available
                sysname = await get_sysname(self.hass, host, community, port)
                title = user_input.get(CONF_NAME) or sysname or host

                await self.async_set_unique_id(f"{host}:{port}:{community}")
                self._abort_if_unique_id_configured()

                return self.async_create_entry(title=title, data={
                    "host": host, "port": port, "community": community, "name": title
                })
        return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors)
