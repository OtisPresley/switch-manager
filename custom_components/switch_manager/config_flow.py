"""Config flow for Switch Manager integration."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_PORT
from homeassistant.data_entry_flow import FlowResult

from .const import CONF_COMMUNITY, DEFAULT_PORT, DOMAIN
from .snmp import SnmpError, SwitchSnmpClient


class SwitchManagerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Switch Manager."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            port = user_input.get(CONF_PORT, DEFAULT_PORT)
            await self.async_set_unique_id(f"{user_input[CONF_HOST]}:{port}")
            self._abort_if_unique_id_configured()

            client = SwitchSnmpClient(
                host=user_input[CONF_HOST],
                community=user_input[CONF_COMMUNITY],
                port=port,
            )
            try:
                ports = await client.async_get_port_data()
            except SnmpError:
                errors["base"] = "cannot_connect"
            else:
                if not ports:
                    errors["base"] = "no_ports"
                else:
                    title = user_input.get(CONF_NAME) or user_input[CONF_HOST]
                    data = {
                        CONF_HOST: user_input[CONF_HOST],
                        CONF_COMMUNITY: user_input[CONF_COMMUNITY],
                        CONF_PORT: port,
                    }
                    return self.async_create_entry(title=title, data=data)
            finally:
                await client.async_close()

        data_schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_COMMUNITY): str,
                vol.Optional(CONF_PORT, default=DEFAULT_PORT): vol.All(
                    vol.Coerce(int), vol.Range(min=1, max=65535)
                ),
                vol.Optional(CONF_NAME): str,
            }
        )

        return self.async_show_form(step_id="user", data_schema=data_schema, errors=errors)
