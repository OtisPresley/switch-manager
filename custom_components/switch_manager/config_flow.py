"""Config flow for Switch Manager integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_PORT
from homeassistant.data_entry_flow import FlowResult
from homeassistant.requirements import async_process_requirements

from .const import CONF_COMMUNITY, DEFAULT_PORT, DOMAIN, REQUIREMENTS
from .snmp import SnmpDependencyError, SnmpError, SwitchSnmpClient

_LOGGER = logging.getLogger(__name__)


class SwitchManagerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Switch Manager."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow state."""

        self._requirements_ready = False

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            if not self._requirements_ready:
                try:
                    await async_process_requirements(self.hass, DOMAIN, REQUIREMENTS)
                except Exception as err:  # pragma: no cover - depends on runtime
                    _LOGGER.exception("Unable to install pysnmp requirements", exc_info=err)
                    errors["base"] = "missing_dependency"
                else:
                    self._requirements_ready = True

            if errors:
                return self.async_show_form(
                    step_id="user", data_schema=self._build_schema(user_input), errors=errors
                )

            port = user_input.get(CONF_PORT, DEFAULT_PORT)
            await self.async_set_unique_id(f"{user_input[CONF_HOST]}:{port}")
            self._abort_if_unique_id_configured()

            client: SwitchSnmpClient | None = None
            try:
                client = await SwitchSnmpClient.async_create(
                    user_input[CONF_HOST],
                    user_input[CONF_COMMUNITY],
                    port,
                )
                ports = await client.async_get_port_data()
            except SnmpDependencyError as err:
                _LOGGER.error("pysnmp dependency issue: %s", err)
                errors["base"] = "missing_dependency"
            except SnmpError as err:
                _LOGGER.error("Unable to communicate with %s: %s", user_input[CONF_HOST], err)
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
                if client is not None:
                    await client.async_close()

        return self.async_show_form(
            step_id="user", data_schema=self._build_schema(user_input), errors=errors
        )

    @staticmethod
    def _build_schema(user_input: dict[str, Any] | None) -> vol.Schema:
        defaults = user_input or {}
        return vol.Schema(
            {
                vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, vol.UNDEFINED)): str,
                vol.Required(
                    CONF_COMMUNITY, default=defaults.get(CONF_COMMUNITY, vol.UNDEFINED)
                ): str,
                vol.Optional(
                    CONF_PORT,
                    default=defaults.get(CONF_PORT, DEFAULT_PORT),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                vol.Optional(CONF_NAME, default=defaults.get(CONF_NAME, vol.UNDEFINED)): str,
            }
        )
