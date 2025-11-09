"""Switch platform for Switch Manager integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_ADMIN_STATUS,
    ATTR_DESCRIPTION,
    ATTR_OPER_STATUS,
    ATTR_PORT,
    ATTR_SPEED,
    DOMAIN,
)
from . import SwitchCoordinator


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    data = hass.data[DOMAIN]["entries"][entry.entry_id]
    coordinator: SwitchCoordinator = data["coordinator"]

    entities: list[SwitchManagerPort] = []
    for port in coordinator.data.get("ports", []):
        entities.append(SwitchManagerPort(coordinator, entry, port["index"]))

    async_add_entities(entities)


class SwitchManagerPort(CoordinatorEntity[SwitchCoordinator], SwitchEntity):
    """Representation of a switch port as a Home Assistant Switch entity."""

    _attr_should_poll = False
    _attr_has_entity_name = True
    _attr_icon = "mdi:ethernet"

    def __init__(self, coordinator: SwitchCoordinator, entry: ConfigEntry, index: int) -> None:
        super().__init__(coordinator)
        self.entry = entry
        self.index = index
        self._attr_unique_id = f"{entry.entry_id}:{index}"
        self._attr_name = f"Port {index}"
        self._identifier = (DOMAIN, entry.entry_id)
        self._configuration_url = f"snmp://{entry.data[CONF_HOST]}"

    @property
    def is_on(self) -> bool:
        port = self._port_data
        return port and port[ATTR_ADMIN_STATUS] == "1"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        port = self._port_data
        if not port:
            return {}
        return {
            ATTR_PORT: port["index"],
            ATTR_DESCRIPTION: port.get("description"),
            ATTR_SPEED: _format_speed(port.get("speed")),
            ATTR_ADMIN_STATUS: _decode_status(port.get("admin_status")),
            ATTR_OPER_STATUS: _decode_status(port.get("oper_status")),
        }

    @property
    def available(self) -> bool:
        return super().available and self._port_data is not None

    @property
    def device_info(self) -> DeviceInfo:
        info = self.coordinator.data.get("device_info", {}) if self.coordinator.data else {}
        manufacturer = info.get("manufacturer")
        model = info.get("model")
        firmware = info.get("firmware")
        name = info.get("name") or self.entry.title

        return DeviceInfo(
            identifiers={self._identifier},
            manufacturer=manufacturer,
            model=model,
            sw_version=firmware,
            name=name,
            configuration_url=self._configuration_url,
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_admin_state(self.index, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_admin_state(self.index, False)

    @property
    def _port_data(self) -> dict[str, Any] | None:
        for port in self.coordinator.data.get("ports", []):
            if port["index"] == self.index:
                return port
        return None


def _decode_status(value: str | None) -> str | None:
    mapping = {
        "1": "up",
        "2": "down",
        "3": "testing",
        "4": "unknown",
        "5": "dormant",
        "6": "notPresent",
        "7": "lowerLayerDown",
    }
    return mapping.get(value or "")


def _format_speed(value: str | None) -> str | None:
    if not value:
        return None
    try:
        bps = int(value)
    except (TypeError, ValueError):
        return value
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.1f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    return f"{bps} bps"
