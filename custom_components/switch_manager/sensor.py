from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any, Dict, Optional

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SENSORS = (
    ("firmware", "Firmware Rev"),
    ("hostname", "Hostname"),
    ("manuf_model", "Manufacturer & Model"),
    ("uptime", "Uptime"),
)


def _format_uptime(seconds: Optional[str]) -> str:
    """Return human friendly uptime from seconds string (SNMP hundredths handled upstream)."""
    if not seconds:
        return "Unknown"
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return "Unknown"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    if days:
        return f"{days} days, {hours:02d}:{mins:02d}:{secs:02d}"
    return f"{hours:02d}:{mins:02d}:{secs:02d}"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    node = hass.data[DOMAIN].get(entry.entry_id)
    if not node:
        _LOGGER.error("Sensor setup: missing node for entry_id=%s", entry.entry_id)
        return
    coordinator = node["coordinator"]

    entities = []
    for key, name in SENSORS:
        entities.append(SwitchInfoSensor(coordinator, entry, key, name))
    async_add_entities(entities)


class SwitchInfoSensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, key: str, name: str) -> None:
        super().__init__(coordinator)
        self._key = key
        self._attr_name = name
        self._attr_unique_id = f"{entry.entry_id}-{key}"

    @property
    def native_value(self) -> Any:
        system: Dict[str, Any] = (self.coordinator.data or {}).get("system", {}) or {}
        if self._key == "uptime":
            return _format_uptime(system.get("uptime"))
        return system.get(self._key) or "Unknown"
