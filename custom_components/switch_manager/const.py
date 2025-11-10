from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "switch_manager"

# Make sure both switch + sensor platforms are loaded
PLATFORMS: list[Platform] = [Platform.SWITCH, Platform.SENSOR]
