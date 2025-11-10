from __future__ import annotations

import logging
import re
import ipaddress
from typing import Any, Dict, List

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def _resolve_coordinator(hass, entry):
    """Return the DataUpdateCoordinator regardless of storage shape."""
    dom: Dict[str, Any] | None = hass.data.get(DOMAIN)

    # Layout seen in your logs:
    # hass.data[DOMAIN] -> {"entries": { entry_id: {...} }, "service_registered": True}
    if isinstance(dom, dict) and "entries" in dom:
        entries = dom.get("entries")
        if isinstance(entries, dict):
            node = entries.get(entry.entry_id)
            if node is not None:
                if isinstance(node, dict) and "coordinator" in node:
                    return node["coordinator"]
                if hasattr(node, "async_request_refresh") and hasattr(node, "data"):
                    return node

    # Fallbacks for older layouts
    if isinstance(dom, dict):
        node = dom.get(entry.entry_id)
        if node is not None:
            if isinstance(node, dict) and "coordinator" in node:
                return node["coordinator"]
            if hasattr(node, "async_request_refresh") and hasattr(node, "data"):
                return node
        if "coordinator" in dom and hasattr(dom["coordinator"], "async_request_refresh"):
            return dom["coordinator"]

    runtime = getattr(entry, "runtime_data", None)
    if runtime is not None:
        if hasattr(runtime, "async_request_refresh") and hasattr(runtime, "data"):
            return runtime
        if hasattr(runtime, "coordinator"):
            return getattr(runtime, "coordinator")

    _LOGGER.error(
        "Could not resolve coordinator for entry_id=%s; hass.data keys: %s; runtime_data=%s",
        entry.entry_id,
        list((dom or {}).keys()) if isinstance(dom, dict) else type(dom).__name__,
        type(runtime).__name__ if runtime is not None else None,
    )
    raise KeyError(entry.entry_id)


def _short_intf_name(long_name: str, alias: str) -> str | None:
    """
    Convert long ifDescr to short names:

      'Vlan 11' / 'VLAN11'                -> 'Vl11'
      'Unit: 1 Slot: 0 Port: 46 Gigabit' -> 'Gi1/0/46'
      'Unit: 1 Slot: 0 Port: 1 20G'      -> 'Tw1/0/1'   (20G stacking)
      'Unit: 1 Slot: 1 Port: 2 10G'      -> 'Te1/1/2'
    """
    text = long_name or ""
    alt = alias or ""

    # VLANs – try name first, then alias
    for candidate in (text, alt):
        mv = re.search(r"\bV(?:lan)?\s*([0-9]+)\b", candidate, re.IGNORECASE)
        if mv:
            return f"Vl{int(mv.group(1))}"

    # Physical form "Unit: X Slot: Y Port: Z <type>"
    m = re.search(r"Unit:\s*(\d+)\s+Slot:\s*(\d+)\s+Port:\s*(\d+)\s+(.*)", text)
    if not m:
        return None
    unit, slot, port, tail = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)

    t = tail.lower()
    # 20G stacking ports -> Tw (per your note)
    if "20g" in t or "20 g" in t:
        itype = "Tw"
    elif "10g" in t or "ten" in t or "tengig" in t or "ten-gig" in t or "ten gig" in t:
        itype = "Te"
    elif "fast" in t or "100m" in t:
        itype = "Fa"
    else:
        # Default to Gigabit for anything else mentioning 1G/gigabit
        itype = "Gi"

    return f"{itype}{unit}/{slot}/{port}"


def _should_exclude(name: str, alias: str, include: List[str], exclude: List[str]) -> bool:
    """
    Default filtering:
      - Exclude CPU, loopback, and "Link Aggregate" virtual interfaces
      - Keep VLANs
      - Then apply include/exclude lists (simple substring case-insensitive)
    """
    text = f"{name} {alias}".lower()

    if "cpu" in text or "software loopback" in text or text.startswith("link aggregate"):
        return True

    if include and not any(pat.lower() in text for pat in include):
        return True
    if exclude and any(pat.lower() in text for pat in exclude):
        return True

    return False


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Switch Manager port switches."""
    coordinator = _resolve_coordinator(hass, entry)
    ports = coordinator.data.get("ports", {})

    # Include/Exclude (comma-separated) from Options
    include_opt = (entry.options.get("include") or "").strip()
    exclude_opt = (entry.options.get("exclude") or "").strip()
    include = [s.strip() for s in (include_opt.split(",") if include_opt else [])]
    exclude = [s.strip() for s in (exclude_opt.split(",") if exclude_opt else [])]

    entities: list[SwitchManagerPort] = []
    iterable = ports.values() if isinstance(ports, dict) else ports
    seen_indices: set[int] = set()

    for port in iterable:
        if not isinstance(port, dict):
            continue
        idx = int(port.get("index", 0))
        if idx in seen_indices:
            continue  # de-dup by ifIndex
        seen_indices.add(idx)

        name = str(port.get("name") or "")
        alias = str(port.get("alias") or "")

        if _should_exclude(name, alias, include, exclude):
            continue

        short = _short_intf_name(name, alias)
        friendly = short or (alias if alias else f"Port {idx}")

        entities.append(SwitchManagerPort(coordinator, entry, idx, friendly))

    if not entities:
        _LOGGER.warning("No ports matched filter; total available: %s", len(list(iterable)))

    async_add_entities(entities)


class SwitchManagerPort(CoordinatorEntity, SwitchEntity):
    """Representation of a network switch port."""

    _attr_should_poll = False

    def __init__(self, coordinator, entry, port_index: int, friendly_name: str):
        """Initialize the switch port entity."""
        super().__init__(coordinator)
        self._entry = entry
        self._port_index = port_index
        self._attr_unique_id = f"{entry.entry_id}_{port_index}"
        self._attr_name = friendly_name

    # -------- device info (manufacturer/model/firmware/uptime/hostname) ----------
    @property
    def device_info(self) -> Dict[str, Any]:
        sysinfo = self.coordinator.data.get("system", {}) if hasattr(self.coordinator, "data") else {}
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": sysinfo.get("hostname") or (self._entry.title or "Switch"),
            "manufacturer": sysinfo.get("manufacturer"),
            "model": sysinfo.get("model"),
            "sw_version": sysinfo.get("firmware"),
        }

    @property
    def is_on(self) -> bool:
        """Return True if port is administratively up."""
        ports = self.coordinator.data.get("ports", {})
        port = ports.get(self._port_index) if isinstance(ports, dict) else None
        if isinstance(port, dict):
            admin = port.get("admin")
            return admin == 1
        return False

    async def async_turn_on(self, **kwargs) -> None:
        """Enable the switch port (ifAdminStatus = up(1))."""
        client = getattr(self.coordinator, "client", None)
        if client is None:
            _LOGGER.error("No SNMP client available for port %s", self._port_index)
            return
        try:
            await client.async_set_octet_string(
                f"1.3.6.1.2.1.2.2.1.7.{self._port_index}", 1
            )
            await self.coordinator.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to enable port %s: %s", self._port_index, err)

    async def async_turn_off(self, **kwargs) -> None:
        """Disable the switch port (ifAdminStatus = down(2))."""
        client = getattr(self.coordinator, "client", None)
        if client is None:
            _LOGGER.error("No SNMP client available for port %s", self._port_index)
            return
        try:
            await client.async_set_octet_string(
                f"1.3.6.1.2.1.2.2.1.7.{self._port_index}", 2
            )
            await self.coordinator.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to disable port %s: %s", self._port_index, err)

    @staticmethod
    def _cidrs_from_ipv4_list(records: List[Dict[str, str]]) -> List[str]:
        out: List[str] = []
        for rec in records or []:
            addr = str(rec.get("address", ""))
            mask = str(rec.get("netmask", ""))
            try:
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                out.append(f"{ipaddress.IPv4Address(addr)}/{prefix}")
            except Exception:
                continue
        return out

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose additional port attributes including IPv4+CIDR and system info."""
        data = self.coordinator.data if hasattr(self.coordinator, "data") else {}
        sysinfo = data.get("system", {})
        ports = data.get("ports", {})
        port = ports.get(self._port_index) if isinstance(ports, dict) else None

        attrs: dict[str, Any] = {}
        if isinstance(port, dict):
            attrs.update({
                "index": port.get("index", self._port_index),
                "name": port.get("name"),
                "alias": port.get("alias"),
                "admin": port.get("admin"),
                "oper": port.get("oper"),
            })

            ipv4 = port.get("ipv4") or []
            cidrs = self._cidrs_from_ipv4_list(ipv4)
            if cidrs:
                attrs["ip_cidr_primary"] = cidrs[0]
                attrs["ipv4_cidrs"] = cidrs
                # keep first address/mask for simple UIs
                attrs["ip_address"] = (ipv4[0] or {}).get("address")
                attrs["netmask"] = (ipv4[0] or {}).get("netmask")

        # System-level attrs
        if sysinfo:
            attrs.setdefault("hostname", sysinfo.get("hostname"))
            if "uptime_seconds" in sysinfo:
                attrs.setdefault("uptime_seconds", sysinfo.get("uptime_seconds"))
            if "uptime" in sysinfo:
                attrs.setdefault("uptime", sysinfo.get("uptime"))
            attrs.setdefault("manufacturer", sysinfo.get("manufacturer"))
            attrs.setdefault("model", sysinfo.get("model"))
            attrs.setdefault("firmware", sysinfo.get("firmware"))

        return attrs
