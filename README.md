# Switch Manager: Home Assistant Custom Integration

[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-41BDF5?logo=home-assistant&logoColor=white&style=flat)](https://www.home-assistant.io/)
[![HACS Badge](https://img.shields.io/badge/HACS-Default-41BDF5.svg)](https://hacs.xyz)
[![License: MIT](https://raw.githubusercontent.com/otispresley/switch-manager/main/assets/license-mit.svg)](https://github.com/OtisPresley/switch-manager/blob/main/LICENSE)
[![hassfest](https://img.shields.io/github/actions/workflow/status/OtisPresley/switch-manager/hassfest.yaml?branch=main&label=hassfest)](https://github.com/OtisPresley/switch-manager/actions/workflows/hassfest.yaml)
[![HACS](https://img.shields.io/github/actions/workflow/status/OtisPresley/switch-manager/hacs.yaml?branch=main&label=HACS)](https://github.com/OtisPresley/switch-manager/actions/workflows/hacs.yaml)
[![CI](https://img.shields.io/github/actions/workflow/status/OtisPresley/switch-manager/ci.yaml?branch=main&event=push)](https://github.com/OtisPresley/switch-manager/actions/workflows/ci.yaml)

Switch Manager discovers an SNMP-enabled switch and exposes each port to [Home Assistant](https://www.home-assistant.io/) with live status, descriptions, and administrative control. Pair it with the included Lovelace card for a rich dashboard visualisation of your hardware.

---

## Table of Contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Installation](#installation)
  - [HACS (recommended)](#hacs-recommended)
  - [Manual Install](#manual-install)
- [Configuration](#configuration)
- [Lovelace card](#lovelace-card)
- [Services](#services)
- [Troubleshooting](#troubleshooting)
- [Changelog](https://github.com/OtisPresley/switch-manager/blob/main/CHANGELOG.md)
- [Support](#support)

---

## Highlights

- 🔍 Automatic discovery of port count, speed, description, and operational status via SNMP v2c
- 🔄 Background polling that keeps Home Assistant entities in sync with switch updates
- 🎚️ One `switch` entity per interface for toggling administrative state (up/down)
- 🏷️ Service for updating the interface alias (`ifAlias`) without leaving Home Assistant
- 🖼️ Lovelace card that mirrors the switch layout with colour-coded port status and quick actions

---

## Requirements

- Home Assistant 2023.12 or newer (recommended)
- A switch reachable via SNMP v2c (UDP/161) with read access to interface tables and write access to `ifAlias`
- The SNMP community string that grants the required permissions
- pysnmp 4.x (the integration installs it automatically when needed)

---

## Installation

### Install through HACS (recommended)

1. In Home Assistant, open **HACS → Integrations → ⋮ → Custom repositories** and add `https://github.com/OtisPresley/switch-manager` as an Integration repository.
2. Search HACS for **Switch Manager** and click **Download**.
3. Restart Home Assistant when prompted.

### Manual installation

1. Download the latest release ZIP from the [GitHub releases page](https://github.com/OtisPresley/switch-manager/releases).
2. Copy `custom_components/switch_manager` into your Home Assistant `custom_components` directory.
3. Copy `www/community/switch-manager-card` into `www/community` (create the path if necessary).
4. Restart Home Assistant.

---

## Configuration

1. Go to **Settings → Devices & services → Add integration** and search for **Switch Manager**.
2. Enter the switch hostname/IP address, the SNMP community string, and optionally a friendly name or non-standard SNMP port.
3. Once the flow completes, Home Assistant adds one `switch` entity per discovered interface. Entities follow the pattern `switch.<device_name>_port_<index>`.

---

## Lovelace card

1. Add the card JavaScript as a resource under **Settings → Dashboards → Resources**:

   ```yaml
   url: /hacsfiles/switch-manager-card/switch-manager-card.js
   type: module
   ```

2. Place the card on any dashboard:

   ```yaml
   type: custom:switch-manager-card
   title: Core Switch
   entities:
     - switch.core_switch_port_1
     - switch.core_switch_port_2
     - switch.core_switch_port_3
   ```

   Clicking a port opens a dialog with quick actions to toggle the port or edit its description.

### Overlay a custom switch image

Export the layout of your switch (for example, from Visio) as an image that lives under `/config/www`. The card can place colour-coded markers on top of that image by switching to the `image` layout and providing coordinates for every port:

```yaml
type: custom:switch-manager-card
title: Bonus Closet Switch
image: /local/images/bonus-closet-switch.png
layout: image
marker_size: 28  # optional, defaults to 26px
ports:
  - entity: switch.bonus_closet_port_1
    label: 1
    x: 12.5   # percentage from the left edge
    y: 62     # percentage from the top edge
  - entity: switch.bonus_closet_port_2
    label: 2
    x: 23
    y: 62
  # ...repeat for each port you want to place on the image
```

Markers adopt the port’s administrative status—green for enabled, red for disabled, amber for unknown—and clicking them opens the same management dialog shown in the grid layout.

---

## Services

### Update a port description

Use the `switch_manager.set_port_description` service to change an interface alias:

```yaml
service: switch_manager.set_port_description
data:
  entity_id: switch.core_switch_port_5
  description: Uplink to router
```

---

### Toggle administrative state

The state of each port entity reflects the interface's administrative status. Turning it **on** sets the port to *up*; turning it **off** sets it to *down*. Entity attributes include both administrative and operational status direct from SNMP.

---

## Troubleshooting

- **Ports missing:** Ensure the SNMP community string permits reads on the interface tables (`ifDescr`, `ifSpeed`, `ifOperStatus`).
- **Description updates fail:** Confirm the community string has write permission for `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`).
- **Unexpected speeds:** Some devices report zero or vendor-specific rates for unused interfaces; check the switch UI to confirm raw SNMP data.

---

## Support

- Open an issue on the [GitHub tracker](https://github.com/OtisPresley/switch-manager/issues) if you run into problems or have feature requests.
- Contributions and feedback are welcome!

If you find this integration useful and want to support development, you can:

[![Buy Me a Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-orange)](https://www.buymeacoffee.com/OtisPresley)
[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/OtisPresley)
