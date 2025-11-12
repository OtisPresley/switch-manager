# SNMP Switch Manager: Home Assistant Custom Integration

[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-41BDF5?logo=home-assistant&logoColor=white&style=flat)](https://www.home-assistant.io/)
[![HACS Badge](https://img.shields.io/badge/HACS-Default-41BDF5.svg)](https://hacs.xyz)
[![License: MIT](https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/license-mit.svg)](https://github.com/OtisPresley/snmp-switch-manager/blob/main/LICENSE)
[![hassfest](https://img.shields.io/github/actions/workflow/status/OtisPresley/snmp-switch-manager/hassfest.yaml?branch=main&label=hassfest)](https://github.com/OtisPresley/snmp-switch-manager/actions/workflows/hassfest.yaml)
[![HACS](https://img.shields.io/github/actions/workflow/status/OtisPresley/snmp-switch-manager/hacs.yaml?branch=main&label=HACS)](https://github.com/OtisPresley/snmp-switch-manager/actions/workflows/hacs.yaml)
[![CI](https://img.shields.io/github/actions/workflow/status/OtisPresley/snmp-switch-manager/ci.yaml?branch=main&event=push)](https://github.com/OtisPresley/snmp-switch-manager/actions/workflows/ci.yaml)

SNMP Switch Manager discovers an SNMP-enabled switch and exposes each port to [Home Assistant](https://www.home-assistant.io/) with live status, descriptions, and administrative control. Pair it with the included Lovelace card for a rich dashboard visualisation of your hardware.

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

- Home Assistant 2024.12 or newer (recommended)
- A switch reachable via SNMP v2c (UDP/161) with read access to interface tables and write access to `ifAlias`
- The SNMP community string that grants the required permissions
- pysnmp 4.x (the integration installs it automatically when needed)

---

## Installation

### Install through HACS (recommended)

1. In Home Assistant, open **HACS → Integrations → ⋮ → Custom repositories** and add `https://github.com/OtisPresley/snmp-switch-manager` as an Integration repository.
2. Search HACS for **Switch Manager** and click **Download**.
3. Restart Home Assistant when prompted.

### Manual installation

1. Download the latest release ZIP from the [GitHub releases page](https://github.com/OtisPresley/snmp-switch-manager/releases).
2. Copy `custom_components/snmp_switch_manager` into your Home Assistant `custom_components` directory.
3. Copy `www/community/snmp-switch-manager-card` into `www/community` (create the path if necessary).
4. Restart Home Assistant.

---

## Configuration

1. Go to **Settings → Devices & services → Add integration** and search for **SNMP Switch Manager**.
2. Enter the switch hostname/IP address, the SNMP community string, and optionally a friendly name or non-standard SNMP port.
3. Once the flow completes, Home Assistant adds one `switch` entity per discovered interface. Entities follow the pattern `switch.<device_name>_port_<index>`.

---

## Lovelace card

1. Download the snmp-switch-manager-card.js file from the [SNMP Switch Manager Card](https://github.com/OtisPresley/snmp-switch-manager-card) repository and place it in `www/community/snmp-switch-manager-card/` in Home Assistant.

2. Add the card JavaScript as a resource under **Settings → Dashboards → Resources**:

   ```yaml
   url: /local/community/snmp-switch-manager-card/snmp-switch-manager-card.js
   type: module
   ```

3. Place the card on any dashboard:

   ```yaml
    type: custom:snmp-switch-manager-card
    title: Core Switch
    view: panel
    ports_per_row: 12
    info_position: below
    label_size: 8
    anchor_entity: switch.gi1_0_1
    diagnostics:
      - sensor.hostname
      - sensor.firmware_revision
      - sensor.manufacturer
      - sensor.model
      - sensor.uptime
   ```

   The `anchor_entity` is any entity in your switch so it knows which ports and diagnostics to display.
   
   Clicking a port opens a dialog with quick actions to toggle the port or edit its description. There is also an alternative `list` view depicted in the      third image below.

    <p float="left">
      <img src="https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/screenshot1.png" alt="Screenshot 1" width="315"/>
      <img src="https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/screenshot2.png" alt="Screenshot 2" width="315"/>
      <img src="https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/screenshot3.png" alt="Screenshot 3" width="315"/>
    </p>

---

## Services

### Update a port description

Use the `snmp_switch_manager.set_port_description` service to change an interface alias:

```yaml
service: snmp_switch_manager.set_port_description
data:
  entity_id: switch.gi1_0_5
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

- Open an issue on the [GitHub tracker](https://github.com/OtisPresley/snmp-switch-manager/issues) if you run into problems or have feature requests.
- Contributions and feedback are welcome!

If you find this integration useful and want to support development, you can:

[![Buy Me a Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-orange)](https://www.buymeacoffee.com/OtisPresley)
[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/OtisPresley)
