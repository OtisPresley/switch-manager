# SNMP Switch Manager: Home Assistant Custom Integration

[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-41BDF5?logo=home-assistant&logoColor=white&style=flat)](https://www.home-assistant.io/)
[![HACS Badge](https://img.shields.io/badge/HACS-Default-41BDF5.svg)](https://hacs.xyz)
[![HA installs](https://img.shields.io/badge/dynamic/json?url=https://analytics.home-assistant.io/custom_integrations.json&query=$.snmp_switch_manager.total&label=Installs&color=41BDF5)](https://analytics.home-assistant.io/custom_integrations.json)
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

- Home Assistant 2025.11.2 or newer (recommended)
- A switch reachable via SNMP v2c (UDP/161) with read access to interface tables and write access to `ifAlias`
- The SNMP community string that grants the required permissions
- pysnmp 7.x (the integration installs it automatically when needed)

---

## Installation

### HACS (recommended)
You can install this integration directly from HACS:

[![Open your Home Assistant instance and show the repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=OtisPresley&repository=snmp-switch-manager)

After installation, restart Home Assistant and add the integration:

[![Open your Home Assistant instance and add this integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=snmp_switch_manager)

---

#### Manual steps (if you prefer not to use the buttons)
1. In Home Assistant, open **HACS → Integrations**.  
2. Click **Explore & Download Repositories**, search for **SNMP Switch Manager**, then click **Download**.  
3. **Restart Home Assistant**.  
4. Go to **Settings → Devices & Services → Add Integration → SNMP Switch Manager**.  

### Manual install
1. Copy the folder `custom_components/snmp_switch_manager` into your HA `config/custom_components` directory.
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration → SNMP Switch Manager**.

---

## Configuration

1. Go to **Settings → Devices & services → Add integration** and search for **SNMP Switch Manager**.
2. Enter the switch hostname/IP address, the SNMP community string, and optionally a friendly name or non-standard SNMP port.
3. Once the flow completes, Home Assistant adds one `switch` entity per discovered interface. Entities follow the pattern `switch.<device_name>_port_<index>`.

---

## Lovelace card

1. Download the `snmp-switch-manager-card.js` and  `snmp-switch-manager-card-editor.js` files and place them in `www/community/snmp-switch-manager-card/` in Home Assistant.

2. Add the card and editor JavaScript as a resource under **Settings → Dashboards → Resources**:

   ```yaml
   url: /local/community/snmp-switch-manager-card/snmp-switch-manager-card.js
   type: module
   ```

   ```yaml
   url: /local/community/snmp-switch-manager-card/snmp-switch-manager-card-editor.js
   type: module
   ```

3. Place the card on any dashboard and edit via the GUI or in YAML:
   <p float="left">
      <img src="https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/screenshot1.png" alt="Screenshot 1" width="250"/>
   </p>

   ```yaml
    type: custom:snmp-switch-manager-card
    title: Core Switch
    view: panel
    ports_per_row: 24
    info_position: below
    label_size: 6
    anchor_entity: switch.gi1_0_1
    diagnostics:
      - sensor.hostname
      - sensor.firmware_revision
      - sensor.manufacturer
      - sensor.model
      - sensor.uptime
    port_size: 18
    gap: 10
   ```

   The follows are descriptions of the settings:
   - `title` sets the text displayed at the tip of the card.
   - `view` sets the style that the card uses. `list` lists each port in a tile. `panel` show a representation of the front of a switch.
   - `ports_per_row` sets the number of ports to show in each row on the card when in panel view.
   - `info_position` displays the Diagnostics and Virtual Interfaces either `above` the phisical ports or `below` them.
   - `label_size` determines the font size used for the port labels when in panel view.
   - `anchor_entity` is any entity in your switch so it knows which ports and diagnostics to display.
   - `diagnostics` is a list of sensors you want to display in the diagnostics area.
   - `port_size` determines the size of the port images when in panel view.
   - `gap` determines how far apart the ports are when in panel view.
   
   Clicking a port opens a dialog with quick actions to toggle the port or edit its description. The alternative `list` view depicted in the third image below.

    <p float="left">
      <img src="https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/screenshot2.png" alt="Screenshot 1" width="250"/>
      <img src="https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/screenshot3.png" alt="Screenshot 2" width="250"/>
      <img src="https://raw.githubusercontent.com/otispresley/snmp-switch-manager/main/assets/screenshot4.png" alt="Screenshot 3" width="250"/>
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

If your switch does not display correctly, then the integration will need to have specific support added for it. Please open an issue with an text file attachment with the results of an `snmpwalk` command against your switch with an **RW SNMP v2c community string** and any necessary screenshots. Also describe what is incorrect and what it should look like.

### Switches Supported
- Dell EMC Networking OS6

### Open an Issue
- Open an issue on the [GitHub tracker](https://github.com/OtisPresley/snmp-switch-manager/issues) if you run into problems or have feature requests.
- Contributions and feedback are welcome!

If you find this integration useful and want to support development, you can:

[![Buy Me a Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-orange)](https://www.buymeacoffee.com/OtisPresley)
[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/OtisPresley)
