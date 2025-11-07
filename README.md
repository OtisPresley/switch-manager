# Switch Manager for Home Assistant

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge)](https://hacs.xyz/)
[![GitHub release](https://img.shields.io/github/v/release/OtisPresley/switch-manager?style=for-the-badge)](https://github.com/OtisPresley/switch-manager/releases)
[![GitHub issues](https://img.shields.io/github/issues/OtisPresley/switch-manager?style=for-the-badge)](https://github.com/OtisPresley/switch-manager/issues)
[![License](https://img.shields.io/github/license/OtisPresley/switch-manager?style=for-the-badge)](LICENSE)

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20the%20project-FF5E5B?style=for-the-badge&logo=ko-fi)](https://ko-fi.com/otispresley)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/OtisPresley)

Switch Manager discovers an SNMP-enabled switch and exposes every port to Home Assistant with live status, descriptions, and administrative control. Pair it with the included Lovelace card for a rich dashboard visualisation of your hardware.

## Features

- 🔍 Automatic discovery of port count, speed, description, and operational status via SNMP v2c
- 🔄 Background polling that keeps Home Assistant entities in sync with switch updates
- 🎚️ One `switch` entity per interface for toggling administrative state (up/down)
- 🏷️ Service for updating the interface alias (`ifAlias`) without leaving Home Assistant
- 🖼️ Lovelace card that mirrors the switch layout with colour-coded port status and quick actions

## Requirements

- Home Assistant 2023.12 or newer (recommended)
- A switch reachable via SNMP v2c (UDP/161) with read access to interface tables and write access to `ifAlias`
- The SNMP community string that grants the required permissions

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

## Configuration

1. Go to **Settings → Devices & services → Add integration** and search for **Switch Manager**.
2. Enter the switch hostname/IP address, the SNMP community string, and optionally a friendly name or non-standard SNMP port.
3. Once the flow completes, Home Assistant adds one `switch` entity per discovered interface. Entities follow the pattern `switch.<device_name>_port_<index>`.

### Update a port description

Use the `switch_manager.set_port_description` service to change an interface alias:

```yaml
service: switch_manager.set_port_description
data:
  entity_id: switch.core_switch_port_5
  description: Uplink to router
```

### Toggle administrative state

The state of each port entity reflects the interface's administrative status. Turning it **on** sets the port to *up*; turning it **off** sets it to *down*. Entity attributes include both administrative and operational status direct from SNMP.

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
   image: /local/images/core-switch.png
   entities:
     - switch.core_switch_port_1
     - switch.core_switch_port_2
     - switch.core_switch_port_3
   ```

Clicking a port opens a dialog with quick actions to toggle the port or edit its description.

## Troubleshooting

- **Ports missing:** Ensure the SNMP community string permits reads on the interface tables (`ifDescr`, `ifSpeed`, `ifOperStatus`).
- **Description updates fail:** Confirm the community string has write permission for `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`).
- **Unexpected speeds:** Some devices report zero or vendor-specific rates for unused interfaces; check the switch UI to confirm raw SNMP data.

## Support

Open an issue on the [GitHub tracker](https://github.com/OtisPresley/switch-manager/issues) if you run into problems or have feature requests. Contributions and feedback are welcome!
