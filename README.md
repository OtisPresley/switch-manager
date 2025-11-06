# Home Assistant: Switch Manager

Switch Manager is a Home Assistant custom integration and Lovelace card for discovering and managing network switches via SNMP. Install it through HACS to gain automatic port discovery, live status, and per-port controls directly from Home Assistant.

## Features

- 🕵️ Automatic discovery of interface count, speed, description, and operational status via SNMP v2c
- 🧠 DataUpdateCoordinator-backed polling to keep Home Assistant entities in sync with the switch
- 🔁 Exposes every switch port as a controllable `switch` entity for toggling the administrative state
- 📝 Service for updating a port alias/description
- 🖼️ Lovelace dashboard card that visualises port state with colour coding and quick actions

## Requirements

- Home Assistant 2023.12 or newer (recommended)
- Network switch reachable via SNMP v2c with read/write access to `ifAlias`
- SNMP community string with permission to query and update interface information

## Installation via HACS

1. In Home Assistant, open **HACS → Integrations → ⋮ → Custom repositories** and add `https://github.com/OtisPresley/switch-manager` as an integration repository.
2. From HACS, search for **Switch Manager** and install it.
3. Restart Home Assistant when prompted.

Manual installation is also possible by copying `custom_components/switch_manager` into your Home Assistant `custom_components` directory and `www/community/switch-manager-card` into `www/community`.

## Configuration

1. Navigate to **Settings → Devices & services → Add Integration** and select **Switch Manager**.
2. Enter the switch hostname/IP, SNMP community string, and (optionally) a custom name or SNMP port.
3. After setup, Home Assistant will create one `switch` entity per detected interface. Port entities are named `switch.<device_name>_port_<index>`.

### Updating Port Descriptions

Use the `switch_manager.set_port_description` service to change a port's alias:

```yaml
service: switch_manager.set_port_description
data:
  entity_id: switch.core_switch_port_5
  description: Uplink to Router
```

### Toggling Administrative State

Turning a port entity **on** sets the interface admin status to *up*; turning it **off** sets it to *down*. The entity attributes display both administrative and operational states reported by SNMP.

## Lovelace Card

Add the Switch Manager card as a Lovelace resource, then place it on your dashboard to visualise port state and perform quick actions:

```yaml
resources:
  - url: /hacsfiles/switch-manager-card/switch-manager-card.js
    type: module

views:
  - title: Network
    cards:
      - type: custom:switch-manager-card
        title: Core Switch
        image: /local/images/core-switch.png
        entities:
          - switch.core_switch_port_1
          - switch.core_switch_port_2
          - switch.core_switch_port_3
          # add remaining port entities as needed
```

Clicking a port opens a dialog that mirrors the entity controls, allowing description edits and admin-state toggling without leaving the dashboard.

## Troubleshooting

- **Ports do not appear:** Confirm the SNMP community string grants read access to the interface table (`ifDescr`, `ifSpeed`, `ifOperStatus`).
- **Description updates fail:** Ensure the community string permits write access to `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`). Some switches require enabling write access per OID.
- **Incorrect speeds:** Certain devices report line rate in bits per second; values are converted to human-readable strings, but legacy hardware may report zero for unused interfaces.

For bug reports or feature requests, please open an issue on [GitHub](https://github.com/OtisPresley/switch-manager/issues).
