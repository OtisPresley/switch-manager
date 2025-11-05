# Home Assistant: Switch Manager

Switch Manager is a Home Assistant custom integration and Lovelace card for discovering and managing network switches via SNMP. The integration can be distributed through [HACS](https://hacs.xyz/) for easy installation.

## Features

- 🕵️ Automatic discovery of interface count, speed, description, and operational status via SNMP v2c
- 🧠 DataUpdateCoordinator-backed polling to keep Home Assistant entities in sync with the switch
- 🔁 Exposes every switch port as a controllable `switch` entity for toggling the administrative state
- 📝 Service for updating a port alias/description
- 🖼️ Lovelace dashboard card that visualises port state with colour coding and quick actions

## Installation (HACS)

1. Copy the `custom_components/switch_manager` directory into your Home Assistant `custom_components` folder (or add this repository as a custom repository in HACS).
2. Restart Home Assistant.
3. Navigate to **Settings → Devices & services → Add Integration** and search for **Switch Manager**.
4. Enter the switch hostname/IP, SNMP community string, and optional name/port.

## Entities

Each detected physical/logical interface becomes a Home Assistant `switch` entity named `Port <index>`. Every entity exposes useful attributes:

- `description` — alias/description (from `ifAlias` or `ifDescr`)
- `speed` — formatted human readable interface speed
- `admin_status` — Administrative state (`up`, `down`, ...)
- `oper_status` — Operational state reported by SNMP

Turning the entity on/off toggles the administrative state (up/down) via SNMP.

## Services

`switch_manager.set_port_description`
: Update the alias/description (`ifAlias`) for a port. Parameters:
  - `entity_id`: Port switch entity
  - `description`: New description text

## Lovelace Card

The frontend card is located at `www/community/switch-manager-card/switch-manager-card.js` and renders a visual representation of the switch and its ports. To use it in Lovelace:

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
          # ... add the remaining port entities
```

Clicking on a port opens an inline dialog allowing you to toggle the administrative state or update the description.

## SNMP Notes

- The integration uses SNMP v2c with the provided community string.
- It reads the following OIDs: `ifDescr`, `ifSpeed`, `ifAdminStatus`, `ifOperStatus`, and `ifAlias`.
- Description updates are performed against `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`). Ensure your device permits write access for that OID.

## Development

- Python dependency: `pysnmp>=4.4.12`
- Poll interval defaults to 30 seconds and can be overridden per-entry through future options flow work.

## Working with this repository locally

If you are using a Git-enabled workspace (such as the Codespaces-style environment
backing this project), all files generated above live inside the repository
directory. From a terminal in that environment you can inspect them with:

```bash
cd /workspace/switch-manager
ls
```

To bring the project down to your own computer or push the existing commits to
GitHub:

1. Add the repository remote if it is not already present:
   ```bash
   git remote add origin git@github.com:OtisPresley/switch-manager.git
   ```
2. Push the current branch (`work`) to GitHub:
   ```bash
   git push -u origin work
   ```
3. On another machine, clone the repository:
   ```bash
   git clone git@github.com:OtisPresley/switch-manager.git
   cd switch-manager
   ```
4. You can now view or edit the integration files locally under
   `custom_components/switch_manager/` and the Lovelace card under
   `www/community/switch-manager-card/`.

## Using GitHub Codespaces

If you have already created a Codespace for `OtisPresley/switch-manager`, use the
steps below to synchronise this workspace with that Codespace:

1. **From this environment (where the files were generated):**
   - Verify the GitHub remote exists. If it does not, add it with
     `git remote add origin git@github.com:OtisPresley/switch-manager.git`.
   - Push the current branch so the Codespace can see the commits:
     ```bash
     git push -u origin work
     ```
2. **Inside the Codespace:** open a terminal (it already starts inside a clone of
   your repository) and run:
   ```bash
   git fetch origin
   git checkout work        # create or switch to the branch backed by this work
   git pull --ff-only       # ensure the Codespace copy matches the pushed commits
   ```
   The integration code will now be present under
   `custom_components/switch_manager/` and the Lovelace card under
   `www/community/switch-manager-card/` within the Codespace filesystem.
3. If you would like to keep working on the default branch instead, merge the
   `work` branch into `main` (or whichever branch you prefer) from within the
   Codespace and push the updated branch:
   ```bash
   git checkout main
   git merge work
   git push origin main
   ```

Following this process makes the current integration code available inside the
Codespace you created, while keeping the canonical history on GitHub.

## FAQ: Do I need a special CLI to publish these files?

No additional "Codex" command-line tools are required. Everything here is a
standard Git repository. To move the work into your own GitHub account you only
need the regular Git client that ships with macOS, most Linux distributions, and
the official [Git for Windows](https://git-scm.com/download/win) installer.

This workspace cannot push to your repository automatically because it does not
have your GitHub credentials. Instead, run the `git push` command yourself from
this environment (steps listed above). That single command sends all committed
files to GitHub. Afterwards you can pull or clone the repository from any other
machine — including a Codespace — using normal Git commands, without installing
anything beyond Git itself.

## Publishing to HACS

Follow the [official HACS publishing checklist](https://hacs.xyz/docs/publish/) when you are ready to release a new version:

1. Update `custom_components/switch_manager/manifest.json` with the new semantic version number and ensure dependencies are accurate.
2. Verify `hacs.json` reflects the minimum Home Assistant version you support and keep `render_readme` enabled so the README appears in HACS.
3. Commit and tag the release (for example, `git tag v0.1.0`). HACS consumes GitHub releases, so remember to push both commits and tags.
4. Draft a GitHub release that matches the tag and includes release notes summarizing the changes.
5. After publishing, test installation through HACS to confirm the integration and the Lovelace card both download correctly.

Contributions and feedback are welcome!
