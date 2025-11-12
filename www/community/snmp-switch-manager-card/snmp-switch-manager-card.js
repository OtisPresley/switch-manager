class SnmpSwitchManagerCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._config = null;
    this._hass = null;
  }

  setConfig(config) {
    // Accept either explicit ports or auto-discovery with optional device_name
    // Supported keys:
    //  - title: string
    //  - image: /local/... (optional, for "image" layout)
    //  - layout: "image" | "grid"  (default: "grid")
    //  - ports: [entity_id, ...]   (optional explicit list)
    //  - device_name: "SWITCH-BONUSCLOSET" (optional filter, substring match)
    this._config = {
      title: config.title ?? "Switch",
      image: config.image ?? null,
      layout: (config.layout === "image" || config.layout === "grid") ? config.layout : "grid",
      ports: Array.isArray(config.ports) ? config.ports : null,
      device_name: config.device_name ?? null,
      marker_size: Number.isFinite(config.marker_size) ? Number(config.marker_size) : 26,
    };
    this._render();
  }

  set hass(hass) {
    this._hass = hass;
    this._render();
  }

  getCardSize() {
    return 4;
  }

  _discoverPorts() {
    if (!this._hass) return [];

    // If user supplied an explicit list, normalize/return that
    if (this._config.ports && this._config.ports.length) {
      return this._config.ports
        .map((entity_id) => {
          const st = this._hass.states[entity_id];
          if (!st) return null;
          return { entity_id, state: st };
        })
        .filter(Boolean);
    }

    // AUTO-DISCOVERY:
    // Find switch.* entities that look like ports from THIS integration:
    // Heuristic: must have attributes.Index (capital I) as created by snmp_switch_manager
    // Also accept lowercase 'index' just in case.
    const all = Object.entries(this._hass.states);

    const filtered = all
      .filter(([eid, st]) => {
        if (!eid.startsWith("switch.")) return false;
        if (!st || !st.attributes) return false;

        const hasIndex =
          st.attributes.Index !== undefined ||
          st.attributes.index !== undefined;

        if (!hasIndex) return false;

        // Optional device filter: substring match in friendly_name OR entity_id
        if (this._config.device_name) {
          const dn = String(this._config.device_name).toLowerCase();
          const fn = String(st.attributes.friendly_name || "").toLowerCase();
          const id = eid.toLowerCase();
          if (!fn.includes(dn) && !id.includes(dn)) return false;
        }
        return true;
      })
      .map(([entity_id, state]) => ({ entity_id, state }));

    // Sort by the integration's Name attribute when present, else by entity_id
    filtered.sort((a, b) => {
      const na = (a.state.attributes.Name || a.entity_id).toString();
      const nb = (b.state.attributes.Name || b.entity_id).toString();
      return na.localeCompare(nb, undefined, { numeric: true, sensitivity: "base" });
    });

    return filtered;
  }

  _render() {
    if (!this.shadowRoot || !this._config || !this._hass) return;

    const ports = this._discoverPorts();

    // Base styles
    const style = `
      :host { display: block; }
      ha-card { display: block; padding: 0; }
      .header {
        font-size: 20px;
        font-weight: 600;
        padding: 12px 16px;
        border-bottom: 1px solid var(--divider-color);
      }
      .body { padding: 12px; }
      .empty { color: var(--secondary-text-color); padding: 12px 16px; }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
        gap: 8px;
      }
      .port {
        border-radius: 10px;
        padding: 10px;
        border: 1px solid var(--divider-color);
        background: var(--card-background-color);
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .port .name { font-weight: 600; }
      .kv { font-size: 12px; color: var(--secondary-text-color); }
      .image-wrap {
        position: relative;
        overflow: hidden;
        border-radius: 12px;
      }
      .image-wrap img {
        display: block;
        width: 100%;
        height: auto;
      }
      .marker {
        position: absolute;
        width: ${this._config.marker_size}px;
        height: ${this._config.marker_size}px;
        border-radius: 50%;
        background: var(--primary-color);
        opacity: 0.85;
        transform: translate(-50%, -50%);
        cursor: pointer;
        border: 2px solid rgba(0,0,0,.25);
      }
    `;

    // Build content
    const header = `<div class="header">${this._config.title}</div>`;

    let body = "";
    if (!ports.length) {
      body = `<div class="empty">No ports to display yet.</div>`;
    } else if (this._config.layout === "image" && this._config.image) {
      // Image layout (markers don’t have coordinates yet—future enhancement)
      body = `
        <div class="body">
          <div class="image-wrap">
            <img src="${this._config.image}" alt="switch front" />
            <!-- In a later version we can add coordinate-aware markers -->
          </div>
        </div>`;
    } else {
      // Grid layout
      const grid = ports
        .map(({ entity_id, state }) => {
          const attrs = state.attributes || {};
          const name = attrs.Name || entity_id.split(".")[1];
          const admin = attrs.Admin ?? "Unknown";
          const oper = attrs.Oper ?? "Unknown";
          const ip = attrs.IP ?? attrs.Ip ?? ""; // supports your new IP attribute
          const idx = attrs.Index ?? attrs.index ?? "";

          // Toggle handler
          const toggle = `
            <mwc-button
              outlined
              data-entity="${entity_id}"
              @click="${(ev) => this._handleToggle(ev)}"
            >Toggle</mwc-button>
          `;

          return `
            <div class="port">
              <div class="name">${name}</div>
              <div class="kv">Entity: ${entity_id}</div>
              <div class="kv">Index: ${idx}</div>
              <div class="kv">Admin: ${admin} | Oper: ${oper}</div>
              ${ip ? `<div class="kv">IP: ${ip}</div>` : ``}
              <ha-entity-toggle
                .hass=${"__HASS__"}
                .stateObj=${"__STATE__" + entity_id}
              ></ha-entity-toggle>
            </div>
          `;
        })
        .join("");

      body = `<div class="body"><div class="grid">${grid}</div></div>`;
    }

    // Compose DOM
    this.shadowRoot.innerHTML = `
      <ha-card>
        <style>${style}</style>
        ${header}
        ${body}
      </ha-card>
    `;

    // Wire up toggles using HA’s built-in toggle for correct semantics
    // Replace placeholders with actual objects (safe approach for HA cards)
    ports.forEach(({ entity_id, state }) => {
      const toggles = this.shadowRoot.querySelectorAll("ha-entity-toggle");
      toggles.forEach((t) => {
        if (!t.getAttribute("data-wired")) {
          // Patch placeholders
          if (t.outerHTML.includes("__STATE__" + entity_id)) {
            t.hass = this._hass;
            t.stateObj = state;
            t.setAttribute("data-wired", "1");
          }
        }
      });
    });
  }

  _handleToggle(ev) {
    const entity_id = ev.currentTarget?.getAttribute("data-entity");
    if (!entity_id || !this._hass) return;
    const current = this._hass.states[entity_id];
    const turnOn = (current?.state ?? "off") !== "on";
    this._hass.callService("switch", turnOn ? "turn_on" : "turn_off", {
      entity_id,
    });
  }
}

customElements.define("snmp-switch-manager-card", SnmpSwitchManagerCard);

// Card picker metadata
window.customCards = window.customCards || [];
window.customCards.push({
  type: "snmp-switch-manager-card",
  name: "SNMP Switch Manager Card",
  description: "Auto-discovers SNMP Switch Manager ports and renders them.",
});
