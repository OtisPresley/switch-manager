class SwitchManagerCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._config = null;
    this._hass = null;
    this._dialogEntity = null;
  }

  setConfig(config) {
    if (!config.entities || !Array.isArray(config.entities) || !config.entities.length) {
      throw new Error("You must provide a list of port switch entities.");
    }
    this._config = {
      title: config.title,
      image: config.image,
      entities: config.entities,
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

  _render() {
    if (!this._config || !this._hass) {
      return;
    }

    const entities = this._config.entities
      .map((entityId) => ({
        entityId,
        stateObj: this._hass.states[entityId],
      }))
      .filter((item) => item.stateObj);

    const style = `
      :host {
        display: block;
      }
      ha-card {
        display: block;
        padding: 0;
      }
      .card {
        padding: 16px;
        box-sizing: border-box;
        position: relative;
      }
      .header {
        font-size: 20px;
        font-weight: 500;
        margin-bottom: 12px;
      }
      .switch-image {
        width: 100%;
        max-height: 180px;
        object-fit: contain;
        margin-bottom: 12px;
        border-radius: 8px;
      }
      .ports {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(70px, 1fr));
        gap: 8px;
      }
      .port {
        background: var(--primary-background-color);
        border-radius: 6px;
        padding: 8px;
        text-align: center;
        cursor: pointer;
        border: 2px solid transparent;
        transition: transform 0.1s ease;
      }
      .port:hover {
        transform: translateY(-2px);
      }
      .port-name {
        font-size: 12px;
        font-weight: 600;
        margin-bottom: 6px;
      }
      .port-status {
        width: 100%;
        height: 12px;
        border-radius: 4px;
        background: var(--divider-color);
      }
      .port-status.on {
        background: var(--success-color, #21ba45);
      }
      .port-status.off {
        background: var(--error-color, #db2828);
      }
      .port-status.unknown {
        background: var(--warning-color, #fbbd08);
      }
      .dialog-backdrop {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.4);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10;
      }
      .dialog {
        background: var(--card-background-color);
        padding: 16px;
        border-radius: 12px;
        width: 320px;
        max-width: 90%;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
        display: flex;
        flex-direction: column;
        gap: 12px;
      }
      .dialog h3 {
        margin: 0;
        font-size: 18px;
      }
      .dialog .description-input {
        width: 100%;
        padding: 8px;
        border-radius: 6px;
        border: 1px solid var(--divider-color);
        background: var(--primary-background-color);
        color: var(--primary-text-color);
      }
      .dialog .actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
      }
      button {
        border: none;
        border-radius: 6px;
        padding: 8px 12px;
        cursor: pointer;
      }
      button.primary {
        background: var(--primary-color);
        color: var(--text-primary-color);
      }
      button.secondary {
        background: var(--secondary-background-color, #e0e0e0);
        color: var(--primary-text-color);
      }
    `;

    const wrapper = document.createElement("div");
    wrapper.classList.add("card");

    if (this._config.title) {
      const header = document.createElement("div");
      header.classList.add("header");
      header.textContent = this._config.title;
      wrapper.appendChild(header);
    }

    if (this._config.image) {
      const img = document.createElement("img");
      img.src = this._config.image;
      img.classList.add("switch-image");
      img.alt = this._config.title || "Switch";
      wrapper.appendChild(img);
    }

    if (entities.length) {
      const ports = document.createElement("div");
      ports.classList.add("ports");

      entities.forEach(({ entityId, stateObj }) => {
        const port = document.createElement("div");
        port.classList.add("port");
        port.dataset.entity = entityId;

        const name = document.createElement("div");
        name.classList.add("port-name");
        name.textContent = stateObj.attributes.friendly_name || entityId;
        port.appendChild(name);

        const status = document.createElement("div");
        status.classList.add("port-status");
        const haState = stateObj.state;
        if (haState === "on") {
          status.classList.add("on");
        } else if (haState === "off") {
          status.classList.add("off");
        } else {
          status.classList.add("unknown");
        }
        port.appendChild(status);

        const desc = document.createElement("div");
        desc.style.fontSize = "11px";
        desc.style.marginTop = "4px";
        desc.textContent = stateObj.attributes.description || "";
        port.appendChild(desc);

        port.addEventListener("click", () => this._openDialog(entityId));
        ports.appendChild(port);
      });

      wrapper.appendChild(ports);
    } else {
      const empty = document.createElement("div");
      empty.style.fontStyle = "italic";
      empty.style.fontSize = "13px";
      empty.textContent = "No port entities available.";
      wrapper.appendChild(empty);
    }

    const card = document.createElement("ha-card");
    card.appendChild(wrapper);

    const root = document.createElement("div");
    root.appendChild(card);

    if (this._dialogEntity) {
      const dialog = this._createDialog();
      root.appendChild(dialog);
    }

    this.shadowRoot.innerHTML = `
      <style>${style}</style>
    `;
    this.shadowRoot.appendChild(root);
  }

  _createDialog() {
    const entityId = this._dialogEntity;
    const stateObj = this._hass.states[entityId];
    const backdrop = document.createElement("div");
    backdrop.classList.add("dialog-backdrop");
    backdrop.addEventListener("click", (event) => {
      if (event.target === backdrop) {
        this._closeDialog();
      }
    });

    const dialog = document.createElement("div");
    dialog.classList.add("dialog");

    const title = document.createElement("h3");
    title.textContent = stateObj?.attributes?.friendly_name || entityId;
    dialog.appendChild(title);

    const status = document.createElement("div");
    status.textContent = `Admin: ${stateObj?.attributes?.admin_status || stateObj?.state}, Oper: ${stateObj?.attributes?.oper_status || "unknown"}`;
    status.style.fontSize = "13px";
    dialog.appendChild(status);

    const descriptionInput = document.createElement("input");
    descriptionInput.type = "text";
    descriptionInput.classList.add("description-input");
    descriptionInput.value = stateObj?.attributes?.description || "";
    dialog.appendChild(descriptionInput);

    const actions = document.createElement("div");
    actions.classList.add("actions");

    const toggle = document.createElement("button");
    toggle.classList.add("secondary");
    toggle.textContent = stateObj?.state === "on" ? "Disable port" : "Enable port";
    toggle.addEventListener("click", async () => {
      await this._togglePort(entityId, stateObj?.state !== "on");
      this._closeDialog();
    });
    actions.appendChild(toggle);

    const save = document.createElement("button");
    save.classList.add("primary");
    save.textContent = "Save description";
    save.addEventListener("click", async () => {
      await this._setDescription(entityId, descriptionInput.value);
      this._closeDialog();
    });
    actions.appendChild(save);

    const cancel = document.createElement("button");
    cancel.classList.add("secondary");
    cancel.textContent = "Cancel";
    cancel.addEventListener("click", () => this._closeDialog());
    actions.appendChild(cancel);

    dialog.appendChild(actions);
    backdrop.appendChild(dialog);
    return backdrop;
  }

  _openDialog(entityId) {
    this._dialogEntity = entityId;
    this._render();
  }

  _closeDialog() {
    this._dialogEntity = null;
    this._render();
  }

  async _togglePort(entityId, turnOn) {
    const [domain, service] = turnOn ? ["switch", "turn_on"] : ["switch", "turn_off"];
    await this._hass.callService(domain, service, { entity_id: entityId });
  }

  async _setDescription(entityId, description) {
    await this._hass.callService("switch_manager", "set_port_description", {
      entity_id: entityId,
      description,
    });
  }
}

if (!customElements.get("switch-manager-card")) {
  customElements.define("switch-manager-card", SwitchManagerCard);
}

if (window.customCards === undefined) {
  window.customCards = [];
}

if (!window.customCards.some((card) => card.type === "switch-manager-card")) {
  window.customCards.push({
    type: "switch-manager-card",
    name: "Switch Manager",
    description: "Visualise and manage switch ports discovered by the Switch Manager integration.",
  });
}
