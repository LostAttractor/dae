"use strict";

const byId = (id) => document.getElementById(id);
let device = null;

function message(id, value = "", error = false) {
  const target = byId(id);
  target.textContent = value;
  target.classList.toggle("error", error);
}

async function request(path, method = "GET", body, headers = {}) {
  if (method !== "GET") headers["X-Dae-API"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method, headers, cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const detail = response.headers.get("Content-Type")?.startsWith("application/json")
      ? (await response.json()).error : await response.text();
    const error = new Error(detail || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

async function change(messageId, controls, action, refresh) {
  controls.disabled = true;
  message(messageId, "Saving…");
  try {
    await action();
    await refresh();
    message(messageId, "Saved.");
  } catch (error) {
    message(messageId, error.message, true);
  } finally {
    controls.disabled = false;
  }
}

function renderDevice() {
  const sets = byId("sets");
  sets.replaceChildren();
  byId("device-identity").textContent = `IP ${device.source_ip} · MAC ${device.mac}`;
  for (const set of device.sets) {
    const row = byId("set-template").content.firstElementChild.cloneNode(true);
    row.querySelector(".name").textContent = set.name;
    row.querySelector(".state").textContent = set.joined ? "Joined" : "Not joined";
    row.querySelector(".description").textContent = set.description;
    const button = row.querySelector("button");
    button.textContent = set.joined ? "Leave" : "Join";
    button.onclick = () => change("device-message", row,
      () => request(`/api/device/sets/${encodeURIComponent(set.name)}`, set.joined ? "DELETE" : "PUT"),
      loadDevice);
    sets.append(row);
  }
  if (!device.sets.length) sets.textContent = "No client sets configured.";
  renderMITM();
}

function renderMITM() {
  const mitm = device?.mitm;
  byId("mitm-toggle").disabled = !mitm;
  byId("mitm-toggle").textContent = mitm?.enabled ? "Disable" : "Enable";
  byId("mitm-reset").disabled = !mitm || mitm.override === null;
  if (!device) {
    byId("mitm-status").textContent = "Device controls unavailable. You can still download the certificate.";
  } else if (!mitm) {
    byId("mitm-status").textContent = "HTTPS modules are not enabled on this router.";
  } else {
    const source = mitm.override === null ? "configuration" : "device override";
    byId("mitm-status").textContent = `${mitm.enabled ? "Enabled" : "Disabled"} · ${source}`;
  }
}

async function loadDevice() {
  try {
    device = await request("/api/device");
    renderDevice();
  } catch (error) {
    device = null;
    byId("sets").replaceChildren();
    byId("device-identity").textContent = "This device could not be identified.";
    renderMITM();
    throw error;
  }
}

async function loadSelectors() {
  const data = await request("/api/selectors");
  const list = byId("selectors");
  byId("token-field").hidden = !data.admin_enabled;
  byId("api-token").disabled = !data.admin_enabled;
  byId("admin-disabled").hidden = data.admin_enabled;
  list.replaceChildren();
  for (const [index, selector] of data.selectors.entries()) {
    const row = byId("selector-template").content.firstElementChild.cloneNode(true);
    const select = row.querySelector("select");
    const label = row.querySelector("label");
    label.textContent = selector.name;
    select.id = `selector-${index}`;
    label.htmlFor = select.id;
    for (const node of selector.nodes) {
      const latency = Number.isFinite(node.latency_ms) ? ` · ${Math.round(node.latency_ms)} ms` : "";
      const state = node.checking ? " · checking" : node.healthy ? "" : " · unavailable";
      select.add(new Option(`${node.name}${latency}${state}`, node.id));
    }
    select.value = selector.node_id;
    const defaultNode = selector.nodes.find((node) => node.id === selector.default_node_id);
    row.querySelector(".state").textContent = `${selector.overridden ? "Manual override" : "Using configuration"} · Default: ${defaultNode?.name || "unavailable"}`;
    const apply = row.querySelector(".apply");
    const reset = row.querySelector(".reset");
    row.disabled = !data.admin_enabled;
    select.disabled = apply.disabled = !selector.nodes.length;
    reset.disabled = !selector.overridden;
    const path = `/api/selectors/${encodeURIComponent(selector.name)}`;
    const save = (method, body) => {
      const token = byId("api-token").value;
      if (!token) {
        message("selectors-message", "Enter the configured API token to change a selector.", true);
        byId("api-token").focus();
        return;
      }
      return change("selectors-message", row,
        () => request(path, method, body, { Authorization: `Bearer ${token}` }), loadSelectors);
    };
    apply.onclick = () => save("PUT", { node_id: select.value });
    reset.onclick = () => save("DELETE");
    list.append(row);
  }
  if (!data.selectors.length) list.textContent = "No selector policies are configured.";
}

async function loadCertificate() {
  byId("certificate-details").hidden = true;
  try {
    const certificate = await request("/api/certificate");
    byId("https-panel").hidden = false;
    byId("certificate-status").textContent = certificate.name;
    byId("fingerprint").textContent = certificate.fingerprint;
    byId("certificate-details").hidden = false;
  } catch (error) {
    if (error.status !== 404) {
      byId("https-panel").hidden = false;
      byId("certificate-status").textContent = "Certificate information is unavailable.";
      throw error;
    }
    byId("https-panel").hidden = true;
  }
}

function setMITM(enabled) {
  if (!device?.mitm) return;
  const headers = { "X-Dae-MITM": device.mitm.ca_fingerprint };
  change("mitm-message", byId("mitm-controls"),
    () => request("/api/device/mitm", enabled === undefined ? "DELETE" : "PUT",
      enabled === undefined ? undefined : { enabled }, headers), loadDevice);
}

async function refresh() {
  byId("refresh").disabled = true;
  message("mitm-message");
  await Promise.all([
    ["device-message", loadDevice],
    ["selectors-message", loadSelectors],
    ["certificate-message", loadCertificate],
  ].map(async ([id, load]) => {
    message(id);
    try { await load(); } catch (error) { message(id, error.message, true); }
  }));
  byId("refresh").disabled = false;
}

byId("mitm-toggle").onclick = () => setMITM(!device?.mitm?.enabled);
byId("mitm-reset").onclick = () => setMITM();
byId("refresh").onclick = refresh;
refresh();
