import { request } from "./api.js";

const byId = (id) => document.getElementById(id);
const template = (id) => byId(id).content.firstElementChild.cloneNode(true);

// Serialize user actions and keep the token only in the password field.
async function run(action) {
  const controls = byId("controls");
  if (controls.disabled) return;
  controls.disabled = true;
  byId("message").textContent = "Working…";
  try {
    await action();
    byId("message").textContent = "Done.";
  } catch (error) {
    byId("message").textContent = error.message;
  } finally {
    controls.disabled = false;
  }
}

function renderDevice(device) {
  byId("identity").textContent = `${device.source_ip} · ${device.mac}`;
  byId("sets").replaceChildren();
  for (const set of device.sets) {
    const row = template("set-template");
    row.querySelector("strong").textContent = set.name;
    row.querySelector("small").textContent = set.description;
    const button = row.querySelector("button");
    button.textContent = set.joined ? "Leave" : "Join";
    button.onclick = () => run(async () => renderDevice(await request(
      `/api/device/sets/${encodeURIComponent(set.name)}`, set.joined ? "DELETE" : "PUT")));
    byId("sets").append(row);
  }
  if (!device.sets.length) byId("sets").textContent = "No client sets configured.";

  byId("mitm").replaceChildren();
  if (!device.mitm) {
    byId("mitm").textContent = "HTTPS modules are not enabled on this router.";
    return;
  }
  const mitm = device.mitm;
  const row = template("mitm-template");
  row.querySelector("span").textContent = `${mitm.enabled ? "Enabled" : "Disabled"} (${mitm.override === null ? "configuration" : "device override"})`;
  const toggle = row.querySelector(".toggle");
  const reset = row.querySelector(".reset");
  const save = (method, body) => run(async () => renderDevice(await request(
    "/api/device/mitm", method, body, { "X-Dae-MITM": mitm.ca_fingerprint })));
  toggle.textContent = mitm.enabled ? "Disable" : "Enable";
  toggle.onclick = () => save("PUT", { enabled: !mitm.enabled });
  reset.disabled = mitm.override === null;
  reset.onclick = () => save("DELETE");
  byId("mitm").append(row);
}

function selectorRow(selector, adminEnabled) {
  const row = template("selector-template");
  row.querySelector("legend").textContent = selector.name;
  row.disabled = !adminEnabled;
  const select = row.querySelector("select");
  for (const node of selector.nodes) {
    const latency = Number.isFinite(node.latency_ms) ? ` · ${Math.round(node.latency_ms)} ms` : "";
    const health = node.checking ? " · checking" : node.healthy ? "" : " · unavailable";
    select.add(new Option(`${node.name}${latency}${health}`, node.id));
  }
  select.value = selector.node_id;
  const apply = row.querySelector(".apply");
  const reset = row.querySelector(".reset");
  select.disabled = apply.disabled = !selector.nodes.length;
  reset.disabled = !selector.overridden;
  const save = (method, body) => run(async () => {
    const token = byId("token").value;
    if (!token) throw new Error("Enter the API token to change a selector.");
    const updated = await request(`/api/selectors/${encodeURIComponent(selector.name)}`,
      method, body, { Authorization: `Bearer ${token}` });
    row.replaceWith(selectorRow(updated, adminEnabled));
  });
  apply.onclick = () => save("PUT", { node_id: select.value });
  reset.onclick = () => save("DELETE");
  return row;
}

function renderSelectors(data) {
  byId("token-field").hidden = !data.admin_enabled;
  byId("admin-disabled").hidden = data.admin_enabled;
  byId("selectors").replaceChildren(...data.selectors.map((selector) => selectorRow(selector, data.admin_enabled)));
  if (!data.selectors.length) byId("selectors").textContent = "No selector policies configured.";
}

async function refresh() {
  byId("identity").textContent = "Loading…";
  byId("sets").replaceChildren();
  byId("selectors").replaceChildren();
  byId("mitm").textContent = "Device controls unavailable.";
  byId("certificate").textContent = "Certificate unavailable.";
  const results = await Promise.allSettled([
    request("/api/device").then(renderDevice).catch((error) => {
      byId("identity").textContent = "Device could not be identified.";
      throw error;
    }),
    request("/api/selectors").then(renderSelectors),
    request("/api/certificate").then((certificate) => {
      byId("certificate").textContent = `${certificate.name} · SHA-256: ${certificate.fingerprint}`;
    }).catch((error) => { if (error.status !== 404) throw error; }),
  ]);
  const errors = results.filter((result) => result.status === "rejected");
  if (errors.length) throw new Error(errors.map((result) => result.reason.message).join("\n"));
}

byId("refresh").onclick = () => run(refresh);
run(refresh);
