import { request } from "./api.js";
import { byId, template } from "./dom.js";
import { selectorRow } from "./selectors.js";
import { renderDeviceStatus, renderGlobalStatus, clearGlobalStatus } from "./status.js";
import { certificateDevice, certificateIdentity, testCertificate } from "./certificate.js";

const accessDenied = (error) => error.status === 401 || error.status === 403;
const accessLabels = {
  api_key: { title: "Administrator", description: "Logged in · Remembered for 7 days" },
  lan: { title: "LAN access", description: "Verified LAN device · No API key configured" },
  unix: { title: "Local access", description: "Authorized by local socket permissions" },
};
let authMode = null;
let selectorRequestVersion = 0;
let pollingSelectors = false;
let deviceRequestVersion = 0;
let globalRequestVersion = 0;
let certificateRequestVersion = 0;
let deviceStateKey = "";

function message(text = "", tone = "success") {
  const element = byId("message");
  element.textContent = text;
  element.dataset.tone = tone;
  element.hidden = !text;
}

function updated(label = "Updated") {
  byId("updated").textContent = `${label} ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

// User actions supersede any pending poll, including its errors. Disabling the
// fieldset also preserves each control's individual disabled state.
async function run(action, success = "", pending = "Saving changes…") {
  const controls = byId("controls");
  if (controls.disabled) return false;
  const focused = document.activeElement;
  controls.disabled = true;
  controls.setAttribute("aria-busy", "true");
  selectorRequestVersion++;
  deviceRequestVersion++;
  globalRequestVersion++;
  certificateRequestVersion++;
  message(pending, "pending");
  try {
    await action();
    message(success);
    return true;
  } catch (error) {
    message(error.message, "error");
    return false;
  } finally {
    controls.disabled = false;
    controls.setAttribute("aria-busy", "false");
    if (document.activeElement === document.body && focused.isConnected && !focused.matches(":disabled") && focused.checkVisibility()) {
      focused.focus({ preventScroll: true });
    }
  }
}

function setAccess(mode, error) {
  const authorized = mode !== null;
  const { title, description } = authorized ? accessLabels[mode] : { title: "Guest", description: "" };
  const denied = error?.status === 403;
  authMode = mode;
  byId("login-form").hidden = authorized;
  byId("session-info").hidden = !authorized;
  byId("access-title").textContent = title;
  byId("access-description").textContent = description;
  byId("logout").hidden = mode !== "api_key";
  byId("selectors-locked").hidden = authorized;
  byId("selectors").hidden = !authorized;
  byId("selector-count").hidden = !authorized;
  byId("access-required").textContent = denied ? "Access denied" : "Login required";
  byId("access-required").dataset.tone = denied ? "error" : "neutral";
  byId("login-hint").textContent = denied ? error.message : "Enter your API key above to view selector status and switch nodes.";
  if (!authorized) {
    globalRequestVersion++;
    clearGlobalStatus(denied ? "Access denied." : "Login required to view global status.");
    byId("selectors").replaceChildren();
    byId("selector-count").textContent = denied ? "Access denied" : "Login required";
  }
}

function empty(container, text) {
  const paragraph = document.createElement("p");
  paragraph.className = "muted";
  paragraph.textContent = text;
  byId(container).replaceChildren(paragraph);
}

function renderDevice(device) {
  certificateDevice(device);
  const key = JSON.stringify(device);
  if (key === deviceStateKey) return;
  deviceStateKey = key;
  byId("identity").textContent = `${device.source_ip}\n${device.mac}`;
  const rows = new Map([...byId("sets").children].map((row) => [row.dataset.name, row]));
  const children = [];
  for (const set of device.sets) {
    const label = set.description || set.name;
    const row = rows.get(set.name) || template("set-template");
    row.dataset.name = set.name;
    row.querySelector("strong").textContent = label;
    const button = row.querySelector("button");
    button.textContent = set.joined ? "Leave" : "Join";
    button.setAttribute("aria-label", `${set.joined ? "Leave" : "Join"} ${label}`);
    button.onclick = () => run(async () => renderDevice(await request(
      `/api/device/sets/${encodeURIComponent(set.name)}`, set.joined ? "DELETE" : "PUT")),
    `${set.joined ? "Left" : "Joined"} ${label}.`);
    children.push(row);
  }
  byId("sets").replaceChildren(...children);
  if (!device.sets.length) empty("sets", "No device options available.");
  renderMITM(device.mitm);
}

function renderMITM(mitm) {
  byId("mitm").replaceChildren();
  if (!mitm) {
    empty("mitm", "HTTPS modules are not enabled on this router.");
    return;
  }
  const row = template("mitm-template");
  row.querySelector(".mitm-enabled").textContent = mitm.enabled ? "Enabled" : "Disabled";
  row.querySelector(".settings-source").textContent = mitm.override === null ? "Default" : "Custom";
  const toggle = row.querySelector(".toggle");
  const reset = row.querySelector(".reset");
  const save = async (method, body, success) => {
    const saved = await run(async () => renderDevice(await request(
      "/api/device/mitm", method, body, { "X-Dae-MITM": mitm.ca_fingerprint })), success);
    if (saved) byId("mitm").querySelector(".toggle").focus();
  };
  toggle.textContent = mitm.enabled ? "Disable" : "Enable";
  toggle.onclick = () => save("PUT", { enabled: !mitm.enabled }, `HTTPS modules ${mitm.enabled ? "disabled" : "enabled"} for this device.`);
  reset.disabled = mitm.override === null;
  reset.onclick = () => save("DELETE", undefined, "HTTPS modules reset to default.");
  byId("mitm").append(row);
}

// Mutations run serially. Reads check their version before applying any state,
// so a stale 401 cannot clear access granted by a more recent request.
async function adminRequest(path, method, body) {
  try {
    return await request(path, method, body);
  } catch (error) {
    if (accessDenied(error)) setAccess(null, error);
    throw error;
  }
}

function renderSelectors(data) {
  setAccess(data.auth_mode);
  byId("selector-count").textContent = `${data.selectors.length} group${data.selectors.length === 1 ? "" : "s"}`;
  const rows = [...byId("selectors").querySelectorAll(".selector-row")];
  const sameGroups = data.selectors.length === rows.length && data.selectors.every((selector, i) => rows[i].dataset.group === selector.name);
  if (sameGroups) {
    data.selectors.forEach((selector, i) => rows[i].update(selector));
  } else {
    const actions = { run, request: adminRequest, refresh: loadSelectors };
    byId("selectors").replaceChildren(...data.selectors.map((selector) => selectorRow(selector, actions)));
  }
  if (!data.selectors.length) empty("selectors", "No selector policies configured.");
}

async function loadSelectors({ allowGuest = false, background = false } = {}) {
  const version = ++selectorRequestVersion;
  try {
    const data = await request("/api/selectors");
    if (version !== selectorRequestVersion) return;
    renderSelectors(data);
    updated("Selectors updated");
    return true;
  } catch (error) {
    if (version !== selectorRequestVersion) return;
    if (accessDenied(error)) {
      setAccess(null, error);
      byId("updated").textContent = error.status === 401 ? "Login required" : "Access denied";
      if (background) message(error.message, "error");
      if (allowGuest || background) return;
    } else if (background) {
      byId("updated").textContent = "Live update failed · Retrying";
      return;
    } else {
      byId("selector-count").textContent = "Unavailable";
      byId("selector-count").hidden = true;
      empty("selectors", "Could not load selectors. Try refreshing.");
    }
    throw error;
  }
}

async function loadDevice({ background = false } = {}) {
  const version = ++deviceRequestVersion;
  try {
    const snapshot = await request("/api/device/status");
    if (version !== deviceRequestVersion) return;
    renderDevice(snapshot.device);
    renderDeviceStatus(snapshot);
  } catch (error) {
    if (version !== deviceRequestVersion) return;
    byId("device-status-updated").textContent = "Device update failed · Retrying";
    if (error.status === 403 || !background) {
      deviceStateKey = "";
      certificateDevice(null);
      byId("identity").textContent = "Device could not be identified.";
      empty("sets", error.message);
      empty("device-traffic", error.message);
      byId("device-outbounds").replaceChildren();
      empty("mitm", "Device controls unavailable.");
    }
    if (error.status !== 403 && !background) throw error;
  }
}

async function loadCertificate({ background = false } = {}) {
  const version = ++certificateRequestVersion;
  try {
    const certificate = await request("/api/certificate");
    if (version !== certificateRequestVersion) return;
    certificateIdentity(certificate);
    byId("certificate").textContent = `${certificate.name}\nSHA-256: ${certificate.fingerprint}`;
    byId("certificate-panel").hidden = false;
  } catch (error) {
    if (version !== certificateRequestVersion) return;
    if (error.status === 404) {
      certificateIdentity(null);
      byId("certificate-panel").hidden = true;
    } else if (!background) throw error;
  }
}

async function loadGlobalStatus({ background = false } = {}) {
  const version = ++globalRequestVersion;
  try {
    const snapshot = await request("/api/status");
    if (version !== globalRequestVersion || authMode === null) return;
    renderGlobalStatus(snapshot);
  } catch (error) {
    if (version !== globalRequestVersion) return;
    if (accessDenied(error)) setAccess(null, error);
    else byId("global-status-updated").textContent = "Global update failed · Retrying";
    if (!background) throw error;
  }
}

async function loadAdmin(options = {}) {
  if (await loadSelectors(options)) await loadGlobalStatus(options);
}

async function refresh() {
  const results = await Promise.allSettled([
    loadDevice(),
    loadAdmin({ allowGuest: authMode === null }),
    loadCertificate(),
  ]);
  const errors = results.filter((result) => result.status === "rejected");
  if (errors.length) {
    byId("updated").textContent = "Refresh incomplete";
    throw new Error(errors.map((result) => result.reason.message).join("\n"));
  }
  updated();
}

byId("login-form").onsubmit = async (event) => {
  event.preventDefault();
  const signedIn = await run(async () => {
    await request("/api/session", "PUT", undefined, { Authorization: `Bearer ${byId("api-key").value}` });
    byId("api-key").value = "";
    await loadAdmin();
  }, "Access verified. Global and selector status are now available.", "Logging in…");
  byId(signedIn ? "refresh" : "api-key").focus();
};
byId("logout").onclick = async () => {
  const signedOut = await run(async () => {
    await request("/api/session", "DELETE");
    setAccess(null);
    await loadAdmin({ allowGuest: true });
  }, "Your saved login session has been cleared.", "Logging out…");
  if (signedOut) byId(authMode === null ? "api-key" : "refresh").focus();
};
byId("refresh").onclick = () => run(refresh, "Status refreshed.", "Refreshing status…");
byId("test-certificate").onclick = () => run(testCertificate, "Certificate test completed. See the results below.", "Testing this browser’s certificate and MITM connection…");
setInterval(async () => {
  if (document.hidden || pollingSelectors || byId("controls").disabled) return;
  pollingSelectors = true;
  try {
    await Promise.allSettled([
      loadDevice({ background: true }), loadCertificate({ background: true }),
      ...(authMode === null ? [] : [loadAdmin({ background: true })]),
    ]);
  } finally {
    pollingSelectors = false;
  }
}, 2000);
run(refresh, "", "Loading your network…");
