import { request } from "./api.js";
import { byId, template } from "./dom.js";
import { selectorRow } from "./selectors.js";

const accessDenied = (error) => error.status === 401 || error.status === 403;
const accessLabels = {
  api_key: { title: "Administrator", description: "Signed in · Remembered for 7 days" },
  lan: { title: "LAN access", description: "Verified LAN device · No API key configured" },
  unix: { title: "Local access", description: "Authorized by local socket permissions" },
};
let authMode = null;
let selectorRequestVersion = 0;
let pollingSelectors = false;

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
  byId("access-required").textContent = denied ? "Access denied" : "Login required";
  byId("login-hint").textContent = error?.message ?? "Enter your API key above to view selector status and switch nodes.";
  if (!authorized) {
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
    button.classList.toggle("primary", !set.joined);
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
  const badge = row.querySelector(".badge");
  badge.textContent = mitm.enabled ? "Enabled" : "Disabled";
  badge.classList.toggle("active", mitm.enabled);
  row.querySelector("small").textContent = mitm.override === null ? "Default" : "Device override";
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
  reset.onclick = () => save("DELETE", undefined, "HTTPS modules reset to defaults.");
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
      empty("selectors", "Could not load selectors. Try refreshing.");
    }
    throw error;
  }
}

async function loadDevice() {
  byId("identity").textContent = "Identifying your device…";
  byId("sets").replaceChildren();
  empty("mitm", "Device controls unavailable.");
  try {
    renderDevice(await request("/api/device"));
  } catch (error) {
    byId("identity").textContent = "Device could not be identified.";
    empty("sets", error.message);
    if (error.status !== 403) throw error;
  }
}

async function loadCertificate() {
  byId("certificate-panel").hidden = true;
  try {
    const certificate = await request("/api/certificate");
    byId("certificate").textContent = `${certificate.name}\nSHA-256: ${certificate.fingerprint}`;
    byId("certificate-panel").hidden = false;
  } catch (error) {
    if (error.status !== 404) throw error;
  }
}

async function refresh() {
  const results = await Promise.allSettled([
    loadDevice(),
    loadSelectors({ allowGuest: authMode === null }),
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
    await loadSelectors();
  }, "Access verified. Selector status is now available.", "Logging in…");
  byId(signedIn ? "refresh" : "api-key").focus();
};
byId("logout").onclick = async () => {
  const signedOut = await run(async () => {
    await request("/api/session", "DELETE");
    setAccess(null);
    await loadSelectors({ allowGuest: true });
  }, "Your saved login session has been cleared.", "Logging out…");
  if (signedOut) byId(authMode === null ? "api-key" : "refresh").focus();
};
byId("refresh").onclick = () => run(refresh, "Status refreshed.", "Refreshing status…");
setInterval(async () => {
  if (authMode === null || document.hidden || pollingSelectors || byId("controls").disabled) return;
  pollingSelectors = true;
  try {
    await loadSelectors({ background: true });
  } finally {
    pollingSelectors = false;
  }
}, 2000);
run(refresh, "", "Loading your network…");
