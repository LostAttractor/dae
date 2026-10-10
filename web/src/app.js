import { request } from "./api.js";
import { byId, template } from "./dom.js";
import { createSelectors } from "./selectors.jsx";
import { createStatus } from "./status.jsx";
import { certificateDevice, certificateIdentity, testCertificate } from "./certificate.js";
import { createDiagnostics } from "./diagnostics.jsx";
import { createClientSets, createManagedClients } from "./clients.jsx";
import { createNavigation } from "./navigation.js";
import { createUpdatedLabel } from "./updated.jsx";

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

const diagnostics = createDiagnostics(byId("diagnostic-view"));
const status = createStatus(byId("status-view"));
const updatedLabel = createUpdatedLabel(byId("updated"));
const managedClients = createManagedClients(byId("managed-clients-view"), request);
const selectors = createSelectors(byId("selectors"), { run, request: adminRequest, refresh: loadSelectors });
const navigation = createNavigation((page) => {
  status.setVisible(page === "settings");
  managedClients.setActive(page === "devices");
});
const clientSets = createClientSets(byId("sets"), { run, request, update: renderDevice, onCompare: (set) => {
  navigation.show("testing");
  diagnostics.compare(set);
} });

function message(text = "", tone = "success") {
  const element = byId("message");
  element.textContent = text;
  element.dataset.tone = tone;
  element.hidden = !text;
}

function updated() {
  updatedLabel.refresh();
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
  diagnostics.setAccess(authorized);
  managedClients.setAccess(authorized);
  byId("managed-clients-view").hidden = !authorized;
  byId("devices-locked").hidden = authorized;
  byId("devices-login-hint").textContent = denied ? error.message : "Log in above to manage other devices.";
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
  byId("login-hint").textContent = denied ? error.message : "Enter your API key above to view outbound groups and switch nodes.";
  if (!authorized) {
    globalRequestVersion++;
    status.clearGlobal(denied ? "Access denied." : "Login required to view all devices.");
    byId("daemon-version").textContent = "";
    byId("daemon-version").hidden = true;
    selectors.clear();
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
  diagnostics.setDevice(JSON.stringify([device.mac, device.source_ip, device.sets]));
  byId("identity").textContent = device.source_ip;
  byId("device-mac").textContent = `MAC ${device.mac}`;
  clientSets.show(device);
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
async function adminRequest(path, method, body, headers) {
  try {
    return await request(path, method, body, headers);
  } catch (error) {
    if (accessDenied(error)) setAccess(null, error);
    throw error;
  }
}

function renderSelectors(data) {
  setAccess(data.auth_mode);
  byId("selector-count").textContent = `${data.selectors.length} group${data.selectors.length === 1 ? "" : "s"}`;
  selectors.show(data.selectors);
}

async function loadSelectors({ allowGuest = false, background = false } = {}) {
  const version = ++selectorRequestVersion;
  try {
    const data = await request("/api/selectors");
    if (version !== selectorRequestVersion) return;
    renderSelectors(data);
    updated();
    return true;
  } catch (error) {
    if (version !== selectorRequestVersion) return;
    if (accessDenied(error)) {
      setAccess(null, error);
      updatedLabel.message(error.status === 401 ? "Login required" : "Access denied");
      if (background) message(error.message, "error");
      if (allowGuest || background) return;
    } else if (background) {
      updatedLabel.message("Live update failed · Retrying");
      return;
    } else {
      byId("selector-count").textContent = "Unavailable";
      byId("selector-count").hidden = true;
      selectors.error("Could not load selectors. Try refreshing.");
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
    status.setDevice(snapshot);
  } catch (error) {
    if (version !== deviceRequestVersion) return;
    status.deviceError(error.message, error.status === 403 || !background);
    if (error.status === 403 || !background) {
      deviceStateKey = "";
      diagnostics.setDevice("");
      certificateDevice(null);
      byId("identity").textContent = "Device could not be identified.";
      byId("device-mac").textContent = "";
      clientSets.error(error.message);
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
    status.setGlobal(snapshot);
    byId("daemon-version").textContent = `dae · ${snapshot.version}`;
    byId("daemon-version").hidden = !snapshot.version;
  } catch (error) {
    if (version !== globalRequestVersion) return;
    if (accessDenied(error)) setAccess(null, error);
    else status.globalError();
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
    updatedLabel.message("Refresh incomplete");
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
  }, "Access verified. Outbound groups and traffic for all devices are now available.", "Logging in…");
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
byId("refresh").onclick = () => run(refresh, "Network state refreshed.", "Refreshing network state…");
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
