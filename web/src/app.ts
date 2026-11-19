import type { AuthMode, Page, SettingSection, DeviceState, DeviceStatus, DeviceContext, SelectorsResponse, CertificateMetadata, GlobalStatus } from "./types.ts";
import { request as apiRequest, errorMessage, errorStatus, HTTPError, type HTTPMethod, loginAvailable } from "./api.ts";
import { byId } from "./dom.ts";
import { mountShell } from "./shell.tsx";
import { createNotifications } from "./notifications.tsx";
import { createMITM } from "./mitm.tsx";
import { createSettingNavigation } from "./setting.tsx";
import { createSelectors } from "./selectors.tsx";
import { createStatus } from "./status.tsx";
import { certificateAccessChanged, certificateDevice, certificateIdentity, testCertificate } from "./certificate.ts";
import { createDiagnostics } from "./diagnostics.tsx";
import { createClientSets, createManagedClients } from "./clients.tsx";
import { createNavigation } from "./navigation.tsx";
import { createUpdatedLabel } from "./updated.tsx";

const accessDenied = (error: unknown) => errorStatus(error) === 401 || errorStatus(error) === 403;
const accessLabels = {
  admin_key: { title: "Administrator", description: "Full management access" },
  user_key: { title: "User", description: "Signed in with a user key" },
  lan: { title: "LAN Access", description: "Verified LAN ingress · User access without a key" },
  unix: { title: "Local access", description: "Authorized by local socket permissions" },
};
let authMode: AuthMode | null | undefined;
let selectorRequestVersion = 0;
let pollingSelectors = false;
let deviceRequestVersion = 0;
let globalRequestVersion = 0;
let certificateRequestVersion = 0;
let deviceStateKey = "";

mountShell(byId("app"));
const message = createNotifications(byId("notifications"), byId("notification-layer"));
byId<HTMLButtonElement>("test-certificate").disabled = true;
const diagnostics = createDiagnostics(byId("diagnostic-view"));
const status = createStatus(byId("status-view"));
const mitm = createMITM(byId("mitm"), { run, request, update: renderDevice, retest: () => byId<HTMLButtonElement>("test-certificate").click() });
const updatedLabel = createUpdatedLabel(byId("updated"));
const managedClients = createManagedClients(byId("managed-clients-view"), request);
const selectors = createSelectors(byId("quick-selectors"), byId("selectors"), { run, request: adminRequest, refresh: loadSelectors });

async function request<T = unknown>(path: string, method?: HTTPMethod, body?: unknown, headers?: Record<string, string>): Promise<T> {
  const value = await apiRequest<T>(path, method, body, headers);
  if (method === "PUT" || method === "DELETE") diagnostics.invalidate();
  return value;
}
let activePage: Page = "overview", settingSection: SettingSection = "devices";
function updateVisibility() {
  status.setView(activePage);
  selectors.setView(activePage, settingSection);
}
const settingNavigation = createSettingNavigation(byId("setting-navigation"), section => navigation.show(`setting/${section}`, false));
const navigation = createNavigation((page, section) => {
  activePage = page;
  if (section) settingSection = section;
  settingNavigation.show(settingSection);
  updateVisibility();
});
const clientSets = createClientSets(byId("sets"), { run, request, update: renderDevice, onCompare: (set) => {
  navigation.show("setting/explain");
  diagnostics.compare(set);
} });

function updated() {
  updatedLabel.refresh();
}

// User actions supersede any pending poll, including its errors. Disabling the
// fieldset also preserves each control's individual disabled state.
async function run(action: () => Promise<unknown>, success = "", pending = "Saving changes…") {
  const controls = byId<HTMLFieldSetElement>("controls");
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
    message(errorMessage(error), "error");
    return false;
  } finally {
    controls.disabled = false;
    controls.setAttribute("aria-busy", "false");
    if (document.activeElement === document.body && focused instanceof HTMLElement && focused.isConnected && !focused.matches(":disabled") && focused.checkVisibility()) {
      focused.focus({ preventScroll: true });
    }
  }
}

function setAccess(mode: AuthMode | null, error?: unknown) {
  const authorized = mode !== null;
  const admin = mode === "admin_key" || mode === "unix";
  const signedIn = mode === "user_key" || mode === "admin_key";
  const { title, description } = authorized ? accessLabels[mode] : { title: "Guest", description: loginAvailable ? "Log in with your API key to manage the network." : "HTTPS is required to log in. HTTP supports anonymous setup only." };
  const denied = errorStatus(error) === 403;
  if (authMode !== mode) certificateAccessChanged();
  authMode = mode;
  diagnostics.setAccess(admin);
  clientSets.setAccess(admin);
  settingNavigation.setAccess(admin);
  managedClients.setAccess(admin);
  byId("managed-clients-view").hidden = !admin;
  byId("devices-locked").hidden = admin;
  byId("devices-login-hint").textContent = denied ? errorMessage(error) : mode === "user_key" ? "Log out and use an administrator key to manage other devices." : loginAvailable ? "Log in with an administrator key to manage other devices." : "Open this page over HTTPS to log in and manage other devices.";
  byId("login-form").hidden = !loginAvailable || signedIn || mode === "unix";
  if (authorized) status.allowGlobal();
  byId("access-title").textContent = title;
  byId("access-description").textContent = denied ? errorMessage(error) : description;
  byId("access-description").hidden = signedIn;
  const logout = byId("logout");
  logout.textContent = signedIn ? "Log out" : "Clear session";
  logout.hidden = !signedIn && !(loginAvailable && error instanceof HTTPError && error.invalidSession);
  for (const prefix of ["", "quick-"]) {
    byId(`${prefix}selectors-locked`).hidden = authorized;
    byId(`${prefix}selectors`).hidden = !authorized;
    byId(`${prefix}selector-count`).hidden = !authorized;
    byId(`${prefix}access-required`).textContent = denied ? "Access denied" : "Login required";
    byId(`${prefix}access-required`).dataset.tone = denied ? "error" : "neutral";
    byId(`${prefix}login-hint`).textContent = denied ? errorMessage(error) : loginAvailable ? "Enter your API key above to view outbound groups and switch nodes." : "Open this page over HTTPS to log in and view outbound groups.";
  }
  if (!authorized) {
    globalRequestVersion++;
    status.clearGlobal(denied ? "Access denied." : "Login required to view all devices.");
    byId("daemon-version").textContent = "";
    byId("daemon-version").hidden = true;
    selectors.clear();
    for (const prefix of ["", "quick-"]) byId(`${prefix}selector-count`).textContent = denied ? "Access denied" : "Login required";
  }
}

function setDeviceIdentity(ip: string, mac: string, reason = "") {
  byId("identity").textContent = ip || "Unavailable";
  byId("device-mac").textContent = mac || "Unavailable";
  byId("device-identity").title = reason;
}

function renderDevice(device: DeviceState) {
  certificateDevice(device);
  const key = JSON.stringify(device);
  if (key === deviceStateKey) return;
  deviceStateKey = key;
  diagnostics.setDevice(JSON.stringify([device.mac, device.source_ip, device.sets, device.mitm]));
  setDeviceIdentity(device.source_ip, device.mac);
  clientSets.show(device);
  mitm.show(device.mitm);
}

function clearDevice(reason: string) {
  deviceRequestVersion++;
  deviceStateKey = "";
  status.deviceError(reason, true);
  diagnostics.setDevice("");
  certificateDevice(null);
  setDeviceIdentity("", "", reason);
  clientSets.unavailable(reason);
  mitm.unavailable();
}

// Mutations run serially. Reads check their version before applying any state,
// so a stale 401 cannot clear access granted by a more recent request.
async function adminRequest<T = unknown>(path: string, method?: HTTPMethod, body?: unknown, headers?: Record<string, string>): Promise<T> {
  try {
    return await request<T>(path, method, body, headers);
  } catch (error) {
    if (accessDenied(error)) setAccess(null, error);
    throw error;
  }
}

function renderSelectors(data: SelectorsResponse) {
  setAccess(data.auth_mode);
  for (const prefix of ["", "quick-"]) byId(`${prefix}selector-count`).textContent = `${data.selectors.length} group${data.selectors.length === 1 ? "" : "s"}`;
  selectors.show(data.selectors, data.admin_enabled);
}

async function loadSelectors({ allowGuest = false, background = false } = {}) {
  const version = ++selectorRequestVersion;
  try {
    const data = await request<SelectorsResponse>("/api/selectors");
    if (version !== selectorRequestVersion) return;
    renderSelectors(data);
    updated();
    return true;
  } catch (error) {
    if (version !== selectorRequestVersion) return;
    if (accessDenied(error)) {
      setAccess(null, error);
      updatedLabel.message(errorStatus(error) === 401 ? "Login required" : "Access denied");
      if (background && !allowGuest) message(errorMessage(error), "error");
      if (allowGuest || background) return;
    } else if (background) {
      updatedLabel.message("Live update failed · Retrying");
      return;
    } else {
      for (const prefix of ["", "quick-"]) {
        byId(`${prefix}selector-count`).textContent = "Unavailable";
        byId(`${prefix}selector-count`).hidden = true;
      }
      selectors.error("Could not load selectors. Try refreshing.");
    }
    throw error;
  }
}

async function loadDevice({ background = false } = {}) {
  const version = ++deviceRequestVersion;
  try {
    const connection = await request<DeviceContext>("/api/device/context");
    if (version !== deviceRequestVersion) return;
    diagnostics.setGeneration(connection.generation);
    clientSets.setGeneration(connection.generation);
    if (!connection.device) {
      const reason = "This connection has no Ethernet MAC. Device traffic, client sets and HTTPS module preferences are unavailable.";
      status.deviceUnavailable(reason);
      const key = JSON.stringify(connection.context);
      if (deviceStateKey !== key) {
        deviceStateKey = key;
        diagnostics.setDevice(key);
        certificateDevice(null);
        const ip = connection.context.source_ip;
        setDeviceIdentity(ip || "", ip ? "Unavailable (IP-only connection)" : "");
        clientSets.unavailable(reason, "warning");
        mitm.unavailable();
      }
      return;
    }
    const snapshot = await request<DeviceStatus>("/api/device/status");
    if (version !== deviceRequestVersion) return;
    renderDevice(snapshot.device);
    status.setDevice(snapshot);
  } catch (error) {
    if (version !== deviceRequestVersion) return;
    if (accessDenied(error) || !background) clearDevice(errorMessage(error));
    else status.deviceError(errorMessage(error), false);
    if (!accessDenied(error) && !background) throw error;
  }
}

async function loadCertificate({ background = false } = {}) {
  const version = ++certificateRequestVersion;
  try {
    const certificate = await request<CertificateMetadata>("/api/certificate");
    if (version !== certificateRequestVersion) return;
    certificateIdentity(certificate);
    byId("certificate-name").textContent = certificate.name;
    byId("certificate-fingerprint").textContent = certificate.fingerprint;
    byId("certificate-panel").hidden = false;
  } catch (error) {
    if (version !== certificateRequestVersion) return;
    if (accessDenied(error) || errorStatus(error) === 404) {
      certificateIdentity(null);
      byId("certificate-name").textContent = "";
      byId("certificate-fingerprint").textContent = "";
      byId("certificate-panel").hidden = true;
    } else if (!background) throw error;
  }
}

async function loadGlobalStatus({ background = false } = {}) {
  const version = ++globalRequestVersion;
  try {
    const snapshot = await request<GlobalStatus>("/api/status");
    if (version !== globalRequestVersion || authMode == null) return;
    if (snapshot.schema !== 17) throw new Error("Unsupported daemon status schema. Use matching Web and daemon versions.");
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
    loadAdmin({ allowGuest: authMode == null }).then(() => managedClients.refresh()),
    loadCertificate(),
  ]);
  const errors = results.filter((result) => result.status === "rejected");
  if (errors.length) {
    updatedLabel.message("Refresh incomplete");
    throw new Error(errors.map((result) => errorMessage(result.reason)).join("\n"));
  }
  updated();
}

byId<HTMLFormElement>("login-form").onsubmit = async (event) => {
  event.preventDefault();
  if (!loginAvailable) return;
  const signedIn = await run(async () => {
    const key = byId<HTMLInputElement>("api-key").value;
    byId<HTMLInputElement>("api-key").value = "";
    certificateAccessChanged();
    await request("/api/session", "PUT", undefined, { Authorization: `Bearer ${key}` });
    await loadAdmin();
    await Promise.all([loadDevice(), loadCertificate()]);
  }, "Access verified. Outbound groups and traffic for all devices are now available.", "Logging in…");
  byId(signedIn ? "refresh" : "api-key").focus();
};
byId("logout").onclick = async () => {
  const signedOut = await run(async () => {
    certificateAccessChanged();
    await request("/api/session", "DELETE");
    setAccess(null);
    clearDevice("Login required to view this device.");
    certificateIdentity(null);
    byId("certificate-panel").hidden = true;
    await Promise.all([loadAdmin({ allowGuest: true }), loadDevice(), loadCertificate()]);
  }, "Browser login session cleared.", "Logging out…");
  if (signedOut) byId(authMode === null ? "api-key" : "refresh").focus();
};
byId("refresh").onclick = () => run(refresh, "Network state refreshed.", "Refreshing network state…");
byId<HTMLButtonElement>("test-certificate").onclick = async () => {
  let result: Awaited<ReturnType<typeof testCertificate>>;
  await run(async () => { result = await testCertificate(); }, "", "Testing this browser’s certificate and MITM connection…");
  if (result) message(result.text, result.tone);
};
setInterval(async () => {
  if (document.hidden || pollingSelectors || byId<HTMLFieldSetElement>("controls").disabled) return;
  pollingSelectors = true;
  try {
    await Promise.allSettled([
      loadDevice({ background: true }), loadCertificate({ background: true }),
      loadAdmin({ background: true, allowGuest: authMode === null }),
    ]);
  } finally {
    pollingSelectors = false;
  }
}, 2000);
// Initial loading is already shown by the page's placeholders and busy state.
// A fast cached startup can finish before a transient toast's first paint.
run(refresh, "", "");
