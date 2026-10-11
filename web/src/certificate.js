import { request, challengeRequest } from "./api.js";
import { byId } from "./dom.js";

let identity = "";
let fingerprint = "";
let available = false;
let enabled = false;
let generation = 0;
let serverGeneration = "";
let mitmOrigins = [];

function state(id, text, tone = "neutral") {
  const node = byId(id);
  node.textContent = text;
  node.dataset.tone = tone;
}

function invalidate() {
  generation++;
  state("certificate-trust-result", "Not tested");
  state("certificate-mitm-result", "Not tested");
  byId("certificate-test-info").textContent = "Results apply to this browser only.";
}

export function certificateDevice(device) {
  const next = device ? `${device.source_ip}/${device.mac}` : "";
  const nextEnabled = device?.mitm?.enabled || false;
  if (identity !== next || enabled !== nextEnabled || device?.mitm && device.mitm.ca_fingerprint !== fingerprint) invalidate();
  identity = next;
  enabled = nextEnabled;
  byId("test-certificate").disabled = !identity || !available;
}

export function certificateIdentity(certificate) {
  const next = certificate?.fingerprint || "";
  const nextGeneration = certificate?.test_generation || "";
  if (next !== fingerprint || nextGeneration !== serverGeneration) invalidate();
  serverGeneration = nextGeneration;
  mitmOrigins = certificate?.test_mitm_origins || [];
  fingerprint = next;
  available = Boolean(certificate?.test_available);
  byId("certificate-test-panel").hidden = !available;
  byId("test-certificate").disabled = !identity || !available;
}

export async function testCertificate() {
  const version = ++generation;
  state("certificate-trust-result", "Testing…");
  state("certificate-mitm-result", "Waiting for CA test");
  let test;
  try { test = await request("/api/device/certificate-tests", "POST"); }
  catch (error) {
    state("certificate-trust-result", "Test unavailable", "error");
    state("certificate-mitm-result", "Not tested");
    throw error;
  }
  if (version !== generation) return;
  if (test.ca_fingerprint !== fingerprint) {
    invalidate();
    throw new Error("The CA changed. Refresh the page and test the current certificate.");
  }
  const proof = async (url, stage) => {
    const result = await challengeRequest(url, stage === "mitm" ? mitmOrigins : undefined);
    if (result.id !== test.id || result.ca_fingerprint !== test.ca_fingerprint) throw new Error("Unexpected challenge response");
    return result.stage === stage;
  };
  let trust = false;
  let intercepted = false;
  try { trust = await proof(test.trust_url, "trust"); } catch { /* The browser does not expose the TLS/network failure reason. */ }
  if (version !== generation) return;
  state("certificate-trust-result", trust ? "Accepted by this browser" : "Verification incomplete", trust ? "success" : "error");
  if (trust && test.mitm_enabled) {
    state("certificate-mitm-result", "Testing…");
    try { intercepted = await proof(test.mitm_url, "mitm"); } catch { /* Confirm observations using the same-origin API below. */ }
  }
  if (version !== generation) return;
  let observation;
  try { observation = await request(`/api/device/certificate-tests/${encodeURIComponent(test.id)}`); }
  catch (error) {
    invalidate();
    throw new Error(`Test is no longer current: ${error.message}`);
  }
  if (version !== generation) return;
  trust = trust && observation.trust_observed;
  intercepted = intercepted && observation.mitm_observed;
  state("certificate-trust-result", trust ? "Accepted by this browser" : "Verification incomplete", trust ? "success" : "error");
  state("certificate-mitm-result", !test.mitm_enabled ? "MITM is disabled" : !trust ? "CA test required" : intercepted ? "Transparent MITM verified" : "Verification incomplete", intercepted ? "success" : trust && test.mitm_enabled ? "error" : "neutral");
  let detail = "";
  if (!trust) detail = "\nCheck certificate installation and full trust. Browsers do not distinguish certificate rejection from network or browser-policy failures here.";
  else if (test.mitm_enabled && !intercepted) detail = "\nThe virtual target did not complete a verified MITM challenge. Check that its traffic reaches dae; it has no upstream service.";
  byId("certificate-test-info").textContent = `${new Date().toLocaleString()} · This browser only · SHA-256: ${test.ca_fingerprint}${detail}`;
}
