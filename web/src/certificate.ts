import type { DeviceState, CertificateMetadata, MITMTest } from "./types.ts";
import { request, certificateRequest, challengeRequest, errorMessage } from "./api.ts";
import { byId } from "./dom.ts";

let identity = "";
let fingerprint = "";
let enabled = false;
let caVersion = 0;
let mitmVersion = 0;
let serverGeneration = "";
let mitmOrigins: string[] = [];

interface TestFeedback { text: string; tone: "success" | "warning" }

// Whether this browser accepted the current CA in its latest test. A failure may
// also come from the network or browser policy, so it is "unverified", not "untrusted".
export type CertificateTrust = "unknown" | "testing" | "trusted" | "unverified";
let trust: CertificateTrust = "unknown";
const trustListeners = new Set<(trust: CertificateTrust) => void>();
function setTrust(next: CertificateTrust) {
  if (trust === next) return;
  trust = next;
  for (const listener of trustListeners) listener(next);
}
export function onCertificateTrust(listener: (trust: CertificateTrust) => void) {
  trustListeners.add(listener);
  listener(trust);
  return () => { trustListeners.delete(listener); };
}
// Only a direct connection to dae can run the test, which the development server is not.
export const certificateTestable = !import.meta.env.DEV;

function state(id: string, text: string, tone: "neutral" | "pending" | "success" | "warning" | "error" = "neutral") {
  const node = byId(id);
  node.textContent = text;
  node.dataset.tone = tone;
}

function invalidateMITM() {
  mitmVersion++;
  state("certificate-mitm-result", "Not tested");
}

function invalidateCA() {
  caVersion++;
  setTrust("unknown");
  state("certificate-trust-result", "Not tested");
  invalidateMITM();
  byId("certificate-test-info").textContent = "Results apply to this browser only.";
  byId("certificate-http-setup").hidden = true;
}

export function certificateDevice(device: DeviceState | null) {
  const next = device ? `${device.source_ip}/${device.mac}` : "";
  const nextEnabled = device?.mitm?.enabled || false;
  if (identity !== next || enabled !== nextEnabled) invalidateMITM();
  identity = next;
  enabled = nextEnabled;
  autoTest();
}

// While HTTPS modules are on, an untrusted CA breaks this device's HTTPS
// connections. Test once when the page finds them on, and again whenever they are
// turned on or the device or CA changes. Results stay on the page without a toast.
let autoTested = "";
function autoTest() {
  if (!enabled || !identity || !fingerprint) {
    if (!enabled) autoTested = "";
    return;
  }
  const key = `${identity}/${fingerprint}`;
  if (!certificateTestable || autoTested === key) return;
  autoTested = key;
  testCertificate().catch(() => { /* The results panel reports the failure. */ });
}

export function certificateIdentity(certificate: CertificateMetadata | null) {
  const next = certificate?.fingerprint || "";
  const nextGeneration = certificate?.mitm_test_generation || "";
  if (next !== fingerprint) invalidateCA();
  else if (nextGeneration !== serverGeneration) invalidateMITM();
  serverGeneration = nextGeneration;
  mitmOrigins = certificate?.mitm_test_origins || [];
  fingerprint = next;
  byId("certificate-test-panel").hidden = !fingerprint;
  byId<HTMLButtonElement>("test-certificate").disabled = !fingerprint;
  autoTest();
}

export async function testCertificate(): Promise<TestFeedback | undefined> {
  const caAttempt = ++caVersion, mitmAttempt = ++mitmVersion;
  const currentMITM = () => caAttempt === caVersion && mitmAttempt === mitmVersion;
  setTrust("testing");
  state("certificate-trust-result", "Testing…", "pending");
  state("certificate-mitm-result", "Waiting for CA trust test");
  byId("certificate-http-setup").hidden = true;
  let accepted = false;
  try {
    const certificate = await certificateRequest();
    accepted = certificate.ca_fingerprint === fingerprint;
  } catch { /* Browsers do not expose the TLS/network failure reason. */ }
  if (caAttempt !== caVersion) return;
  setTrust(accepted ? "trusted" : "unverified");
  state("certificate-trust-result", accepted ? "CA trusted by this browser" : "Verification incomplete", accepted ? "success" : "warning");
  byId("certificate-test-info").textContent = `Tested ${new Date().toLocaleString()} in this browser only; other applications and the system trust store are not checked.`;
  if (!currentMITM()) return;
  if (!accepted) {
    state("certificate-mitm-result", "CA trust test required", "warning");
    byId("certificate-test-info").textContent += "\nCheck certificate installation and full trust, network connectivity and browser policy.";
    if (location.protocol === "https:") {
      const setup = new URL(location.href), port = location.port || "443";
      setup.protocol = "http:";
      setup.port = port;
      const link = byId<HTMLAnchorElement>("certificate-http-setup");
      link.href = setup.href;
      link.hidden = false;
    }
    return { tone: "warning", text: "CA trust could not be verified. See the results below." };
  }
  if (!serverGeneration || !identity || !enabled) {
    const reason = !serverGeneration ? "MITM is unavailable" : !identity ? "Device identity unavailable" : "MITM is disabled";
    state("certificate-mitm-result", reason);
    return { tone: "success", text: `CA trust verified. ${reason}.` };
  }
  state("certificate-mitm-result", "Testing…", "pending");
  let test: MITMTest;
  try { test = await request<MITMTest>("/api/device/mitm-tests", "POST"); }
  catch (error) {
    if (!currentMITM()) return;
    state("certificate-mitm-result", "Test unavailable", "error");
    throw error;
  }
  if (!currentMITM()) return;
  if (test.ca_fingerprint !== fingerprint) {
    invalidateCA();
    throw new Error("The CA changed. Refresh the page and test the current certificate.");
  }
  if (!test.mitm_enabled) {
    state("certificate-mitm-result", "MITM is disabled");
    return { tone: "success", text: "CA trust verified. MITM is disabled." };
  }
  let intercepted = false;
  try {
    const proof = await challengeRequest(test.mitm_url, mitmOrigins);
    intercepted = proof.id === test.id && proof.ca_fingerprint === test.ca_fingerprint;
  } catch { /* Confirm observations using the same-origin API below. */ }
  if (!currentMITM()) return;
  let observation: MITMTest;
  try { observation = await request<MITMTest>(`/api/device/mitm-tests/${encodeURIComponent(test.id)}`); }
  catch (error) {
    if (!currentMITM()) return;
    invalidateMITM();
    throw new Error(`MITM test is no longer current: ${errorMessage(error)}`);
  }
  if (!currentMITM()) return;
  intercepted = intercepted && observation.mitm_observed;
  state("certificate-mitm-result", intercepted ? "Transparent MITM verified" : "Verification incomplete", intercepted ? "success" : "warning");
  if (!intercepted) {
    byId("certificate-test-info").textContent += "\nThe virtual target did not complete a verified MITM challenge. Check that its traffic reaches dae; it has no upstream service.";
    return { tone: "warning", text: "CA trust verified, but interception could not be verified. See the results below." };
  }
  return { tone: "success", text: "CA trust and interception verified." };
}
