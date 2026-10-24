import { useEffect, useState } from "react";
import { certificateRequest, errorMessage, request } from "./api.ts";
import { CertificateDownload } from "./certificate-panel.tsx";
import { byId } from "./dom.ts";
import { createView } from "./react-view.ts";
import type { CertificateMetadata } from "./types.ts";

function Setup() {
  const [ca, setCA] = useState<CertificateMetadata>();
  const [busy, setBusy] = useState(true);
  const [feedback, setFeedback] = useState("");
  const [result, setResult] = useState("Not tested");
  useEffect(() => {
    request<CertificateMetadata>("/api/certificate").then(setCA).catch(e => setFeedback(errorMessage(e))).finally(() => setBusy(false));
  }, []);
  async function verify() {
    setBusy(true);
    try { setResult((await certificateRequest()).ca_fingerprint === ca?.fingerprint ? "CA trusted by this browser" : "Verification incomplete"); }
    catch { setResult("Verification incomplete"); }
    finally { setBusy(false); }
  }
  const secure = new URL(location.href);
  if (secure.protocol === "http:") { const port = secure.port || "80"; secure.protocol = "https:"; secure.port = port; }
  return <main className="mx-auto grid max-w-2xl gap-4 p-6">
    <h1 className="text-xl font-semibold">Certificate setup</h1>
    <p>Verify the fingerprint on your router before installing this CA. Open the management page over HTTPS after installation.</p>
    <fieldset id="controls" aria-busy={busy} disabled={busy} className="grid gap-3">
      {ca && <><strong>{ca.name}</strong><code className="break-all">{ca.fingerprint}</code><CertificateDownload />
        <button id="test-certificate" type="button" onClick={verify}>Test certificate</button>
        <span id="certificate-trust-result" role="status">{result}</span></>}
      <p id="certificate-test-info" role="status">{feedback}</p>
    </fieldset>
    {location.protocol === "http:" && <a href={secure.href} className="text-kumo-link">Open HTTPS management page</a>}
    <div id="popup-layer" />
  </main>;
}

document.title = "Network Panel · Certificate setup";
createView(byId("app"))(<Setup />);
