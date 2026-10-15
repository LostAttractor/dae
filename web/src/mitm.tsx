import type { DeviceState, DeviceActions, MITMState } from "./types.ts";
import { Button } from "@cloudflare/kumo/components/button";
import { Select } from "@cloudflare/kumo/components/select";
import { useEffect, useState } from "react";
import { type CertificateTrust, certificateTestable, onCertificateTrust } from "./certificate.ts";
import { InlineNotice, StatusBanner } from "./notice.tsx";
import { createView } from "./react-view.ts";

// A device either follows the router configuration or overrides it, so the
// preference is one choice among three; choosing the default clears the override.
export type MITMChoice = "default" | "on" | "off";
export const mitmChoice = (override: boolean | null): MITMChoice => override === null ? "default" : override ? "on" : "off";

export function MITMChoiceRow({ id, value, defaultLabel, onChange }: { id: string; value: MITMChoice; defaultLabel: string; onChange: (next: MITMChoice) => void }) {
  return <div className="mitm-row flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
    <span id={`${id}-label`} className="font-medium">Use for this device</span>
    <Select className="w-56 max-w-full" aria-labelledby={`${id}-label`} value={value} items={{ default: defaultLabel, on: "On", off: "Off" }}
      onValueChange={next => { if (next === "default" || next === "on" || next === "off") onChange(next); }} render={<button type="button" id={id} />} />
  </div>;
}

// Without a trusted CA, interception breaks the device's HTTPS connections. This is a
// banner, not a heading note: it stays until this browser verifies the CA and turns
// red in place when modules are on and verification failed.
function TrustNotice({ enabled, trust, retest }: { enabled: boolean; trust: CertificateTrust; retest: () => void }) {
  if (enabled && trust === "unverified") return <StatusBanner tone="error" title="This browser could not verify the CA certificate"
    description="If it is not installed and trusted, this device's HTTPS connections fail while HTTPS modules are on. Install it under Certificate & browser verification and test again."
    action={<Button type="button" className="retest-certificate" onClick={retest}>Test again</Button>} />;
  if (trust === "trusted") return <InlineNotice tone="success" className="trust-notice mt-1.5 text-sm">This browser trusts the CA certificate.</InlineNotice>;
  if (enabled && trust === "testing") return <p className="trust-notice mt-1.5 text-sm text-kumo-subtle" role="status">Checking that this browser trusts the CA certificate…</p>;
  return <StatusBanner tone="warning" title="Install and trust the CA certificate first"
    description="Otherwise this device's HTTPS connections fail while HTTPS modules are on." />;
}

function MITM({ mitm, trust, actions }: { mitm: MITMState; trust: CertificateTrust; actions: MITMActions }) {
  const routerDefault = mitm.default ? "On" : "Off";
  async function choose(next: MITMChoice) {
    if (next === mitmChoice(mitm.override)) return;
    const saved = await actions.run(async () => actions.update(await actions.request<DeviceState>("/api/device/mitm",
      next === "default" ? "DELETE" : "PUT", next === "default" ? undefined : { enabled: next === "on" }, { "X-Dae-MITM": mitm.ca_fingerprint })),
    next === "default" ? `HTTPS modules follow the router default (${routerDefault}) on this device.` : `HTTPS modules turned ${next} for this device.`);
    if (saved) document.querySelector<HTMLElement>("#mitm-choice")?.focus();
  }
  return <>
    <TrustNotice enabled={mitm.enabled} trust={certificateTestable ? trust : "unknown"} retest={actions.retest} />
    <div className="mt-3"><MITMChoiceRow id="mitm-choice" value={mitmChoice(mitm.override)} defaultLabel={`Router default (${routerDefault})`} onChange={choose} /></div>
  </>;
}

function MITMView({ mitm, actions }: { mitm: MITMState; actions: MITMActions }) {
  const [trust, setTrust] = useState<CertificateTrust>("unknown");
  useEffect(() => onCertificateTrust(setTrust), []);
  return <MITM mitm={mitm} trust={trust} actions={actions} />;
}

interface MITMActions extends DeviceActions { retest: () => void }

export function createMITM(container: HTMLElement, actions: MITMActions) {
  const render = createView(container);
  render(<p className="mt-1.5 text-kumo-subtle">Loading device settings…</p>);
  return {
    show: (mitm: MITMState | null | undefined) => render(mitm ? <MITMView mitm={mitm} actions={actions} />
      : <p className="mt-1.5 text-kumo-subtle">HTTPS modules are not enabled on this router.</p>),
    unavailable: () => render(<StatusBanner tone="warning" title="Device controls unavailable." />),
  };
}
