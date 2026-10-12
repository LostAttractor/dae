import type { DeviceState, DeviceActions, MITMState } from "./types.ts";
import { Button } from "@astryxdesign/core/Button";
import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { createView } from "./react-view.ts";

function MITM({ mitm, actions }: { mitm: MITMState | null | undefined; actions: DeviceActions }) {
  if (!mitm) return <p className="muted">HTTPS modules are not enabled on this router.</p>;
  const fingerprint = mitm.ca_fingerprint;
  async function save(method: "PUT" | "DELETE", body: { enabled: boolean } | undefined, success: string) {
    const saved = await actions.run(async () => actions.update(await actions.request<DeviceState>(
      "/api/device/mitm", method, body, { "X-Dae-MITM": fingerprint })), success);
    if (saved) document.querySelector<HTMLButtonElement>("#mitm .toggle")?.focus();
  }
  return <div className="button-row">
    <Button className="toggle" label={mitm.enabled ? "Disable" : "Enable"}
      onClick={() => save("PUT", { enabled: !mitm.enabled }, `HTTPS modules ${mitm.enabled ? "disabled" : "enabled"} for this device.`)} />
    <Button className="reset" label="Use default" isDisabled={mitm.override === null}
      onClick={() => save("DELETE", undefined, "HTTPS modules reset to default.")} />
  </div>;
}

export function createMITM(container: HTMLElement, summaryContainer: HTMLElement, actions: DeviceActions) {
  const render = createView(container), renderSummary = createView(summaryContainer);
  render(<p className="muted">Loading device settings…</p>);
  return {
    show: (mitm: MITMState | null | undefined) => {
      renderSummary(mitm ? <Badge label={`${mitm.enabled ? "Enabled" : "Disabled"} (${mitm.override === null ? "Default" : "Custom"})`} /> : null);
      render(<MITM mitm={mitm} actions={actions} />);
    },
    unavailable: () => {
      renderSummary(null);
      render(<Banner status="warning" title="Device controls unavailable." />);
    },
  };
}
