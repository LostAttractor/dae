import { Button } from "@astryxdesign/core/Button";
import { Badge } from "@astryxdesign/core/Badge";
import { createView } from "./react-view.js";

function MITM({ mitm, actions }) {
  if (!mitm) return <p className="muted">HTTPS modules are not enabled on this router.</p>;
  async function save(method, body, success) {
    const saved = await actions.run(async () => actions.update(await actions.request(
      "/api/device/mitm", method, body, { "X-Dae-MITM": mitm.ca_fingerprint })), success);
    if (saved) document.querySelector("#mitm .toggle")?.focus();
  }
  return <>
    <div className="mitm-summary status-row">
      <Badge className="mitm-enabled" label={mitm.enabled ? "Enabled" : "Disabled"} />
      <Badge className="settings-source" label={mitm.override === null ? "Default" : "Custom"} />
    </div>
    <div className="button-row">
      <Button className="toggle" label={mitm.enabled ? "Disable" : "Enable"}
        onClick={() => save("PUT", { enabled: !mitm.enabled }, `HTTPS modules ${mitm.enabled ? "disabled" : "enabled"} for this device.`)} />
      <Button className="reset" label="Use default" isDisabled={mitm.override === null}
        onClick={() => save("DELETE", undefined, "HTTPS modules reset to default.")} />
    </div>
  </>;
}

export function createMITM(container, actions) {
  const render = createView(container);
  render(<p className="muted">Loading device settings…</p>);
  return {
    show: (mitm) => render(<MITM mitm={mitm} actions={actions} />),
    unavailable: () => render(<p className="muted">Device controls unavailable.</p>),
  };
}
