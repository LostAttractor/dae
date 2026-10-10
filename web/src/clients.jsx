import { useEffect, useLayoutEffect, useState } from "react";
import { createView } from "./react-view.js";
import { useRequest } from "./use-request.js";
import { TraceSteps } from "./trace.jsx";

function ClientImpact({ set, contextKey, request, onCompare }) {
  const [retry, setRetry] = useState(0);
  const result = useRequest();
  useEffect(() => {
    const operation = result.start();
    request(`/api/device/sets/${encodeURIComponent(set.name)}/impact`, "POST", { joined: !set.joined, context: {} })
      .then(operation.resolve, operation.reject);
    return operation.cancel;
  }, [retry, contextKey, set.name, set.joined, request, result.start]);
  const impact = result.value;
  return <div className="impact-content" aria-busy={result.pending}>
    {result.pending && <p>Loading routing effects…</p>}
    {result.error && <><p className="notice">{result.error}</p><button type="button" onClick={() => setRetry(value => value + 1)}>Retry</button></>}
    {impact && <>
      <p>Change: {impact.joined_before ? "On" : "Off"} → {impact.joined_after ? "On" : "Off"}.</p>
      <p className="muted">{impact.connection_behavior === "retain" ? "Existing connections keep their current route." : `Existing connections: ${impact.connection_behavior}.`}</p>
      <TraceSteps steps={impact.rules} />
      {!impact.rules.length && <p className="muted">No active dae routing references.</p>}
      {impact.exports.map((exported, index) => <p key={index} className="muted">{exported} · external firewall rules are not evaluated.</p>)}
      <p className="muted">Other predicates and earlier rules still determine the final route.</p>
      <button type="button" onClick={() => onCompare(set)}>Compare a target</button>
    </>}
  </div>;
}

function ClientSets({ device, actions }) {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState("");
  const contextKey = JSON.stringify([device.mac, device.source_ip, device.sets]);
  const selectedSet = device.sets.find(set => set.name === selected) || device.sets[0];
  if (!device.sets.length) return <p className="muted">No routing options available for this device.</p>;
  return <>
    <div className="client-options">{device.sets.map(set => {
      const label = set.description || set.name;
      return <div key={set.name} className="set-row" data-name={set.name}>
        <strong>{label}</strong>
        <button type="button" className="client-toggle" role="switch" aria-checked={set.joined} aria-label={label} onClick={() => actions.run(async () => {
          actions.update(await actions.request(`/api/device/sets/${encodeURIComponent(set.name)}`, set.joined ? "DELETE" : "PUT"));
        }, `${label} turned ${set.joined ? "off" : "on"} for this device.`)}>
          <span className="switch-track" aria-hidden="true" /><span aria-hidden="true">{set.joined ? "On" : "Off"}</span>
        </button>
      </div>;
    })}</div>
    <details className="client-impact" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>Preview Routing Changes</summary>
      {open && <>
        <label className="impact-option">Option to preview
          <select value={selectedSet.name} onChange={(event) => setSelected(event.target.value)}>
            {device.sets.map(set => <option key={set.name} value={set.name}>{set.description || set.name}</option>)}
          </select>
        </label>
        <ClientImpact key={`${contextKey}/${selectedSet.name}`} set={selectedSet} contextKey={contextKey} request={actions.request} onCompare={actions.onCompare} />
      </>}
    </details>
  </>;
}

export function createClientSets(container, actions) {
  const render = createView(container);
  return {
    show: (device) => render(<ClientSets key={`${device.mac}/${device.source_ip}`} device={device} actions={actions} />),
    error: (text) => render(<p className="muted">{text}</p>),
  };
}

function ManagedClients({ allowed, active, request }) {
  const groups = useRequest(), action = useRequest();
  useLayoutEffect(() => {
    if (!allowed) { groups.reset(); action.reset(); }
  }, [allowed, groups.reset, action.reset]);
  useEffect(() => {
    if (!active || !allowed) return;
    const operation = groups.start();
    request("/api/clients").then(operation.resolve, operation.reject);
    return operation.cancel;
  }, [active, allowed, request, groups.start]);

  async function submit(event) {
    event.preventDefault();
    if (!allowed || action.pending) return;
    const form = new FormData(event.currentTarget);
    const kind = event.nativeEvent.submitter?.value || "show";
    const mac = form.get("mac").trim(), name = form.get("group");
    const operation = action.start();
    try {
      const base = `/api/devices/${encodeURIComponent(mac)}`;
      if (kind === "join" || kind === "leave") {
        if (!name) throw new Error("Choose a client group.");
        await request(`/api/clients/${encodeURIComponent(name)}/members/${encodeURIComponent(mac)}`, kind === "join" ? "PUT" : "DELETE");
      } else if (kind.startsWith("mitm-")) {
        const certificate = await request("/api/certificate");
        if (!operation.current()) return;
        await request(`${base}/mitm`, kind === "mitm-reset" ? "DELETE" : "PUT", kind === "mitm-reset" ? undefined : { enabled: kind === "mitm-enable" }, { "X-Dae-MITM": certificate.fingerprint });
      }
      if (operation.current()) operation.resolve(await request(base));
    } catch (error) { operation.reject(error); }
  }

  const device = action.value;
  return <section id="managed-clients" className="card managed-clients-card" hidden={!allowed} aria-labelledby="managed-clients-title">
    <h2 id="managed-clients-title">Device Settings</h2>
    <p className="section-description">Manage routing groups and HTTPS modules for another device using its MAC address.</p>
    <form id="managed-client-form" onSubmit={submit} onInput={event => { if (event.target.name === "mac") action.reset(); }}>
      <fieldset className="managed-client-controls" disabled={!allowed || action.pending}>
        <fieldset className="managed-section">
          <legend>Device</legend>
          <p>Enter the device's MAC address. All actions below apply to this device.</p>
          <div className="managed-device-lookup">
            <div className="managed-client-fields"><label>MAC address<input id="managed-client-mac" name="mac" placeholder="02:00:00:00:00:10" autoCapitalize="none" spellCheck={false} required /></label></div>
            <button type="submit" value="show">Show settings</button>
          </div>
        </fieldset>
        <fieldset className="managed-section">
          <legend>Routing group</legend>
          <p>Membership affects routing rules that refer to this group.</p>
          <div className="managed-client-fields"><label>Group<select id="managed-client-group" name="group" disabled={groups.pending}>
              {(groups.value?.groups || []).map(group => <option key={group.name} value={group.name}>{group.description || group.name} ({group.members.length} members)</option>)}
          </select></label></div>
          <div className="button-row"><button type="submit" value="join">Join group</button><button type="submit" value="leave">Leave group</button></div>
        </fieldset>
        <fieldset className="managed-section">
          <legend>HTTPS modules</legend>
          <p>The device must trust the router's certificate before using HTTPS modules.</p>
          <div className="button-row"><button type="submit" value="mitm-enable">Enable modules</button><button type="submit" value="mitm-disable">Disable modules</button><button type="submit" value="mitm-reset">Use default</button></div>
        </fieldset>
      </fieldset>
    </form>
    <div id="managed-client-result" aria-live="polite" aria-busy={action.pending || groups.pending}>
      {groups.error && <p className="notice">{groups.error}</p>}
      {action.pending && <p>Loading device settings…</p>}
      {action.error && <p className="notice">{action.error}</p>}
      {device && <><div className="managed-result-heading"><h3>Saved settings</h3><span>{device.mac}</span></div>
        <dl className="managed-device-settings">
          {device.sets.map(set => <div key={set.name}><dt>{set.description || set.name}</dt><dd><span className="badge">{set.joined ? "Joined" : "Not joined"}</span></dd></div>)}
          <div><dt>HTTPS modules</dt><dd><span className="badge">{device.mitm_override === null ? "Use default" : device.mitm_override ? "Enabled" : "Disabled"}</span></dd>
            {device.mitm_override === null && <span className="field-hint">The effective default can depend on the device's source IP.</span>}
          </div>
        </dl>
      </>}
    </div>
  </section>;
}

export function createManagedClients(container, request) {
  const render = createView(container);
  let allowed = false, active = false;
  const update = () => render(<ManagedClients allowed={allowed} active={active} request={request} />);
  update();
  return {
    setAccess: (next) => { if (next !== allowed) { allowed = next; update(); } },
    setActive: (next) => { if (next !== active) { active = next; update(); } },
  };
}
