import type { FormEvent } from "react";
import type { APIRequest, DeviceActions, DeviceState, ClientSetState, ClientImpactResponse, ClientGroups, ManagedDevice, CertificateMetadata } from "./types.ts";
import { formValue } from "./dom.ts";

interface ClientActions extends DeviceActions { onCompare: (set: ClientSetState) => void }
import { Button } from "@astryxdesign/core/Button";
import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { Collapsible } from "@astryxdesign/core/Collapsible";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Field } from "@astryxdesign/core/Field";
import { Switch } from "@astryxdesign/core/Switch";
import { useEffect, useLayoutEffect, useState } from "react";
import { createView } from "./react-view.ts";
import { useRequest } from "./use-request.ts";
import { TraceSteps } from "./trace.tsx";

function ClientImpact({ set, contextKey, request, onCompare }: { set: ClientSetState; contextKey: string; request: APIRequest; onCompare: ClientActions["onCompare"] }) {
  const [retry, setRetry] = useState(0);
  const result = useRequest<ClientImpactResponse>();
  useEffect(() => {
    const operation = result.start();
    request<ClientImpactResponse>(`/api/device/sets/${encodeURIComponent(set.name)}/impact`, "POST", { joined: !set.joined, context: {} })
      .then(operation.resolve, operation.reject);
    return operation.cancel;
  }, [retry, contextKey, set.name, set.joined, request, result.start]);
  const impact = result.value;
  return <div className="impact-content" aria-busy={result.pending}>
    {result.pending && <p>Loading routing effects…</p>}
    {result.error && <Banner status="error" title="Could not load routing effects" description={result.error}
      endContent={<Button label="Retry" type="button" onClick={() => setRetry(value => value + 1)} />} />}
    {impact && <>
      <div className="impact-summary">
        <p>Change: {impact.joined_before ? "On" : "Off"} → {impact.joined_after ? "On" : "Off"}.</p>
        <p className="muted">{impact.connection_behavior === "retain" ? "Existing connections keep their current route." : impact.connection_behavior === "close" ? "This router closes existing connections when routing changes." : `Existing connections: ${impact.connection_behavior}.`}</p>
      </div>
      {impact.rules.length ? <TraceSteps steps={impact.rules} /> : <p className="muted">No active dae routing references.</p>}
      <div className="impact-actions">
        {impact.exports.map((exported, index) => <p key={index} className="muted">{exported} · external firewall rules are not evaluated.</p>)}
        <p className="muted">Policy applicability uses this device's ingress. Referenced rules still depend on their conditions and order. Compare a target to evaluate the route.</p>
        <Button label="Compare a target" type="button" onClick={() => onCompare(set)} />
      </div>
    </>}
  </div>;
}

function ClientSetRow({ set, contextKey, actions }: { set: ClientSetState; contextKey: string; actions: ClientActions }) {
  const [open, setOpen] = useState(false);
  const label = set.description || set.name;
  return <div className="set-row" data-name={set.name}>
    <strong className="set-name">{label}</strong>
    <span className="set-state" aria-hidden="true">{set.joined ? "On" : "Off"}</span>
    <Switch className="client-toggle" label={label} isLabelHidden value={set.joined} onChange={() => actions.run(async () => {
      actions.update(await actions.request<DeviceState>(`/api/device/sets/${encodeURIComponent(set.name)}`, set.joined ? "DELETE" : "PUT"));
    }, `${label} turned ${set.joined ? "off" : "on"} for this device.`)} />
    <Collapsible className="set-details" trigger={<span className="sr-only">Routing details for {label}</span>} isOpen={open} onOpenChange={setOpen}>
      {open && <ClientImpact key={contextKey} set={set} contextKey={contextKey} request={actions.request} onCompare={actions.onCompare} />}
    </Collapsible>
  </div>;
}

function ClientSets({ device, actions }: { device: DeviceState; actions: ClientActions }) {
  const contextKey = JSON.stringify([device.mac, device.source_ip, device.sets]);
  if (!device.sets.length) return <EmptyState isCompact title="No routing options" />;
  return <div className="client-options">{device.sets.map(set =>
    <ClientSetRow key={set.name} set={set} contextKey={contextKey} actions={actions} />
  )}</div>;
}

export function createClientSets(container: HTMLElement, actions: ClientActions) {
  const render = createView(container);
  return {
    show: (device: DeviceState) => render(<ClientSets key={`${device.mac}/${device.source_ip}`} device={device} actions={actions} />),
    unavailable: (text: string, tone: "error" | "warning" = "error") => render(<Banner status={tone} title={text} />),
  };
}

function ManagedClients({ allowed, active, request }: { allowed: boolean; active: boolean; request: APIRequest }) {
  const groups = useRequest<ClientGroups>(), action = useRequest<ManagedDevice>();
  useLayoutEffect(() => {
    if (!allowed) { groups.reset(); action.reset(); }
  }, [allowed, groups.reset, action.reset]);
  useEffect(() => {
    if (!active || !allowed) return;
    const operation = groups.start();
    request<ClientGroups>("/api/clients").then(operation.resolve, operation.reject);
    return operation.cancel;
  }, [active, allowed, request, groups.start]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!allowed || action.pending) return;
    const form = new FormData(event.currentTarget);
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    const kind = submitter instanceof HTMLButtonElement ? submitter.value : "show";
    const mac = formValue(form, "mac").trim(), name = formValue(form, "group");
    const operation = action.start();
    try {
      const base = `/api/devices/${encodeURIComponent(mac)}`;
      if (kind === "join" || kind === "leave") {
        if (!name) throw new Error("Choose a client group.");
        await request(`/api/clients/${encodeURIComponent(name)}/members/${encodeURIComponent(mac)}`, kind === "join" ? "PUT" : "DELETE");
      } else if (kind.startsWith("mitm-")) {
        const certificate = await request<CertificateMetadata>("/api/certificate");
        if (!operation.current()) return;
        await request(`${base}/mitm`, kind === "mitm-reset" ? "DELETE" : "PUT", kind === "mitm-reset" ? undefined : { enabled: kind === "mitm-enable" }, { "X-Dae-MITM": certificate.fingerprint });
      }
      if (operation.current()) operation.resolve(await request<ManagedDevice>(base));
    } catch (error) { operation.reject(error); }
  }

  const device = action.value;
  return <section id="managed-clients" className="setting-section" hidden={!allowed} aria-labelledby="managed-clients-title">
    <h2 id="managed-clients-title" className="setting-heading">Device Settings</h2>
    <form id="managed-client-form" onSubmit={submit} onInput={event => { if (event.target instanceof HTMLInputElement && event.target.name === "mac") action.reset(); }}>
      <fieldset className="managed-client-controls" disabled={!allowed || action.pending}>
        <fieldset className="managed-section">
          <legend className="sr-only">Device</legend>
          <div className="managed-device-lookup">
            <div className="managed-client-fields"><Field label="Device MAC" inputID="managed-client-mac"><input id="managed-client-mac" name="mac" placeholder="02:00:00:00:00:10" autoCapitalize="none" spellCheck={false} required /></Field></div>
            <Button label="Show settings" type="submit" value="show" />
          </div>
        </fieldset>
        <fieldset className="managed-section">
          <legend>Routing group</legend>
          <div className="managed-client-fields"><Field label="Group" inputID="managed-client-group" isDisabled={groups.pending}><select id="managed-client-group" name="group" disabled={groups.pending}>
              {(groups.value?.groups || []).map(group => <option key={group.name} value={group.name}>{group.description || group.name} ({group.members.length} members)</option>)}
          </select></Field></div>
          <div className="button-row"><Button label="Join group" type="submit" value="join" /><Button label="Leave group" type="submit" value="leave" /></div>
        </fieldset>
        <fieldset className="managed-section">
          <legend>HTTPS modules</legend>
          <p>Trust the router certificate before enabling HTTPS modules.</p>
          <div className="button-row"><Button label="Enable modules" type="submit" value="mitm-enable" /><Button label="Disable modules" type="submit" value="mitm-disable" /><Button label="Use default" type="submit" value="mitm-reset" /></div>
        </fieldset>
      </fieldset>
    </form>
    <div id="managed-client-result" aria-live="polite" aria-busy={action.pending || groups.pending}>
      {groups.error && <Banner status="error" title="Could not load groups" description={groups.error} />}
      {action.pending && <p>Loading device settings…</p>}
      {action.error && <Banner status="error" title="Device action failed" description={action.error} />}
      {device && <><div className="managed-result-heading"><h3>Saved settings</h3><span>{device.mac}</span></div>
        <dl className="managed-device-settings">
          {device.sets.map(set => <div key={set.name}><dt>{set.description || set.name}</dt><dd><Badge label={set.joined ? "Joined" : "Not joined"} /></dd></div>)}
          <div><dt>HTTPS modules</dt><dd><Badge label={device.mitm_override === null ? "Use default" : device.mitm_override ? "Enabled" : "Disabled"} /></dd>
            {device.mitm_override === null && <span className="field-hint">The effective default can depend on the device's source IP.</span>}
          </div>
        </dl>
      </>}
    </div>
  </section>;
}

export function createManagedClients(container: HTMLElement, request: APIRequest) {
  const render = createView(container);
  let allowed = false, active = false;
  const update = () => render(<ManagedClients allowed={allowed} active={active} request={request} />);
  update();
  return {
    setAccess: (next: boolean) => { if (next !== allowed) { allowed = next; update(); } },
    setActive: (next: boolean) => { if (next !== active) { active = next; update(); } },
  };
}
