import type { FormEvent } from "react";
import type { APIRequest, DeviceActions, DeviceState, ClientSetState, ClientImpactResponse, ManagedDevice, CertificateMetadata } from "./types.ts";
import { formValue } from "./dom.ts";

interface ClientActions extends DeviceActions { onCompare: (set: ClientSetState) => void }
import { Button } from "@cloudflare/kumo/components/button";
import { Collapsible } from "@cloudflare/kumo/components/collapsible";
import { Empty } from "@cloudflare/kumo/components/empty";
import { Input } from "@cloudflare/kumo/components/input";
import { LayerCard } from "@cloudflare/kumo/components/layer-card";
import { Switch } from "@cloudflare/kumo/components/switch";
import { CaretDownIcon } from "@phosphor-icons/react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createView } from "./react-view.ts";
import { StatusBanner } from "./notice.tsx";
import { type MITMChoice, MITMChoiceRow, mitmChoice } from "./mitm.tsx";
import { cardTitle, groupLabel, nested } from "./ui.ts";
import { useRequest } from "./use-request.ts";
import { TraceSteps } from "./trace.tsx";

const note = "text-sm text-kumo-subtle";

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
  // Routing effects read as details of the row above, like Kumo's indented disclosure panel.
  return <div className={`impact-content mt-1 mb-3 grid gap-4 py-1 ${nested}`} aria-busy={result.pending}>
    {result.pending && <p>Loading routing effects…</p>}
    {result.error && <StatusBanner tone="error" title="Could not load routing effects" description={result.error}
      action={<Button type="button" onClick={() => setRetry(value => value + 1)}>Retry</Button>} />}
    {impact && <>
      <div className="impact-summary grid gap-1">
        <p className="font-medium">Change: {impact.joined_before ? "On" : "Off"} → {impact.joined_after ? "On" : "Off"}.</p>
        <p className={note}>{impact.connection_behavior === "retain" ? "Existing connections keep their current route." : impact.connection_behavior === "close" ? "This router closes existing connections when routing changes." : `Existing connections: ${impact.connection_behavior}.`}</p>
      </div>
      {impact.rules.length ? <TraceSteps steps={impact.rules} /> : <p className={note}>No active dae routing references.</p>}
      <div className="impact-actions grid min-w-0 justify-items-start gap-3">
        {impact.exports.map((exported, index) => <p key={index} className={note}>{exported} · external firewall rules are not evaluated.</p>)}
        <p className={note}>Policy applicability uses this device's ingress. Referenced rules still depend on their conditions and order. Compare a target to evaluate the route.</p>
        <Button className="compare-target" type="button" onClick={() => onCompare(set)}>Compare a target</Button>
      </div>
    </>}
  </div>;
}

// Rows share the parent's columns, so names, states, switches and arrows stay aligned.
// Narrow containers move the name above its controls.
function ClientSetRow({ set, contextKey, actions, allowed }: { set: ClientSetState; contextKey: string; actions: ClientActions; allowed: boolean }) {
  const [open, setOpen] = useState(false);
  const label = set.description || set.name;
  return <div className="set-row col-span-full grid min-w-0 grid-cols-subgrid items-center border-t border-kumo-hairline py-1 first:border-t-0 @max-[16rem]:gap-y-2" data-name={set.name}>
    <strong className="set-name min-w-0 font-medium @max-[16rem]:col-span-full @max-[16rem]:pt-2">{label}</strong>
    <span className={`set-state w-[3ch] text-center text-sm whitespace-nowrap @max-[16rem]:col-start-2 ${set.joined ? "text-kumo-default" : "text-kumo-subtle"}`} aria-hidden="true">{set.joined ? "On" : "Off"}</span>
    {/* The label extends the switch's touch target to 48 by 44 pixels. */}
    <label className="client-toggle flex h-11 w-12 cursor-pointer items-center justify-center"><Switch aria-label={label} checked={set.joined} onCheckedChange={() => actions.run(async () => {
      actions.update(await actions.request<DeviceState>(`/api/device/sets/${encodeURIComponent(set.name)}`, set.joined ? "DELETE" : "PUT"));
    }, `${label} turned ${set.joined ? "off" : "on"} for this device.`)} /></label>
    {allowed && <Collapsible.Root className="set-details contents" open={open} onOpenChange={setOpen}>
      <Collapsible.Trigger className="disclosure-trigger col-start-4 grid size-9 place-items-center rounded-lg text-kumo-subtle hover:bg-kumo-tint">
        <span className="sr-only">Routing details for {label}</span>
        <CaretDownIcon className={open ? "rotate-180" : ""} size={14} weight="bold" aria-hidden />
      </Collapsible.Trigger>
      <Collapsible.Panel className="col-span-full min-w-0">
        {open && <ClientImpact key={contextKey} set={set} contextKey={contextKey} request={actions.request} onCompare={actions.onCompare} />}
      </Collapsible.Panel>
    </Collapsible.Root>}
  </div>;
}

function ClientSets({ device, actions, allowed }: { device: DeviceState; actions: ClientActions; allowed: boolean }) {
  const contextKey = JSON.stringify([device.mac, device.source_ip, device.sets]);
  if (!device.sets.length) return <Empty size="sm" title="No routing options" />;
  return <div className="client-options grid grid-cols-[minmax(0,1fr)_max-content_max-content_2.25rem] gap-x-3">{device.sets.map(set =>
    <ClientSetRow key={set.name} set={set} contextKey={contextKey} actions={actions} allowed={allowed} />
  )}</div>;
}

export function createClientSets(container: HTMLElement, actions: ClientActions) {
  const render = createView(container);
  let allowed = false, device: DeviceState | null = null;
  const update = () => { if (device) render(<ClientSets key={`${device.mac}/${device.source_ip}/${allowed}`} device={device} actions={actions} allowed={allowed} />); };
  return {
    setAccess: (next: boolean) => { if (allowed !== next) { allowed = next; update(); } },
    show: (next: DeviceState) => { device = next; update(); },
    unavailable: (text: string, tone: "error" | "warning" = "error") => { device = null; render(<StatusBanner tone={tone} title={text} />); },
  };
}

// After a lookup, another device's settings use the same rows and controls as this
// device's: a switch per routing rule and the HTTPS module choice. Its router default
// depends on the source IP the device connects from, which this page cannot see.
function ManagedClients({ allowed, request }: { allowed: boolean; request: APIRequest }) {
  const lookup = useRequest<ManagedDevice>();
  // The shown device stays in place while a change saves and reloads it.
  const [device, setDevice] = useState<ManagedDevice | null>(null);
  const focus = useRef("");
  useLayoutEffect(() => {
    if (!allowed) { lookup.reset(); setDevice(null); }
  }, [allowed, lookup.reset]);
  useEffect(() => { if (lookup.value) setDevice(lookup.value); }, [lookup.value]);
  useEffect(() => {
    if (focus.current && !lookup.pending) document.getElementById(focus.current)?.focus({ preventScroll: true });
  }, [device, lookup.pending]);

  async function load(mac: string, change?: (base: string) => Promise<unknown>) {
    const operation = lookup.start();
    try {
      const base = `/api/devices/${encodeURIComponent(mac)}`;
      if (change) await change(base);
      if (operation.current()) operation.resolve(await request<ManagedDevice>(base));
    } catch (error) { operation.reject(error); }
  }
  function show(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!allowed || lookup.pending) return;
    focus.current = "";
    setDevice(null);
    load(formValue(new FormData(event.currentTarget), "mac").trim());
  }
  function toggle(set: ClientSetState, id: string) {
    if (!device || lookup.pending) return;
    focus.current = id;
    load(device.mac, () => request(`/api/clients/${encodeURIComponent(set.name)}/members/${encodeURIComponent(device.mac)}`, set.joined ? "DELETE" : "PUT"));
  }
  function choose(next: MITMChoice) {
    if (!device || lookup.pending || next === mitmChoice(device.mitm_override)) return;
    focus.current = "managed-mitm-choice";
    load(device.mac, async (base) => {
      const certificate = await request<CertificateMetadata>("/api/certificate");
      await request(`${base}/mitm`, next === "default" ? "DELETE" : "PUT", next === "default" ? undefined : { enabled: next === "on" }, { "X-Dae-MITM": certificate.fingerprint });
    });
  }

  return <LayerCard id="managed-clients" render={<section aria-labelledby="managed-clients-title" />} className="setting-section" hidden={!allowed}>
    <LayerCard.Secondary className="setting-heading"><h2 id="managed-clients-title" className={cardTitle}>Device Settings</h2></LayerCard.Secondary>
    <LayerCard.Primary className="gap-0 p-4 md:p-5">
      <form id="managed-client-form" onSubmit={show} onInput={event => {
        if (event.target instanceof HTMLInputElement && event.target.name === "mac") { lookup.reset(); setDevice(null); }
      }}>
        <fieldset className="managed-device-lookup flex max-w-xl min-w-0 flex-wrap items-end gap-2" disabled={!allowed || lookup.pending}>
          <legend className="sr-only">Device</legend>
          <div className="managed-client-fields min-w-0 flex-[1_1_16rem]">
            <Input id="managed-client-mac" name="mac" label="Device MAC" placeholder="02:00:00:00:00:10" autoCapitalize="none" spellCheck={false} required className="w-full" />
          </div>
          <Button type="submit" value="show">Show settings</Button>
        </fieldset>
      </form>
      <div id="managed-client-result" className="empty:hidden" aria-live="polite" aria-busy={lookup.pending}>
        {lookup.pending && !device && <p className="mt-5">Loading device settings…</p>}
        {lookup.error && <StatusBanner tone="error" title="Device action failed" description={lookup.error} />}
        {device && <fieldset className="managed-device-settings min-w-0" disabled={lookup.pending}>
          <legend className="sr-only">Settings for {device.mac}</legend>
          <section className="mt-5 border-t border-kumo-hairline pt-5" aria-labelledby="managed-routing-title">
            {/* Editing the MAC clears these settings, so the field above names their device. */}
            <h3 id="managed-routing-title" className={groupLabel}>Routing Rules</h3>
            {device.sets.length ? <div className="managed-sets mt-1.5 divide-y divide-kumo-hairline">{device.sets.map((set, index) => {
              const label = set.description || set.name, id = `managed-set-${index}`;
              return <div key={set.name} className="managed-set grid grid-cols-[minmax(0,1fr)_max-content_max-content] items-center gap-x-3 py-1" data-name={set.name}>
                <strong className="min-w-0 font-medium">{label}</strong>
                <span className={`managed-set-state w-[3ch] text-center text-sm ${set.joined ? "text-kumo-default" : "text-kumo-subtle"}`} aria-hidden="true">{set.joined ? "On" : "Off"}</span>
                <label className="flex h-11 w-12 cursor-pointer items-center justify-center"><Switch id={id} aria-label={label} checked={set.joined} onCheckedChange={() => toggle(set, id)} /></label>
              </div>;
            })}</div> : <Empty size="sm" title="No routing options" />}
          </section>
          {/* The routing rows' 44px touch targets already leave space below the last row. */}
          <section className="mt-2 border-t border-kumo-hairline pt-5" aria-labelledby="managed-https-title">
            <h3 id="managed-https-title" className={groupLabel}>HTTPS Modules</h3>
            <StatusBanner tone="warning" title="Install and trust the CA certificate on that device first"
              description="Otherwise its HTTPS connections fail while HTTPS modules are on." />
            <div className="mt-3"><MITMChoiceRow id="managed-mitm-choice" value={mitmChoice(device.mitm_override)} defaultLabel="Router default" onChange={choose} /></div>
            <p className="mt-2 text-sm text-kumo-subtle">Its router default depends on the source IP the device connects from.</p>
          </section>
        </fieldset>}
      </div>
    </LayerCard.Primary>
  </LayerCard>;
}

export function createManagedClients(container: HTMLElement, request: APIRequest) {
  const render = createView(container);
  let allowed = false;
  const update = () => render(<ManagedClients allowed={allowed} request={request} />);
  update();
  return {
    setAccess: (next: boolean) => { if (next !== allowed) { allowed = next; update(); } },
  };
}
