import type { ReactNode } from "react";
import type { ExplainStep, ExplainResult, ExplainDecision, ExplainResponse, DiagnosticField, DiagnosticKind } from "./types.ts";
interface TraceActions { onEdit: (name: string) => void; onUseIP: (ip: string) => void }
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { Collapsible } from "@cloudflare/kumo/components/collapsible";
import { Select } from "@cloudflare/kumo/components/select";
import { CaretDownIcon, ProhibitIcon, WarningIcon } from "@phosphor-icons/react";
import { useState } from "react";
import { Disclosure } from "./disclosure.tsx";
import { cardTitle, codeBlock, framed, nested } from "./ui.ts";

const note = "text-sm text-kumo-subtle";
const code = `code-block ${codeBlock} whitespace-pre-wrap`;
const section = "trace-disclosure border-t border-kumo-hairline";
// Long lists grow with the page; they never scroll inside their section.
const rows = "divide-y divide-kumo-hairline text-sm [&>*]:py-2.5 [&>*:first-child]:pt-0 [&>*:last-child]:pb-0";
const factList = "grid gap-2.5 [&>div]:grid [&>div]:gap-x-2 [&>div]:sm:grid-cols-[minmax(100px,1fr)_3fr] [&_dt]:text-sm [&_dt]:text-kumo-subtle";

const words = (value: string = "") => value.replaceAll("_", " ");
const reasons: Record<string, string> = {
  terminal_decision: "This rule determines the route at this stage.",
  predicate_match: "The conditions match.", predicate_miss: "The conditions do not match.",
  missing_context: "More information is needed to evaluate this rule.",
  earlier_terminal_rule: "An earlier rule already determined the route.",
  outbound_unavailable: "Skipped because the outbound is unavailable.",
  not_bound_to_active_policy: "This rule is not part of the active policy.",
  different_ingress_policy: "This rule belongs to another ingress policy.",
  missing_policy_context: "The ingress policy is unknown; this rule has not been evaluated.",
  remaining_predicates_and_rule_order: "Other conditions and earlier rules still affect the outcome.",
  client_reference: "This rule references the client group. Its full match and routing effect have not been evaluated.",
  membership_change: "Client predicate before and after the proposed membership change.",
  no_active_plugins: "No plugins are active.", http_disabled: "HTTP interception is disabled.",
  client_not_allowed: "HTTPS modules are disabled for this device.",
  script_execution_required: "The script must run before its effect can be known. This check does not run scripts.",
};
const reasonText = (reason?: string) => (reason ? reasons[reason] : undefined) || words(reason);
const statusText = (step: ExplainStep) => ({ referenced: "Referenced", selected: "Selected", conditional: "Uncertain", not_reached: "Not reached", inactive: "Inactive", skipped: "Skipped", unknown: "Unknown", error: "Error" } as Record<string, string>)[step.status] || (step.match === "miss" ? "No match" : step.match === "match" ? "Matched" : "Unknown");

const policyStates = {
  match: { label: "Applies", variant: "success", description: "This policy is selected for the current context. The rule still depends on its conditions and earlier decisions." },
  miss: { label: "Does not apply", variant: "secondary", description: "This policy is not selected for the current context, so this rule cannot apply." },
  unknown: { label: "Unknown", variant: "warning", description: "The ingress interface is unknown, so policy applicability cannot be determined." },
} as const;

function PolicyBadge({ step }: { step: ExplainStep }) {
  if (!step.policy) return null;
  const state = policyStates[step.policy_match || "unknown"];
  return <span className="trace-policy" title={state.description}><Badge variant={state.variant}>{`Policy: ${step.policy} · ${state.label}`}</Badge></span>;
}

function PolicyIndicator({ step }: { step: ExplainStep }) {
  if (!step.policy) return null;
  const state = policyStates[step.policy_match || "unknown"];
  const label = `Policy: ${step.policy} · ${state.label}`;
  const color = step.policy_match === "match" ? "bg-kumo-success" : step.policy_match === "miss" ? "bg-kumo-badge-neutral" : "bg-kumo-badge-orange";
  return <span className={`trace-policy-indicator inline-block size-2 flex-none rounded-full ${color}`} data-state={step.policy_match || "unknown"} role="img" aria-label={label} title={label} />;
}

// Collapsed rules keep a one-line expression; expanding wraps it in place.
export function TraceSteps({ steps = [] }: { steps?: ExplainStep[] }) {
  return <div className="trace-steps divide-y divide-kumo-hairline">{steps.map((step, index) => <Collapsible.Root className="trace-step" key={`${step.id || step.expression}:${index}`}>
    <Collapsible.Trigger className="disclosure-trigger group grid w-full cursor-pointer grid-cols-[minmax(0,1fr)_auto] items-baseline gap-2 py-2.5 text-left text-kumo-default">
      <span className="trace-step-label grid items-baseline gap-2 sm:grid-cols-[auto_minmax(0,1fr)]">
        <span className="trace-step-badges flex flex-wrap items-center gap-1.5 justify-self-start">
          <Badge variant={step.status === "error" ? "error" : ["conditional", "unknown"].includes(step.status) ? "warning" : "secondary"}>{statusText(step)}</Badge>
          <PolicyIndicator step={step} />
        </span>
        <span className="trace-expression -my-0.5 min-w-0 truncate py-0.5 font-mono text-sm group-data-[panel-open]:overflow-visible group-data-[panel-open]:whitespace-pre-wrap group-data-[panel-open]:[text-overflow:clip]">{step.expression}</span>
      </span>
      <CaretDownIcon className="text-kumo-subtle group-data-[panel-open]:rotate-180" size={12} weight="bold" aria-hidden />
    </Collapsible.Trigger>
    <Collapsible.Panel keepMounted className={`trace-step-content mb-3.5 grid gap-2 pt-1.5 ${nested}`}>
      {(step.section === "rules" || step.policy) && <div className="trace-step-meta flex flex-wrap items-center gap-1.5">
        {step.section === "rules" && <Badge variant="secondary">Rules</Badge>}
        <PolicyBadge step={step} />
      </div>}
      <p>{reasonText(step.reason)}</p>
      {step.policy && <p className={note}>{policyStates[step.policy_match || "unknown"].description}</p>}
      <p className={note}>Stage: {words(step.stage)}{step.parent && step.parent !== step.policy ? ` · Context: ${step.parent}` : ""}</p>
      <p className={code}>{step.expression}</p>
      {step.outbound && <p>Outbound: {step.outbound} · mark {step.mark || 0} · must {String(Boolean(step.must))}</p>}
      {!!step.targets?.length && <p>Targets: {step.targets.join(", ")}</p>}
      {(step.sources || []).map((source, index) => <p key={index} className={code}>{source.file || "configuration"}:{source.line || 0}:{source.column || 0} {source.expression}</p>)}
      {(step.conditions || []).map((condition, index) => <div key={index} className="trace-condition mt-1 grid gap-1.5 border-t border-kumo-hairline pt-3">
        <strong className="font-semibold">{condition.expression}{condition.reason !== "membership_change" && `: ${words(condition.match)}`}</strong>
        <p className={note}>{condition.reason === "membership_change" ? reasonText(condition.reason) : `${words(condition.status)} · ${reasonText(condition.reason)}`}</p>
        <p className={code}>{condition.reason === "membership_change"
          ? `Before: ${condition.actual || "—"}\nAfter: ${condition.expected || "—"}`
          : `Actual: ${condition.actual || "—"}\nExpected: ${condition.expected || "—"}`}</p>
      </div>)}
    </Collapsible.Panel>
  </Collapsible.Root>)}</div>;
}

function RuleTrace({ steps }: { steps: ExplainStep[] }) {
  const [filter, setFilter] = useState("all");
  const filters: Record<string, [string, (step: ExplainStep) => boolean]> = {
    all: ["All rules", () => true],
    selected: ["Selected", step => step.status === "selected"],
    matched: ["Matched", step => ["evaluated", "selected"].includes(step.status) && step.match === "match"],
    uncertain: ["Uncertain", step => ["conditional", "unknown"].includes(step.status)],
    inactive: ["Inactive / not reached", step => ["inactive", "not_reached"].includes(step.status)],
  };
  const filtered = steps.filter(filters[filter][1]);
  return <Disclosure className={`${section} trace-rule-list`} title="Rule trace" meta={`${steps.length} rule${steps.length === 1 ? "" : "s"}`}>
    <div className="trace-filter max-w-sm">
      <Select label="Show" className="w-full" value={filter} onValueChange={value => setFilter(String(value))}
        items={Object.fromEntries(Object.entries(filters).map(([key, [label, match]]) => [key, `${label} (${steps.filter(match).length})`]))} />
    </div>
    <div><TraceSteps steps={filtered} />{!filtered.length && <p className={note}>No rules in this category.</p>}</div>
  </Disclosure>;
}

function outcome(result: ExplainResult, kind: DiagnosticKind) {
  const decision = result.decision;
  if (!decision.complete) return [decision.missing?.includes("destination.ip") ? "Destination IP needed" : "Cannot determine the result yet", decision.missing?.length ? "Some information needed by the rules is missing. Complete it below and run the check again." : "The result depends on runtime behavior or a choice that this read-only check cannot make."];
  switch (decision.verdict) {
    case "kernel_direct": return ["Direct in the kernel", "This connection passes through the kernel without a userspace handoff."];
    case "drop": return ["Connection blocked", "The current rules or outbound availability policy block this connection."];
    case "userspace": return [decision.outbound === "direct" ? "Direct through userspace" : decision.outbound ? `Routed via ${decision.outbound}` : "Handled in userspace", "The connection is handed to dae in userspace."];
    case "local_response": return ["Answered locally", "A plugin provides a local response."];
    case "analysis": {
      if (kind === "domain") return [result.domains?.length ? `${result.domains.length} cached domain records` : "No cached domain records", "The details show each record's source and kernel presence. No DNS lookup is sent."];
      if (kind === "outbound") {
        const group = result.outbounds?.[0], selected = group?.nodes?.filter(node => node.selected) || [];
        return [!group?.available ? "Outbound unavailable" : group.random ? "Node chosen at connection time" : selected.length === 1 ? `Selected node: ${selected[0].name}` : "Outbound available", "Selection and availability reflect the current snapshot. No connection test is sent."];
      }
      const disabled = result.steps?.find(step => ["no_active_plugins", "http_disabled", "client_not_allowed"].includes(step.reason));
      return [disabled ? reasonText(disabled.reason) : kind === "dns" ? "DNS policy evaluated" : "HTTP plugins evaluated", "Review the matching rules below. This analysis alone does not determine the connection route."];
    }
    default: return ["Result undetermined", "Review the details for the available evidence."];
  }
}

const missingFields: Record<string, [string, string]> = {
  "destination.ip": ["Destination IP", "A URL or hostname does not identify one destination IP. Enter the actual IP, or check a cached candidate below."],
  "destination.port": ["Destination port", "Include a port in the target, such as example.com:443."],
  domain_mapping: ["Kernel domain mapping", "Kernel domain rules use existing DNS-to-IP mappings. Entering a hostname or SNI does not create a mapping."],
  hostname: ["TLS / HTTP hostname", "Supply TLS SNI or an HTTP(S) URL. Use advanced JSON with flow.sni set to an empty string to explicitly declare no hostname."],
  hostname_verification: ["Hostname verification", "Resolver evidence is needed to verify the hostname. This check does not query DNS."],
  trusted_hostname: ["Trusted hostname", "The current hostname evidence is insufficient for this routing stage."],
  rewritten_target_address: ["Rewritten destination IP", "A plugin changed the target. Its destination address is needed to continue."],
  mitm_client_identity: ["Device identity", "A known device is needed to evaluate its HTTPS module settings."],
};

function MissingContext({ decision, context, onEdit, onUseIP }: TraceActions & { decision: ExplainDecision; context: DiagnosticField[] }) {
  const missing = decision.missing || [];
  const [candidate, setCandidate] = useState("");
  const daemon = context.some(field => field.name === "origin" && field.value === "daemon");
  const source = !daemon && context.find(field => field.name === "source_ip" && field.source !== "unknown")?.value;
  // An inherited IPv4 identity cannot simulate an IPv6 connection (or vice versa).
  const candidates = [...new Set((decision.targets || []).map(target => target.match(/^\[([^\]]+)\]:\d+$/)?.[1] || target.match(/^(\d+\.\d+\.\d+\.\d+):\d+$/)?.[1]).filter(ip => ip && (!source || ip.includes(":") === source.includes(":"))))];
  if (!missing.length) return null;
  return <div className="trace-missing my-4">
    <h4 className="mb-3 text-base font-semibold">Complete the missing information</h4>
    <ul className="mb-4 grid gap-3">{missing.map(field => <li key={field} className="grid gap-0.5"><strong className="font-medium">{missingFields[field]?.[0] || words(field)}</strong><span className="text-kumo-subtle">{missingFields[field]?.[1] || "Supply this field in Advanced context if it is known. Omitted values remain unknown."}</span></li>)}</ul>
    <div className="button-row flex flex-wrap gap-2">
      {missing.includes("destination.ip") && <Button type="button" onClick={() => onEdit("ip")}>Enter destination IP</Button>}
      {missing.includes("hostname") && <Button type="button" onClick={() => onEdit("sni")}>Enter hostname</Button>}
      {missing.some(field => !["destination.ip", "domain_mapping", "hostname"].includes(field)) && <Button type="button" onClick={() => onEdit(missing.includes("destination.port") ? "target" : "overrides")}>Edit test context</Button>}
    </div>
    {missing.includes("destination.ip") && candidates.length > 0 && <div className="trace-candidates mt-4 grid gap-2">
      <div className="trace-candidate-controls flex max-w-xl flex-wrap items-end gap-2">
        <div className="min-w-0 flex-[1_1_14rem]">
          <Select className="w-full" label={<span className="flex flex-wrap gap-x-3 gap-y-1">Check one cached IP <span className="font-normal text-kumo-subtle">{candidates.length} candidates{source ? ` · ${source.includes(":") ? "IPv6" : "IPv4"}` : ""} · no DNS query</span></span>}
            placeholder="Choose an IP…" value={candidate || null} onValueChange={value => setCandidate(typeof value === "string" ? value : "")}
            items={Object.fromEntries(candidates.map(ip => [ip, ip]))} />
        </div>
        <Button type="button" className="check-candidate flex-none" disabled={!candidate} onClick={() => onUseIP(candidate)}>Check this IP</Button>
      </div>
      <p className={note}>The result applies to the selected IP only. Your client may use another address.</p>
    </div>}
  </div>;
}

function TraceResult({ title, result, kind, context, onEdit, onUseIP }: TraceActions & { title: string; result: ExplainResult; kind: DiagnosticKind; context: DiagnosticField[] }) {
  const decision = result.decision, steps = result.steps || [];
  const [headline, description] = outcome(result, kind);
  const selected = decision.complete && steps.find(step => step.id === decision.rule_id);
  const targets = decision.targets || [];
  const domains = result.domains || [], group = result.outbounds?.[0];
  const state = !decision.complete ? "unknown" : decision.verdict === "drop" ? "blocked" : "complete";
  const facts: [string, ReactNode][] = kind === "domain" ? [
    ["Cached records", domains.length], ["Present in kernel", domains.filter(entry => entry.resident).length], ["DNS lookup", "Not sent"],
  ] : kind === "outbound" ? [
    ["Group", group?.name || "—"], ["Selection policy", group?.policy || "builtin"], ["Network", group?.network || "—"],
  ] : [
    ["Outbound", decision.outbound ? <>{decision.outbound}{!decision.complete && <span className="font-normal text-kumo-subtle"> · provisional</span>}</> : decision.complete ? "Not applicable" : "Not determined"],
    ["Policy", decision.policy || "—"],
    [!decision.complete && targets.length > 1 ? "Candidate destinations" : "Destination", targets.length === 1 ? targets[0] : targets.length ? `${targets.length} candidates · see details` : decision.original_target || "—"],
  ];
  return <section className="trace-result @container grid min-w-0 content-start gap-1">
    {/* The surface stays neutral so labels keep their contrast; the ring and icon carry the state. */}
    <div className={`trace-outcome ${framed} data-[state=blocked]:ring-kumo-danger/60 data-[state=unknown]:ring-kumo-warning/70`} data-state={state}>
      <p className="trace-label mb-1 text-sm text-kumo-subtle">{title}</p>
      <h3 className="mb-1 flex items-center gap-2 text-xl font-semibold max-sm:text-lg">
        {state === "unknown" && <WarningIcon className="trace-outcome-icon shrink-0 text-kumo-warning" size={20} weight="fill" aria-hidden />}
        {state === "blocked" && <ProhibitIcon className="trace-outcome-icon shrink-0 text-kumo-danger" size={20} weight="bold" aria-hidden />}
        <span>{headline}</span>
      </h3>
      <p className="mb-4 max-w-[70ch]">{description}</p>
      <dl className="trace-facts grid grid-cols-2 gap-3 @xl:grid-cols-[1fr_1fr_2fr] @xl:gap-4 [&>div:last-child]:col-span-full @xl:[&>div:last-child]:col-auto">
        {facts.map(([label, value]) => <div key={label}><dt className="text-sm text-kumo-subtle">{label}</dt><dd className="mt-0.5 font-medium">{value}</dd></div>)}
      </dl>
      {decision.original_outbound && decision.original_outbound !== decision.outbound && <p className="trace-fallback mt-4 border-t border-kumo-hairline pt-4">{decision.original_outbound} is unavailable; fallback outbound: {decision.outbound || "undetermined"}.</p>}
      {selected && <div className="trace-selected mt-4 grid gap-1 border-t border-kumo-hairline pt-4"><strong className="font-semibold">Deciding rule</strong><code className="truncate font-mono text-sm">{selected.expression}</code><span className="text-sm text-kumo-subtle">{reasonText(selected.reason)}</span></div>}
    </div>
    {!decision.complete && <MissingContext decision={decision} context={context} onEdit={onEdit} onUseIP={onUseIP} />}
    {!decision.complete && !decision.missing?.length && result.notes?.length > 0 && <p className="trace-runtime-note my-4">{result.notes.filter(note => !note.startsWith("Fresh unfragmented flow")).join(" ")}</p>}
    {steps.length > 0 && <RuleTrace steps={steps} />}
    {(result.outbounds || []).map((group, index) => <Disclosure className={section} key={index} title={`Outbound nodes · ${group.name}`} meta={group.available ? "available" : "unavailable"}>
      <p className={note}>{group.policy || "builtin"} · {group.network}{group.random ? " · random selection at connection time" : ""}</p>
      <ul className={rows}>{group.nodes.map((node, index) => <li key={index} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <strong className="font-medium">{node.name}</strong>{node.selected && <Badge variant="info">Selected</Badge>}
        <span className="text-kumo-subtle">{words(node.reason)}{node.selection ? ` · priority ${node.selection.priority} · score ${node.selection.score}` : ""}</span>
      </li>)}</ul>
    </Disclosure>)}
    {result.domains?.length > 0 && <Disclosure className={section} title="Cached domain records" meta={`${result.domains.length} records`}>
      <ul className={rows}>{result.domains.map((entry, index) => <li key={index}>{entry.domain} → <span className="font-mono">{entry.ip}</span> <span className="text-kumo-subtle">· {entry.resident ? "present in kernel" : "absent from kernel"} · {words(entry.source)}{entry.retain_until ? ` · retained until ${entry.retain_until}` : ""}</span></li>)}</ul>
    </Disclosure>}
    <Disclosure className={section} title="Technical details">
      <dl className={`trace-technical ${factList}`}>
        {Object.entries({ Verdict: decision.verdict, Complete: String(decision.complete), "Rule ID": decision.rule_id || "—", "Original target": decision.original_target || "—", "Original outbound": decision.original_outbound || "—", Mark: decision.mark, Must: String(decision.must), Capture: (decision.capture || []).join(", ") || "none" }).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
      </dl>
      {targets.length > 0 && <Disclosure nested title="Destination list" meta={`${targets.length}`}><ul className={`${rows} font-mono`}>{targets.map((target, index) => <li key={index}>{target}</li>)}</ul></Disclosure>}
      {(result.notes || []).map((text, index) => <p key={index} className={note}>{text}</p>)}
    </Disclosure>
  </section>;
}

export function Explanation({ response, kind = "flow", target, onEdit, onUseIP }: TraceActions & { response: ExplainResponse; kind?: DiagnosticKind; target: string }) {
  return <div className="explanation mt-5 border-t border-kumo-hairline pt-5">
    {/* The scope qualifies every result below, so it sits under the heading rather than after them. */}
    <div className="mb-3 grid gap-1">
      <div className="trace-heading flex flex-wrap items-baseline gap-x-4 gap-y-1"><h2 className={cardTitle}>Result</h2>{target && <span className="text-kumo-subtle">{target}</span>}</div>
      {response.compared && <p className={note}>Compare the same target and context. Proposed changes have not been applied.</p>}
      {kind === "flow" && <p className={`trace-scope ${note}`}>For a new connection using the current state. Existing connections may keep their earlier route.</p>}
    </div>
    <div className={`trace-results grid gap-4 ${response.compared ? "trace-comparison min-[960px]:grid-cols-2" : ""}`}>
      <TraceResult title="Current settings" result={response.current} kind={kind} context={response.context} onEdit={onEdit} onUseIP={onUseIP} />
      {response.compared && <TraceResult title="With proposed changes" result={response.compared} kind={kind} context={response.context} onEdit={onEdit} onUseIP={onUseIP} />}
    </div>
    <Disclosure className={section} last title="Input context and raw response">
      <p className={note}>Generation {response.generation} · {response.observed_at}</p>
      <dl className={`trace-technical ${factList}`}>{response.context.map((field, index) => <div key={index}><dt>{field.name}</dt><dd>{field.value || "—"} <span className="text-kumo-subtle">[{field.source}]</span></dd></div>)}</dl>
      <Disclosure nested title="Response JSON"><pre className={code}>{JSON.stringify(response, null, 2)}</pre></Disclosure>
    </Disclosure>
  </div>;
}
