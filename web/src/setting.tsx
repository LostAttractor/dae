import type { MouseEvent } from "react";
import type { SettingSection } from "./types.ts";
import { Tabs } from "@cloudflare/kumo/components/tabs";
import { DevicesIcon, ListMagnifyingGlassIcon, ShareNetworkIcon, type Icon } from "@phosphor-icons/react";
import { createView } from "./react-view.ts";

const sections: [SettingSection, string, Icon][] = [["devices", "Devices", DevicesIcon], ["selector", "Selector", ShareNetworkIcon], ["explain", "Explain", ListMagnifyingGlassIcon]];
const isSection = (value: string): value is SettingSection => sections.some(([key]) => key === value);
// The tab list clips overflow, so focus rings are drawn inside each tab.
export const inset = "focus-visible:ring-inset";
// Items follow Kumo's dashboard sidebar menu: a 13px label after a dimmed icon, and a
// filled current item. Kumo's Sidebar module also bundles tooltips, scroll areas and
// resizing, about 40 KB for three links, so only its item styles are used. Kumo's tint
// barely differs from the light canvas, so the fill is the recessed surface there.
// Kumo marks focus with the same fill, so a ring keeps focus visible on the current item.
const fill = "[--setting-fill:light-dark(var(--color-kumo-recessed),var(--color-kumo-tint))]";
const item = "flex min-h-8.5 min-w-0 items-center gap-3 rounded-lg px-3 text-sm font-medium text-kumo-default no-underline outline-none focus-visible:ring-2 focus-visible:ring-kumo-brand";
// Modified clicks keep the browser's link behavior, such as opening a new tab.
const plain = (event: MouseEvent) => event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey;

// Wide screens list the sections beside the content as ordinary links (Tab and Enter);
// narrow screens use tabs, where arrow keys and Home/End select the focused section.
export function createSettingNavigation(container: HTMLElement, onChange: (section: SettingSection) => void) {
  const render = createView(container);
  const desktop = matchMedia("(min-width: 768px)");
  let value: SettingSection = "devices";
  let allowed = false;
  const follow = (key: SettingSection) => (event: MouseEvent) => {
    if (!plain(event)) return;
    event.preventDefault();
    onChange(key);
  };
  function show(next: SettingSection) {
    value = next;
    for (const panel of document.querySelectorAll<HTMLElement>("[data-setting-section]")) {
      panel.hidden = panel.dataset.settingSection !== value;
      panel.setAttribute("role", desktop.matches ? "region" : "tabpanel");
    }
    const visible = sections.filter(([key]) => key !== "explain" || allowed);
    // Set directly on the page canvas, like Cloudflare's sidebar.
    render(desktop.matches ? <ul className={`setting-sidebar grid gap-px ${fill}`}>
      {visible.map(([key, label, Icon]) => <li key={key}>
        <a id={`setting-${key}-tab`} href={`#setting/${key}`} aria-current={key === value ? "page" : undefined}
          className={`${item} ${key === value ? "bg-(--setting-fill)" : "hover:bg-(--setting-fill)"}`} onClick={follow(key)}>
          <Icon className="size-4 shrink-0 opacity-40" aria-hidden /><span className="truncate">{label}</span>
        </a>
      </li>)}
    </ul> : <Tabs variant="underline" value={value} activateOnFocus onValueChange={next => { if (isSection(next) && visible.some(([key]) => key === next)) onChange(next); }}
      tabs={visible.map(([key, label]) => ({ value: key, label, nativeButton: false, className: inset,
        render: <a id={`setting-${key}-tab`} href={`#setting/${key}`} aria-controls={`setting-${key}`} onClick={event => { if (plain(event)) event.preventDefault(); }} /> }))} />);
  }
  desktop.addEventListener("change", () => {
    const focused = document.activeElement && container.contains(document.activeElement) ? document.activeElement.id : null;
    show(value);
    if (focused) document.getElementById(focused)?.focus({ preventScroll: true });
  });
  return { show, setAccess: (next: boolean) => { if (allowed !== next) { allowed = next; show(value); } } };
}
