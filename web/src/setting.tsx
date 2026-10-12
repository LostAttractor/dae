import type { SettingSection } from "./types.ts";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { SideNav, SideNavItem } from "@astryxdesign/core/SideNav";
import { createView } from "./react-view.ts";

const sections: [SettingSection, string][] = [["devices", "Devices"], ["selector", "Selector"], ["explain", "Explain"]];

export function createSettingNavigation(container: HTMLElement, onChange: (section: SettingSection) => void) {
  const render = createView(container);
  const desktop = matchMedia("(min-width: 960px)");
  let value: SettingSection = "devices";
  function show(next: SettingSection) {
    value = next;
    for (const panel of document.querySelectorAll<HTMLElement>("[data-setting-section]")) {
      panel.hidden = panel.dataset.settingSection !== value;
      panel.setAttribute("role", desktop.matches ? "region" : "tabpanel");
    }
    render(desktop.matches ? <SideNav className="setting-sidebar" aria-label="Setting sections">
      {sections.map(([key, label]) => <SideNavItem key={key} label={label} id={`setting-${key}-tab`} href={`#setting/${key}`} isSelected={key === value}
        onClick={event => {
          if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
          event.preventDefault(); onChange(key);
        }} />)}
    </SideNav> : <TabList value={value} onChange={next => { if (sections.some(([key]) => key === next)) onChange(next as SettingSection); }} role="tablist" aria-label="Setting sections" hasDivider>
      {sections.map(([key, label]) => <Tab key={key} value={key} label={label} id={`setting-${key}-tab`} panelId={`setting-${key}`} onFocus={() => onChange(key)} />)}
    </TabList>);
  }
  desktop.addEventListener("change", () => {
    const focused = document.activeElement && container.contains(document.activeElement) ? document.activeElement.id : null;
    show(value);
    if (focused) document.getElementById(focused)?.focus({ preventScroll: true });
  });
  return { show };
}
