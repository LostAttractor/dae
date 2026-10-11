import { Tab, TabList } from "@astryxdesign/core/TabList";
import { createView } from "./react-view.js";

const sections = [["devices", "Devices"], ["outbounds", "Outbound nodes"], ["status", "Global status"]];

export function createManageNavigation(container, onChange) {
  const render = createView(container);
  function select(value) {
    for (const popup of document.querySelectorAll(".node-popover:popover-open")) popup.hidePopover();
    for (const panel of document.querySelectorAll("[data-manage-section]")) panel.hidden = panel.dataset.manageSection !== value;
    render(<TabList value={value} onChange={select} role="tablist" aria-label="Management sections" hasDivider>
      {sections.map(([key, label]) => <Tab key={key} value={key} label={label} id={`manage-${key}-tab`} panelId={`manage-${key}`} onFocus={() => select(key)} />)}
    </TabList>);
    onChange(value);
  }
  select("devices");
}
