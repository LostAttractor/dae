import type { Page, Route, SettingSection } from "./types.ts";
import { Tabs } from "@cloudflare/kumo/components/tabs";
import { byId } from "./dom.ts";
import { createView } from "./react-view.ts";

const routes: Record<Route, { page: Page; title: string; section?: SettingSection }> = {
  overview: { page: "overview", title: "Overview" },
  "setting/devices": { page: "setting", section: "devices", title: "Setting · Devices" },
  "setting/selector": { page: "setting", section: "selector", title: "Setting · Selector" },
  "setting/explain": { page: "setting", section: "explain", title: "Setting · Explain" },
};

export function createNavigation(onChange: (page: Page, section?: SettingSection) => void) {
  const container = byId("page-navigation");
  const render = createView(container);
  let current: Route | undefined;
  let settingRoute: Route = "setting/devices";
  function activate(route: Route, focus: boolean) {
    const { page, section, title } = routes[route];
    const changed = current !== route;
    current = route;
    if (page === "setting") settingRoute = route;
    byId("app").querySelector<HTMLElement>(".shell")!.dataset.view = page;
    for (const panel of document.querySelectorAll<HTMLElement>("[data-page]")) panel.hidden = panel.dataset.page !== page;
    // Page links render as segmented tabs; the container's click handler navigates.
    render(<Tabs className="page-nav" variant="segmented" value={page} tabs={[
      { value: "overview", label: "Overview", nativeButton: false, render: <a href="#overview" /> },
      { value: "setting", label: "Setting", nativeButton: false, render: <a href={`#${settingRoute}`} /> },
    ]} />);
    document.title = `Network Panel · ${title}`;
    onChange(page, section);
    if (changed && focus) {
      window.scrollTo(0, 0);
      byId("page-title").focus({ preventScroll: true });
    }
  }
  function fromLocation(focus: boolean) {
    const route = location.hash.slice(1) || "overview";
    const valid = Object.hasOwn(routes, route);
    if (!valid) history.replaceState(null, "", "#overview");
    activate(valid ? route as Route : "overview", focus);
  }
  function show(route: Route, focus = true) {
    if (!Object.hasOwn(routes, route) || current === route) return;
    history.pushState(null, "", `#${route}`);
    activate(route, focus);
  }
  container.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a") : null;
    if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    const route = link.hash.slice(1);
    if (Object.hasOwn(routes, route)) show(route as Route);
  });
  window.addEventListener("hashchange", () => fromLocation(true));
  fromLocation(false);
  return { show };
}
