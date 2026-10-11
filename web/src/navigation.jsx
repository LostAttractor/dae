import { TopNav, TopNavItem } from "@astryxdesign/core/TopNav";
import { byId } from "./dom.js";
import { createView } from "./react-view.js";

const pages = {
  overview: { title: "Overview", description: "Routing and HTTPS preferences." },
  tracing: { title: "Tracing", description: "Inspect how your network handles a request." },
  manage: { title: "Manage", description: "Manage devices and shared configuration." },
};

export function createNavigation(onChange) {
  const container = byId("page-navigation");
  const render = createView(container);
  let current;
  function activate(page, focus) {
    const changed = current !== page;
    current = page;
    document.querySelector(".shell").dataset.view = page;
    for (const popup of document.querySelectorAll(".node-popover:popover-open")) popup.hidePopover();
    for (const panel of document.querySelectorAll("[data-page]")) panel.hidden = panel.dataset.page !== page;
    render(<TopNav className="page-nav" label="Pages" centerContent={
      Object.entries(pages).map(([key, { title }]) =>
        <TopNavItem key={key} href={`#${key}`} label={title} isSelected={key === page} />)
    } />);
    byId("page-description").textContent = pages[page].description;
    byId("page-note").textContent = page === "tracing"
      ? "Read-only analysis · No test traffic is sent."
      : "Routing changes may interrupt active connections.";
    document.title = `Network Settings · ${pages[page].title}`;
    onChange(page);
    if (changed && focus) {
      window.scrollTo(0, 0);
      byId("page-title").focus({ preventScroll: true });
    }
  }
  function fromLocation(focus) {
    const page = location.hash.slice(1) || "overview";
    const valid = Object.hasOwn(pages, page);
    if (!valid) history.replaceState(null, "", "#overview");
    activate(valid ? page : "overview", focus);
  }
  function show(page) {
    if (!Object.hasOwn(pages, page)) return;
    if (current !== page) history.pushState(null, "", `#${page}`);
    activate(page, true);
  }
  container.addEventListener("click", (event) => {
    const link = event.target.closest("a");
    if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    show(link.hash.slice(1));
  });
  window.addEventListener("hashchange", () => fromLocation(true));
  fromLocation(false);
  return { show };
}
