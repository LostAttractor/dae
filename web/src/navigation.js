import { byId } from "./dom.js";

const titles = { settings: "Network Settings", testing: "Testing", devices: "Devices" };

export function createNavigation(onChange) {
  let current;
  function activate(page, focus) {
    const changed = current !== page;
    current = page;
    document.querySelector(".shell").dataset.view = page;
    for (const popup of document.querySelectorAll(".node-popover:popover-open")) popup.hidePopover();
    for (const panel of document.querySelectorAll("[data-page]")) panel.hidden = panel.dataset.page !== page;
    for (const link of document.querySelectorAll(".page-nav a")) {
      if (link.hash === `#${page}`) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    byId("page-title").textContent = titles[page];
    byId("page-note").textContent = page === "testing"
      ? "Read-only analysis · No test traffic is sent."
      : "Changes apply to new connections.";
    document.title = `dae · ${titles[page]}`;
    onChange(page);
    if (changed && focus) {
      window.scrollTo(0, 0);
      byId("page-title").focus({ preventScroll: true });
    }
  }
  function fromLocation(focus) {
    const page = location.hash.slice(1) || "settings";
    const valid = Object.hasOwn(titles, page);
    if (!valid) history.replaceState(null, "", "#settings");
    activate(valid ? page : "settings", focus);
  }
  function show(page) {
    if (!Object.hasOwn(titles, page)) return;
    if (current !== page) history.pushState(null, "", `#${page}`);
    activate(page, true);
  }
  document.querySelector(".page-nav").addEventListener("click", (event) => {
    const link = event.target.closest("a");
    if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    show(link.hash.slice(1));
  });
  window.addEventListener("hashchange", () => fromLocation(true));
  fromLocation(false);
  return { show };
}
