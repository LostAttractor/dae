import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { createElement } from "react";
import type { ReactNode } from "react";
import { Theme } from "@astryxdesign/core/theme";
import { theme } from "dae-theme";

// Native controllers own the host; React exclusively owns its children.
// Commit before returning so native action completion can safely restore focus.
export function createView(container: HTMLElement) {
  const root = createRoot(container);
  return (content: ReactNode) => {
    const focused = container.contains(document.activeElement) ? document.activeElement : null;
    flushSync(() => root.render(createElement(Theme, { theme, mode: "system", children: content })));
    if (focused instanceof HTMLElement && focused.isConnected && document.activeElement !== focused && !focused.matches(":disabled") && focused.checkVisibility()) {
      focused.focus({ preventScroll: true });
    }
  };
}
