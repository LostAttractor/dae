import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";

// Native controllers own the host; React exclusively owns its children.
// Commit before returning so native action completion can safely restore focus.
export function createView(container) {
  const root = createRoot(container);
  return (content) => {
    const focused = container.contains(document.activeElement) ? document.activeElement : null;
    flushSync(() => root.render(content));
    if (focused?.isConnected && document.activeElement !== focused && !focused.matches(":disabled") && focused.checkVisibility()) {
      focused.focus({ preventScroll: true });
    }
  };
}
