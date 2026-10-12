import { useEffect, useState } from "react";
import { createView } from "./react-view.ts";

function age(timestamp: number, now: number) {
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function UpdatedAt({ timestamp, compact = false }: { timestamp: number; compact?: boolean }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    const sync = () => {
      clearInterval(timer);
      if (document.hidden) return;
      setNow(Date.now());
      timer = setInterval(() => setNow(Date.now()), 1000);
    };
    sync();
    document.addEventListener("visibilitychange", sync);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", sync);
    };
  }, []);
  const date = new Date(timestamp);
  const elapsed = age(timestamp, now);
  const shortAge = elapsed === "just now" ? "now" : elapsed.replace(" ago", "");
  return <time dateTime={date.toISOString()} title={date.toLocaleString()} aria-label={compact ? `Updated ${elapsed}` : undefined}>{compact ? shortAge : `Updated ${elapsed}`}</time>;
}

export function createUpdatedLabel(container: HTMLElement) {
  const render = createView(container);
  render("Not refreshed yet");
  return {
    refresh: () => render(<UpdatedAt timestamp={Date.now()} compact />),
    message: (text: string) => render(text),
  };
}
