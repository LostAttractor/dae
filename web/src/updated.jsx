import { useEffect, useState } from "react";
import { createView } from "./react-view.js";

function age(timestamp, now) {
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function UpdatedAt({ timestamp }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    let timer;
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
  return <time dateTime={date.toISOString()} title={date.toLocaleString()}>Updated {age(timestamp, now)}</time>;
}

export function createUpdatedLabel(container) {
  const render = createView(container);
  return {
    refresh: () => render(<UpdatedAt timestamp={Date.now()} />),
    message: (text) => render(text),
  };
}
