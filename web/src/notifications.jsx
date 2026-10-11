import { useLayoutEffect } from "react";
import { flushSync } from "react-dom";
import { ToastViewport, useToast } from "@astryxdesign/core/Toast";
import { createView } from "./react-view.js";

export function createNotifications(container) {
  let show, dismiss;
  createView(container)(
    <ToastViewport position="bottomEnd" maxVisible={1}>
      <NotificationController connect={(notify) => { show = notify; }} />
    </ToastViewport>,
  );
  return (text = "", tone = "success") => {
    flushSync(() => {
      if (!text) {
        dismiss?.();
        dismiss = null;
        return;
      }
      dismiss = show({
        body: <span id="message" data-tone={tone}>{text}</span>,
        type: tone === "error" ? "error" : "info",
        isAutoHide: tone === "success",
        autoHideDuration: 5000,
        uniqueID: "network-action",
        collisionBehavior: "overwrite",
      });
    });
  };
}

function NotificationController({ connect }) {
  const notify = useToast();
  useLayoutEffect(() => connect(notify), [connect, notify]);
  return null;
}
