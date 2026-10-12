import type { ShowToastFn, ToastDismissFn } from "@astryxdesign/core/Toast";
import { useLayoutEffect } from "react";
import { flushSync } from "react-dom";
import { ToastViewport, useToast } from "@astryxdesign/core/Toast";
import { Icon } from "@astryxdesign/core/Icon";
import { createView } from "./react-view.ts";

export function createNotifications(container: HTMLElement) {
  let show: ShowToastFn;
  let dismiss: ToastDismissFn | null = null;
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
        body: <span id="message" className="inline-notice" data-tone={tone}>{tone === "error" && <Icon icon="error" size="sm" />}<span>{text}</span></span>,
        type: tone === "error" ? "error" : "info",
        isAutoHide: tone === "success",
        autoHideDuration: 5000,
        uniqueID: "network-action",
        collisionBehavior: "overwrite",
      });
    });
  };
}

function NotificationController({ connect }: { connect: (notify: ShowToastFn) => void }) {
  const notify = useToast();
  useLayoutEffect(() => connect(notify), [connect, notify]);
  return null;
}
