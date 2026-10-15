import { Toast, Toasty, createKumoToastManager } from "@cloudflare/kumo/components/toast";
import { createView } from "./react-view.ts";
import { type NoticeTone, NoticeIcon, toneText } from "./notice.tsx";

const tones = { success: "success", warning: "warning", error: "error", pending: "info" } as const satisfies Record<string, NoticeTone>;
type Tone = keyof typeof tones;

// Kumo's toned variants draw a 0.3px ring that renders unevenly and color warning text
// below 4.5:1, so every notification uses the default surface with a 1px outline and
// the notice icon carries the tone. The message keeps clear of the close button, which
// the layer centers on the message like the icon instead of Kumo's top corner.
// One notification at a time: a new action's message replaces the previous one.
// Success closes after five seconds (paused on hover or focus); others stay until dismissed.
export function createNotifications(container: HTMLElement, layer: HTMLElement) {
  const manager = createKumoToastManager();
  let current: string | null = null, sequence = 0;
  createView(container)(<Toasty toastManager={manager} container={layer}>{null}</Toasty>);
  return (text = "", tone: Tone = "success") => {
    if (!text) {
      if (current) manager.close(current);
      return;
    }
    const options = {
      priority: tone === "error" ? "high" : "low", timeout: tone === "success" ? 5000 : 0,
      content: <div className="toast-message flex items-center gap-2 pr-4">
        <NoticeIcon tone={tones[tone]} size={16} />
        <Toast.Title className="min-w-0 text-[0.975rem] leading-5 font-medium">
          <span id="message" className={`whitespace-pre-line ${toneText(tones[tone])}`} data-tone={tone}>{text}</span>
        </Toast.Title>
      </div>,
    } as const;
    if (current) return manager.update(current, options);
    const id = `network-action-${++sequence}`;
    current = manager.add({ ...options, id, onClose: () => { if (current === id) current = null; } });
  };
}
