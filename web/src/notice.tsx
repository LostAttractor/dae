import type { ReactNode } from "react";
import { Banner } from "@cloudflare/kumo/components/banner";
import { CheckCircleIcon, InfoIcon, WarningIcon, WarningOctagonIcon } from "@phosphor-icons/react";

export type NoticeTone = "success" | "warning" | "error" | "info";

// Kumo's light warning color is below 4.5:1 for text, so warning and neutral text keep
// the default color and only their icon carries the tone.
const tones = {
  success: ["text-kumo-success", "", CheckCircleIcon],
  warning: ["text-kumo-default", "text-kumo-warning", WarningIcon],
  error: ["text-kumo-danger", "", WarningOctagonIcon],
  info: ["text-kumo-default", "text-kumo-info", InfoIcon],
} as const;
export const toneText = (tone: NoticeTone) => tones[tone][0];

// Every notice centers its icon on its text, one line or several; text wraps beside the
// icon, never under it.
export function NoticeIcon({ tone, size }: { tone: NoticeTone; size: number }) {
  const [color, iconColor, Icon] = tones[tone];
  return <Icon className={`notice-icon shrink-0 ${iconColor || color}`} size={size} weight="fill" aria-hidden />;
}

// A short line of status text with Kumo's semantic color and icon.
export function InlineNotice({ tone, id, className = "", title, children }: { tone: NoticeTone; id?: string; className?: string; title?: string; children: ReactNode }) {
  return <p id={id} title={title} className={`inline-notice flex items-center gap-1.5 ${toneText(tone)} ${className}`} data-tone={tone}>
    <NoticeIcon tone={tone} size={14} />
    <span className="min-w-0">{children}</span>
  </p>;
}

// Kumo banners for prerequisites, unavailable sections and failed requests; errors are
// announced as alerts. Kumo aligns the icon with the title; it is centered here like the
// banner's action.
export function StatusBanner({ tone, title, description, action }: { tone: "warning" | "error"; title: string; description?: ReactNode; action?: ReactNode }) {
  return <Banner className={`status-banner my-3 items-center ${toneText(tone)}`} variant={tone === "error" ? "error" : "alert"} role={tone === "error" ? "alert" : "status"} data-tone={tone}
    icon={<NoticeIcon tone={tone} size={18} />} title={title} description={description} action={action} />;
}
