import type { ReactNode } from "react";
import { Button } from "@cloudflare/kumo/components/button";
import { Popover } from "@cloudflare/kumo/components/popover";
import { CaretDownIcon, DownloadSimpleIcon } from "@phosphor-icons/react";
import { Disclosure } from "./disclosure.tsx";
import { useEffect, useRef, useState } from "react";
import { floating } from "./ui.ts";

// One download action; the menu names each format and where it is used. The
// profile opens normally so Safari can offer to install it.
const downloads = [
  { href: "/ca.mobileconfig", label: "Configuration profile", hint: "Apple devices · .mobileconfig", download: false },
  { href: "/ca.cer", label: "DER certificate", hint: "Windows, Android · .cer", download: true },
  { href: "/ca.pem", label: "PEM certificate", hint: "Linux, Firefox and tools · .pem", download: true },
];
// Popups render into the layer that paints above the cards; it exists once the shell has rendered.
const layer = { get current() { return document.getElementById("popup-layer"); } };

export function CertificateDownload() {
  return <Popover>
    <Popover.Trigger render={<Button type="button" id="certificate-download" icon={DownloadSimpleIcon} />}>
      Download<CaretDownIcon className="text-kumo-subtle" size={14} weight="bold" aria-hidden />
    </Popover.Trigger>
    <Popover.Content container={layer} side="bottom" align="end" sideOffset={6}
      className={`certificate-downloads [&>[data-side]]:hidden w-72 max-w-[calc(100vw-24px)] gap-0 p-1.5 text-base outline-0 ${floating}`}>
      <Popover.Title className="sr-only">Download the CA certificate</Popover.Title>
      <ul className="grid gap-0.5">{downloads.map(({ href, label, hint, download }) => <li key={href}>
        <a href={href} download={download || undefined} className="grid gap-0.5 rounded-md px-2.5 py-2 text-kumo-default no-underline outline-none hover:bg-kumo-tint focus-visible:ring-2 focus-visible:ring-kumo-brand">
          <span>{label}</span><span className="text-xs text-kumo-subtle">{hint}</span>
        </a>
      </li>)}</ul>
    </Popover.Content>
  </Popover>;
}

export function CertificatePanel({ children }: { children: ReactNode }) {
  const [roomy] = useState(() => matchMedia("(min-width: 768px) and (min-height: 600px)"));
  const [open, setOpen] = useState(roomy.matches);
  const manuallyToggled = useRef(false);
  useEffect(() => {
    const applyDefault = () => { if (!manuallyToggled.current) setOpen(roomy.matches); };
    roomy.addEventListener("change", applyDefault);
    applyDefault();
    return () => roomy.removeEventListener("change", applyDefault);
  }, [roomy]);
  return <Disclosure className="certificate-disclosure" last title="Certificate & browser verification"
    isOpen={open} onOpenChange={(next) => { manuallyToggled.current = true; setOpen(next); }}>
    {children}
  </Disclosure>;
}
