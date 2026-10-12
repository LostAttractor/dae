import type { ReactNode } from "react";
import { Collapsible } from "@astryxdesign/core/Collapsible";
import { useEffect, useRef, useState } from "react";

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
  return <Collapsible className="certificate-disclosure" trigger="Certificate & browser verification" chevronPosition="start"
    isOpen={open} onOpenChange={(next) => { manuallyToggled.current = true; setOpen(next); }}>
    {children}
  </Collapsible>;
}
