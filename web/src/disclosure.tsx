import type { ReactNode } from "react";
import { Collapsible } from "@cloudflare/kumo/components/collapsible";

// The panel height animation follows Kumo's default panel.
const animated = "h-(--collapsible-panel-height) overflow-hidden transition-[height,opacity] duration-100 ease-out data-ending-style:h-0 data-ending-style:opacity-0 data-starting-style:h-0 data-starting-style:opacity-0 [&[hidden]:not([hidden='until-found'])]:hidden";

// A label followed by a caret. Sections open flush with their heading and grow with
// their content; nested details use Kumo's indented panel. Collapsed content stays in
// the document, hidden; render costly content only while open.
// The height animation clips the panel, and outlines and focus rings are drawn just
// outside their element, so the flush panel keeps a 4px gutter beyond its content.
// A `last` section ends its card, whose padding then follows the content directly.
export function Disclosure({ title, meta, className = "", name, nested = false, last = false, children, isOpen, onOpenChange }: { title: ReactNode; meta?: ReactNode; className?: string; name?: string; nested?: boolean; last?: boolean; children: ReactNode; isOpen?: boolean; onOpenChange?: (open: boolean) => void }) {
  return <Collapsible.Root className={`disclosure min-w-0 ${className}`} data-name={name} open={isOpen} onOpenChange={onOpenChange}>
    <Collapsible.DefaultTrigger className="disclosure-trigger min-h-10 w-full py-2 text-left">
      <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="disclosure-title">{title}</span>{meta != null && <span className="count text-sm font-normal text-kumo-subtle tabular-nums">{meta}</span>}
      </span>
    </Collapsible.DefaultTrigger>
    {nested
      ? <Collapsible.DefaultPanel className="min-w-0" keepMounted>{children}</Collapsible.DefaultPanel>
      : <Collapsible.Panel className={`-mx-1 min-w-0 px-1 ${last ? "-mb-1" : ""} ${animated}`} keepMounted><div className={`grid gap-4 pt-1 ${last ? "pb-1" : "pb-4"}`}>{children}</div></Collapsible.Panel>}
  </Collapsible.Root>;
}
