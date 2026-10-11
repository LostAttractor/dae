import { Collapsible } from "@astryxdesign/core/Collapsible";

export function Disclosure({ title, meta, nested = false, className = "", children, isOpen, onOpenChange }) {
  return <Collapsible className={`disclosure${nested ? " disclosure-nested" : ""} ${className}`}
    defaultIsOpen={false} isOpen={isOpen} onOpenChange={onOpenChange} chevronPosition="start"
    trigger={<span className="disclosure-label"><span>{title}</span>{meta && <span className="count">{meta}</span>}</span>}>
    {children}
  </Collapsible>;
}
