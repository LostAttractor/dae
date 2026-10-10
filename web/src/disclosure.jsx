export function Disclosure({ title, meta, nested = false, className = "", children }) {
  return <details className={`disclosure${nested ? " disclosure-nested" : ""} ${className}`}>
    <summary className="disclosure-summary">
      <span className="disclosure-label"><span>{title}</span>{meta && <span className="count">{meta}</span>}</span>
    </summary>
    <div className="disclosure-content">{children}</div>
  </details>;
}
