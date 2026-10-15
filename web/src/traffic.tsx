import { Component, lazy, Suspense } from "react";
import type { ReactNode } from "react";
import type { PathStats } from "./types.ts";
import { rate, series } from "./traffic-data.ts";

const TrafficChart = lazy(() => import("./traffic-chart.tsx"));
const sampleCount = 12;
const sampleSeconds = 5;
const empty = "traffic-empty grid h-full place-content-center text-center text-kumo-subtle";

class ChartBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed
      ? <p className={empty} role="status">Traffic chart unavailable. <a href="" className="text-kumo-link">Reload page</a></p>
      : this.props.children;
  }
}

export function Swatch({ series: key }: { series: string }) {
  return <span className={`inline-block w-3.5 flex-none border-t-2 ${key === "upload" ? "border-dashed border-(--chart-upload)" : "border-(--chart-download)"}`} aria-hidden="true" />;
}

export function TrafficPanel({ stats }: { stats: PathStats }) {
  const history = stats.history || {};
  const upload = (history.upload_bytes_per_second || []).slice(-sampleCount);
  const download = (history.download_bytes_per_second || []).slice(-sampleCount);
  // Missing history stays empty; the right edge is the latest completed sample.
  const data = Array.from({ length: sampleCount }, (_, index) => ({
    seconds: (index - sampleCount + 1) * sampleSeconds,
    upload: upload[index - sampleCount + upload.length] ?? null,
    download: download[index - sampleCount + download.length] ?? null,
  }));
  const hasSamples = upload.length > 0 || download.length > 0;
  const metrics = [
    ["Active connections", (stats.active_connections ?? 0).toLocaleString()],
    ["Upload rate", upload.length ? rate(upload.at(-1)) : "—"],
    ["Download rate", download.length ? rate(download.at(-1)) : "—"],
  ];
  return <div className="traffic-panel">
    <dl className="traffic-metrics mt-2.5 mb-4 grid grid-cols-[repeat(auto-fit,minmax(min(100%,8rem),1fr))] gap-x-3 gap-y-2.5 tabular-nums">{metrics.map(([label, value]) => <div key={label}>
      <dt className="text-sm text-kumo-subtle">{label}</dt><dd className="mt-0.5 text-2xl font-semibold">{value}</dd>
    </div>)}</dl>
    <figure className="traffic-figure border-t border-kumo-hairline pt-3">
      <figcaption className="mb-2 flex flex-wrap items-center justify-end gap-x-4 gap-y-2">
        <span className="sr-only">Transfer rate</span>
        <span className="traffic-legend flex flex-wrap gap-3 text-xs text-kumo-subtle">{series.map((item) => <span key={item.key} className="inline-flex items-center gap-1.5">
          <Swatch series={item.key} />{item.name}
        </span>)}</span>
      </figcaption>
      <div className="traffic-chart h-40 w-full min-w-0 sm:h-36 [&_.recharts-surface]:rounded-md [&_.recharts-surface:focus-visible]:outline-2 [&_.recharts-surface:focus-visible]:outline-offset-2 [&_.recharts-surface:focus-visible]:outline-kumo-brand">
        {hasSamples ? <ChartBoundary>
          <Suspense fallback={<p className={empty} role="status">Loading traffic chart…</p>}>
            <TrafficChart data={data} />
          </Suspense>
        </ChartBoundary> : <p className={empty} role="status">Waiting for the first traffic sample…</p>}
      </div>
      <p className="chart-caption mt-1.5 text-xs text-kumo-subtle">Recent minute · 5-second samples</p>
    </figure>
  </div>;
}
