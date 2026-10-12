import { Component, lazy, Suspense } from "react";
import type { ReactNode } from "react";
import type { PathStats } from "./types.ts";
import { rate, series } from "./traffic-data.ts";

const TrafficChart = lazy(() => import("./traffic-chart.tsx"));
const sampleCount = 12;
const sampleSeconds = 5;

class ChartBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed
      ? <p className="traffic-empty" role="status">Traffic chart unavailable. <a href="">Reload page</a></p>
      : this.props.children;
  }
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
    <dl className="traffic-metrics">{metrics.map(([label, value]) => <div key={label}>
      <dt>{label}</dt><dd>{value}</dd>
    </div>)}</dl>
    <figure className="traffic-figure">
      <figcaption className="traffic-chart-heading">
        <span className="sr-only">Transfer rate</span>
        <span className="traffic-legend">{series.map((item) => <span key={item.key}>
          <span className={`traffic-swatch ${item.key}`} aria-hidden="true" />{item.name}
        </span>)}</span>
      </figcaption>
      <div className="traffic-chart">
        {hasSamples ? <ChartBoundary>
          <Suspense fallback={<p className="traffic-empty" role="status">Loading traffic chart…</p>}>
            <TrafficChart data={data} />
          </Suspense>
        </ChartBoundary> : <p className="traffic-empty" role="status">Waiting for the first traffic sample…</p>}
      </div>
      <p className="chart-caption">Recent minute · 5-second samples</p>
    </figure>
  </div>;
}
