import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const sampleCount = 12;
const sampleSeconds = 5;
const series = [
  { key: "upload", name: "Upload", color: "var(--chart-upload)", dash: "5 4" },
  { key: "download", name: "Download", color: "var(--chart-download)" },
];

export function bytes(value = 0) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toLocaleString(undefined, { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}

const rate = (value) => `${bytes(value)}/s`;
const age = (value) => value === 0 ? "Latest" : `${value}s`;

function RateTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="traffic-tooltip">
    <p>{label === 0 ? "Latest sample" : `${Math.abs(label)}s before latest`}</p>
    <dl>{payload.map((entry) => <div key={entry.dataKey}>
      <dt><span className={`traffic-swatch ${entry.dataKey}`} aria-hidden="true" />{entry.name}</dt>
      <dd>{rate(entry.value)}</dd>
    </div>)}</dl>
  </div>;
}

export function TrafficPanel({ stats }) {
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
    ["Total connections", (stats.total_connections ?? 0).toLocaleString()],
    ["Uploaded", bytes(stats.upload_bytes)], ["Downloaded", bytes(stats.download_bytes)],
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
        {hasSamples ? <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <LineChart data={data} margin={{ top: 12, right: 24, bottom: 0, left: 0 }}
            accessibilityLayer aria-label="Upload and download rates in bytes per second. Use left and right arrow keys to explore five-second samples.">
            <CartesianGrid vertical={false} stroke="var(--line)" strokeDasharray="3 3" />
            <XAxis type="number" dataKey="seconds" domain={[-55, 0]} ticks={[-55, -30, 0]}
              tickFormatter={age} tickLine={false} axisLine={false} tickMargin={10} height={32}
              tick={{ fill: "var(--muted)", fontSize: 13 }} />
            <YAxis domain={[0, (maximum) => Math.max(1, maximum)]} width={84} tickCount={4} allowDecimals={false}
              tickFormatter={rate} tickLine={false} axisLine={false} tickMargin={8}
              tick={{ fill: "var(--muted)", fontSize: 13 }} />
            <Tooltip content={RateTooltip} isAnimationActive={false} cursor={{ stroke: "var(--control-line)", strokeDasharray: "3 3" }} />
            {series.map((item) => <Line key={item.key} type="linear" dataKey={item.key} name={item.name}
              stroke={item.color} strokeWidth={2} strokeDasharray={item.dash}
              dot={{ r: 2, strokeWidth: 0, fill: item.color }} activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--surface)" }}
              isAnimationActive={false} connectNulls={false} />)}
          </LineChart>
        </ResponsiveContainer> : <p className="traffic-empty" role="status">Waiting for the first traffic sample…</p>}
      </div>
      <p className="chart-caption">Recent minute · 5-second samples</p>
    </figure>
  </div>;
}
