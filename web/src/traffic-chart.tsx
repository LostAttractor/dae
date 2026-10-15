import type { TooltipContentProps } from "recharts";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { rate, series } from "./traffic-data.ts";
import { Swatch } from "./traffic.tsx";
import { floating } from "./ui.ts";

const age = (value: number) => value === 0 ? "Latest" : `${value}s`;

function RateTooltip({ active, payload, label }: TooltipContentProps) {
  if (!active || !payload?.length) return null;
  return <div className={`traffic-tooltip px-2.5 py-2 text-xs text-kumo-default ${floating}`}>
    <p className="mb-1.5 text-kumo-subtle">{label === 0 ? "Latest sample" : `${Math.abs(Number(label))}s before latest`}</p>
    <dl>{payload.map((entry) => <div key={String(entry.dataKey)} className="flex items-center justify-between gap-4">
      <dt className="inline-flex items-center gap-1.5"><Swatch series={String(entry.dataKey)} />{entry.name}</dt>
      <dd className="font-semibold tabular-nums">{rate(typeof entry.value === "number" ? entry.value : 0)}</dd>
    </div>)}</dl>
  </div>;
}

export default function TrafficChart({ data }: { data: { seconds: number; upload: number | null; download: number | null }[] }) {
  return <ResponsiveContainer width="100%" height="100%" minWidth={0}>
    <LineChart data={data} margin={{ top: 12, right: 24, bottom: 0, left: 0 }}
      accessibilityLayer aria-label="Upload and download rates in bytes per second. Use left and right arrow keys to explore five-second samples.">
      <CartesianGrid vertical={false} stroke="var(--color-kumo-hairline)" strokeDasharray="3 3" />
      <XAxis type="number" dataKey="seconds" domain={[-55, 0]} ticks={[-55, -30, 0]}
        tickFormatter={age} tickLine={false} axisLine={false} tickMargin={10} height={32}
        tick={{ fill: "var(--text-color-kumo-subtle)", fontSize: 12 }} />
      <YAxis domain={[0, (maximum: number) => Math.max(1, maximum)]} width={84} tickCount={4} allowDecimals={false}
        tickFormatter={rate} tickLine={false} axisLine={false} tickMargin={8}
        tick={{ fill: "var(--text-color-kumo-subtle)", fontSize: 12 }} />
      <Tooltip content={RateTooltip} isAnimationActive={false} cursor={{ stroke: "var(--color-kumo-line)", strokeDasharray: "3 3" }} />
      {series.map((item) => <Line key={item.key} type="linear" dataKey={item.key} name={item.name}
        stroke={item.color} strokeWidth={2} strokeDasharray={item.dash}
        dot={{ r: 2, strokeWidth: 0, fill: item.color }} activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--color-kumo-base)" }}
        isAnimationActive={false} connectNulls={false} />)}
    </LineChart>
  </ResponsiveContainer>;
}
