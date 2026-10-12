export function bytes(value = 0) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toLocaleString(undefined, { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}

export const rate = (value = 0) => `${bytes(value)}/s`;

export const series = [
  { key: "upload", name: "Upload", color: "var(--chart-upload)", dash: "5 4" },
  { key: "download", name: "Download", color: "var(--chart-download)" },
];
