import type { components } from "./api.generated.ts";

export const nodeHealthLabels: Record<components["schemas"]["NodeHealth"], string> = {
  unknown: "Not tested", healthy: "Healthy", confirming: "Confirming failure", unhealthy: "Unavailable",
};
