import type { components } from "../src/api.generated.ts";
type Schema<Name extends keyof components["schemas"]> = components["schemas"][Name];
type PathStats = Schema<"PathStats">;
type GroupStatus = Schema<"GroupStatus">;
type ExplainResult = Schema<"ExplainResult">;
type ExplainRequest = Schema<"ExplainRequest">;
type ExplainResponse = Schema<"ExplainResponse">;
type GlobalStatus = Schema<"StatusSnapshot">;
type CertificateMetadata = Schema<"Certificate">;
type MITMTest = Schema<"MITMTest">;
type DeviceState = Schema<"DeviceState">;
type ManagedDevice = Schema<"ManagedDevice">;
type SelectorState = Schema<"SelectorState">;

export const deferred = () => Promise.withResolvers<void>();
export interface DeferredRead {
  started: ReturnType<typeof deferred>;
  release?: ReturnType<typeof deferred>;
  status?: number;
}

// Fixtures contain only fields exercised by the browser, derived from the API
// schema so names and value types stay consistent with production responses.
export type FixtureStats = Omit<PathStats, "history"> & { history: Partial<PathStats["history"]> };
export type FixtureGroup = Pick<GroupStatus, "name" | "health"> & Partial<Pick<GroupStatus, "policy" | "connectivity" | "target_kind">> & {
  stats: Partial<FixtureStats>;
  nodes: (Pick<Schema<"NodeStatus">, "name" | "checks_connectivity" | "health"> & {
    healthy?: boolean;
    stats: Partial<FixtureStats>;
  })[];
};
export type FixtureResult = Omit<ExplainResult, "outbounds"> & {
  outbounds: (Omit<Schema<"ExplainOutbound">, "observed_at" | "nodes"> & {
    nodes: Omit<Schema<"ExplainNode">, "id">[];
  })[];
};
export type FixtureBody = Partial<ExplainRequest & { node_id: string; outbound: string; enabled: boolean; joined: boolean }>;
export interface RecordedRequest { method: string; path: string; body: FixtureBody }
export interface Fixture {
  mode: "lan" | "api_key" | "denied";
  requests: RecordedRequest[];
  deviceStatusReads?: number;
  nextRead: DeferredRead | null;
  nextDeviceRead: DeferredRead | null;
  nextGlobalRead: DeferredRead | null;
  nextContextRead?: DeferredRead | null;
  generation?: number;
  nextImpact?: DeferredRead | null;
  impactRules?: Schema<"ExplainStep">[];
  nextExplanation?: DeferredRead | null;
  nextManagedDevice?: DeferredRead | null;
  certificate: CertificateMetadata | null;
  caTest?: Schema<"CertificateTest">;
  groups: FixtureGroup[];
  tables: Pick<GlobalStatus["tables"][number], "name" | "used" | "limit">[];
  plugins: Pick<NonNullable<GlobalStatus["plugins"]>[number], "id" | "type" | "state">[];
  stats: FixtureStats;
  selectors: SelectorState[];
  device: DeviceState;
  explanation?: (Omit<ExplainResponse, "current"> & { current: FixtureResult }) | null;
  managed?: ManagedDevice;
  testData?: Omit<MITMTest, "started_at" | "expires_at">;
  l3?: boolean;
  bypass?: boolean;
  untrusted?: boolean;
}
