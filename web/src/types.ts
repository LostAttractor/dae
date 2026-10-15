import type { components } from "./api.generated.ts";
import type { request } from "./api.ts";

export type Schema<Name extends keyof components["schemas"]> = components["schemas"][Name];
export type DeviceState = Schema<"DeviceState">;
export type DeviceStatus = Schema<"DeviceStatus">;
export type DeviceContext = Schema<"DeviceContext">;
export type ClientSetState = Schema<"ClientSetState">;
export type ClientImpactResponse = Schema<"ClientImpact">;
export type ManagedDevice = Schema<"ManagedDevice">;
export type MITMState = Schema<"MITMState">;
export type CertificateMetadata = Schema<"Certificate">;
export type CertificateTest = Schema<"CertificateTest">;
export type MITMTest = Schema<"MITMTest">;
export type MITMTestProof = Schema<"MITMTestProof">;
export type SelectorNode = Schema<"SelectorNode">;
export type SelectorState = Schema<"SelectorState">;
export type SelectorsResponse = Schema<"SelectorsResponse">;
export type GlobalStatus = Schema<"StatusSnapshot">;
export type GroupStatus = Schema<"GroupStatus">;
export type PathStats = Schema<"PathStats">;
export type ExplainRequest = Schema<"ExplainRequest">;
export type ExplainResponse = Schema<"ExplainResponse">;
export type ExplainResult = Schema<"ExplainResult">;
export type ExplainStep = Schema<"ExplainStep">;
export type ExplainDecision = Schema<"ExplainDecision">;
export type DiagnosticField = Schema<"DiagnosticField">;
export type DiagnosticFlow = Schema<"DiagnosticFlow">;
export type DiagnosticKind = NonNullable<ExplainRequest["kind"]>;
export type AuthMode = SelectorsResponse["auth_mode"];

export type Page = "overview" | "setting";
export type SettingSection = "devices" | "selector" | "explain";
export type Route = "overview" | `setting/${SettingSection}`;
export type APIRequest = typeof request;
export type RunAction = (action: () => Promise<unknown>, success?: string, pending?: string) => Promise<boolean>;
export interface DeviceActions {
  run: RunAction;
  request: APIRequest;
  update: (device: DeviceState) => void;
}
