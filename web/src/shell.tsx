import { Badge, KUMO_BADGE_BASE_STYLES } from "@cloudflare/kumo/components/badge";
import { Button, LinkButton } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import { LayerCard } from "@cloudflare/kumo/components/layer-card";
import { createView } from "./react-view.ts";
import { CertificateDownload, CertificatePanel } from "./certificate-panel.tsx";
import { InlineNotice } from "./notice.tsx";
import { cardTitle, codeBlock, framed, groupLabel } from "./ui.ts";

// The header, content and footer share one centered frame inside the page gutter.
export const frame = "mx-auto w-full max-w-[1384px]";
const gutter = "px-4 md:px-7";
// Native controllers set each result's text and data-tone.
const result = `verification-result ${KUMO_BADGE_BASE_STYLES} bg-kumo-fill text-kumo-subtle data-[tone=pending]:bg-kumo-info-tint data-[tone=pending]:text-kumo-info data-[tone=success]:bg-kumo-success-tint data-[tone=success]:text-kumo-success data-[tone=warning]:bg-kumo-warning-tint data-[tone=warning]:text-kumo-warning data-[tone=error]:bg-kumo-danger-tint data-[tone=error]:text-kumo-danger`;

export function mountShell(container: HTMLElement) {
  createView(container)(<Shell />);
}

function Shell() {
  return (
    <div className="shell flex min-h-dvh flex-col" data-view="overview">
      <fieldset id="controls" className="min-w-0" aria-label="Network controls">
        <div className={`border-b border-kumo-line bg-kumo-base ${gutter}`}>
          <header className={`page-header ${frame} flex flex-wrap items-center gap-x-6 gap-y-3 py-3`}>
            <div className="page-heading min-w-0 basis-full md:flex-[0_1_17.5rem]">
              <div className="page-title-row flex min-h-7 flex-wrap items-center gap-x-2 gap-y-1">
                <h1 id="page-title" className="text-lg font-semibold outline-none" tabIndex={-1}>Network Panel</h1>
                <Badge variant="secondary"><span id="access-title">Guest</span></Badge>
              </div>
              <p id="access-description" className="mt-0.5 text-xs text-kumo-subtle">Checking access…</p>
              <Button id="logout" type="button" variant="ghost" size="sm" className="mt-1" hidden>Logout</Button>
              <form id="login-form" className="login-form mt-3 flex max-w-[480px] flex-wrap items-end gap-2">
                <div className="key-field min-w-0 flex-1">
                  <Input id="api-key" name="api-key" type="password" label="API Key" autoComplete="current-password" spellCheck={false} placeholder="Enter your API key" required className="w-full" />
                </div>
                <Button id="login" type="submit">Login</Button>
              </form>
            </div>
            <nav id="page-navigation" className="order-2 min-w-0 max-w-full md:order-none" aria-label="Pages"></nav>
            <div className="page-tools contents md:flex md:min-w-0 md:max-w-full md:flex-[1_1_24rem] md:flex-wrap md:items-center md:justify-end md:gap-x-5 md:gap-y-3">
              <dl className="device-identity order-4 flex min-w-0 max-w-full basis-full flex-wrap items-baseline gap-x-4 gap-y-1 text-xs md:order-none md:basis-auto" aria-label="This device">
                <div className="flex min-w-0 items-baseline gap-1.5"><dt className="whitespace-nowrap text-kumo-subtle">IP</dt><dd id="identity" className="min-w-0 font-mono">Identifying…</dd></div>
                <div className="flex min-w-0 items-baseline gap-1.5"><dt className="whitespace-nowrap text-kumo-subtle">MAC</dt><dd id="device-mac" className="min-w-0 font-mono">Identifying…</dd></div>
              </dl>
              <div className="refresh-status order-3 ml-auto flex min-w-0 max-w-full items-center justify-end gap-2.5 md:order-none md:ml-0">
                <span id="updated" className="min-w-0 max-w-48 text-xs text-kumo-subtle"></span>
                <Button id="refresh" type="button">Refresh</Button>
              </div>
            </div>
          </header>
        </div>

        <main className={`workspace page-content min-w-0 pt-4 md:pt-6 ${gutter}`} aria-labelledby="page-title">
          <div id="overview-page" className={`${frame} grid items-start gap-4 md:gap-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(340px,1fr)]`} data-page="overview">
            <div className="dashboard-main grid min-w-0 gap-4 md:gap-5">
              <LayerCard render={<section aria-labelledby="quick-setting-title" />} className="selectors-card min-w-0">
                <LayerCard.Secondary><h2 id="quick-setting-title" className={cardTitle}>Quick Setting</h2></LayerCard.Secondary>
                <LayerCard.Primary className="gap-0 p-4 md:p-5">
                  <section aria-labelledby="quick-selectors-title">
                    <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                      <h3 id="quick-selectors-title" className={groupLabel}>Selectors</h3>
                      <span id="quick-selector-count" className="count text-sm text-kumo-subtle tabular-nums" hidden>Login required</span>
                    </div>
                    <div id="quick-selectors-locked" className={framed}>
                      <p id="quick-access-required" className="access-required font-semibold data-[tone=error]:text-kumo-danger">Login required</p>
                      <p id="quick-login-hint" className="mt-1 text-kumo-subtle">Enter your API key above to view outbound groups and switch nodes.</p>
                    </div>
                    <div id="quick-selectors" className="selector-list grid grid-cols-[repeat(auto-fit,minmax(min(100%,22.5rem),1fr))] gap-3" hidden></div>
                  </section>
                </LayerCard.Primary>
              </LayerCard>

              <LayerCard render={<section aria-labelledby="device-setting-title" />} className="device-settings min-w-0">
                <LayerCard.Secondary><h2 id="device-setting-title" className={cardTitle}>Device Setting</h2></LayerCard.Secondary>
                <LayerCard.Primary className="gap-0 p-4 md:p-5">
                  <section aria-labelledby="device-title">
                    <h3 id="device-title" className={groupLabel}>Routing Rules</h3>
                    <InlineNotice id="routing-change-note" tone="warning" className="mt-1.5 text-sm">Changes may interrupt active connections.</InlineNotice>
                    <div id="sets" className="set-list @container"></div>
                  </section>

                  {/* The routing rows' 44px touch targets already leave space below the last row. */}
                  <section className="mt-2 border-t border-kumo-hairline pt-5" aria-labelledby="https-title">
                    <h3 id="https-title" className={groupLabel}>HTTPS Modules</h3>
                    <div id="mitm" className="mitm-state"></div>
                  </section>
                  {/* The disclosure trigger's own 8px padding completes the 20px below the divider. */}
                  <section id="certificate-panel" className="certificate-panel mt-5 border-t border-kumo-hairline pt-3" hidden>
                    <CertificatePanel>
                      <div className="certificate-content grid gap-4">
                        <section className="certificate-install grid gap-3" aria-label="Certificate installation">
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <strong id="certificate-name" className="min-w-0 font-semibold"></strong>
                            <CertificateDownload />
                          </div>
                          <div id="certificate" className="certificate-identity grid min-w-0 gap-1.5">
                            <span className="certificate-fingerprint-label text-sm text-kumo-subtle">SHA-256 fingerprint</span>
                            <code id="certificate-fingerprint" className={`${codeBlock} break-all empty:hidden`}></code>
                            <p className="text-sm text-kumo-subtle">Verify this fingerprint on your router, then install and trust the local CA for API HTTPS and enabled HTTPS modules.</p>
                          </div>
                        </section>
                        <section id="certificate-test-panel" className={`grid gap-3 ${framed}`} aria-labelledby="certificate-test-title" hidden>
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <div className="grid min-w-0 flex-[1_1_16rem] gap-1">
                              <h4 id="certificate-test-title" className="text-base font-semibold">Browser verification</h4>
                              {import.meta.env.DEV && <p className="text-sm text-kumo-subtle">Certificate and interception checks require this browser to connect directly to dae.</p>}
                            </div>
                            <Button id="test-certificate" type="button" hidden={import.meta.env.DEV}>Test certificate</Button>
                            {import.meta.env.DEV && <LinkButton variant="secondary" href={`${__DAE_DEV_API_URL__}/#overview`} external>Open dae to verify</LinkButton>}
                          </div>
                          <dl className="certificate-results grid grid-cols-[repeat(auto-fit,minmax(min(100%,12rem),1fr))] gap-x-6 gap-y-3" hidden={import.meta.env.DEV} aria-live="polite">
                            <div className="min-w-0"><dt className="text-sm text-kumo-subtle">CA trust</dt><dd className="mt-1.5"><span id="certificate-trust-result" className={result}>Not tested</span></dd></div>
                            <div className="min-w-0"><dt className="text-sm text-kumo-subtle">HTTPS interception</dt><dd className="mt-1.5"><span id="certificate-mitm-result" className={result}>Not tested</span></dd></div>
                          </dl>
                          <p id="certificate-test-info" className="text-sm whitespace-pre-line text-kumo-subtle" hidden={import.meta.env.DEV}>Results apply to this browser only.</p>
                          <a id="certificate-http-setup" className="text-sm text-kumo-link" hidden>Return to HTTP setup to install and trust the CA</a>
                        </section>
                      </div>
                    </CertificatePanel>
                  </section>
                </LayerCard.Primary>
              </LayerCard>
            </div>
            <div id="status-view" className="min-w-0"></div>
          </div>

          <div id="setting-page" className={`${frame} grid items-start gap-4 md:grid-cols-[13rem_minmax(0,1fr)] md:gap-5`} data-page="setting" hidden>
            {/* The section list stays in view beside long results. */}
            <nav id="setting-navigation" className="min-w-0 md:sticky md:top-6" aria-label="Setting sections"></nav>
            <div id="setting-content" className="min-w-0">
              <div id="setting-devices" role="tabpanel" aria-labelledby="setting-devices-tab" data-setting-section="devices">
                <LayerCard id="devices-locked" render={<section aria-labelledby="devices-locked-title" />}>
                  <LayerCard.Secondary><h2 id="devices-locked-title" className={cardTitle}>Device Settings</h2></LayerCard.Secondary>
                  <LayerCard.Primary className="p-4 md:p-5">
                    <div className={framed}>
                      <p className="access-required font-semibold">Administrator access required</p>
                      <p id="devices-login-hint" className="mt-1 text-kumo-subtle">Log in above to manage other devices.</p>
                    </div>
                  </LayerCard.Primary>
                </LayerCard>
                <div id="managed-clients-view" hidden></div>
              </div>
              <div id="setting-selector" role="tabpanel" aria-labelledby="setting-selector-tab" data-setting-section="selector" hidden>
                <LayerCard render={<section aria-labelledby="selectors-title" />} className="selectors-card">
                  <LayerCard.Secondary className="justify-between">
                    <h2 id="selectors-title" className={cardTitle}>Outbound Nodes</h2>
                    <span id="selector-count" className="count text-sm font-normal text-kumo-default tabular-nums" hidden>Login required</span>
                  </LayerCard.Secondary>
                  <LayerCard.Primary className="p-4 md:p-5">
                    <div id="selectors-locked" className={framed}>
                      <p id="access-required" className="access-required font-semibold data-[tone=error]:text-kumo-danger">Login required</p>
                      <p id="login-hint" className="mt-1 text-kumo-subtle">Enter your API key above to view outbound groups and switch nodes.</p>
                    </div>
                    <div id="selectors" className="selector-list grid grid-cols-[repeat(auto-fit,minmax(min(100%,22.5rem),1fr))] gap-3" hidden></div>
                  </LayerCard.Primary>
                </LayerCard>
              </div>
              <div id="setting-explain" role="tabpanel" aria-labelledby="setting-explain-tab" data-setting-section="explain" hidden>
                <LayerCard id="diagnostics" render={<section aria-labelledby="diagnostics-title" />} className="diagnostics-card">
                  <LayerCard.Secondary className="setting-heading justify-between">
                    <h2 id="diagnostics-title" className={cardTitle}>Explain a request</h2>
                    <span title="No test traffic is sent and no settings are changed."><Badge variant="secondary">Read-only</Badge></span>
                  </LayerCard.Secondary>
                  <LayerCard.Primary id="diagnostic-view" className="gap-0 p-4 md:p-5"></LayerCard.Primary>
                </LayerCard>
              </div>
            </div>
          </div>
        </main>
        {/* Popups paint above the cards, and the fieldset also disables their controls. */}
        <div id="popup-layer"></div>
      </fieldset>

      <div className={`mt-auto ${gutter}`}>
        <footer className={`${frame} flex justify-end py-5 text-xs text-kumo-subtle`}><span id="daemon-version" hidden></span></footer>
      </div>
      {/* Outside the fieldset, so notifications stay dismissible while an action runs.
          The layer centers Kumo's corner close button on the message. */}
      <div id="notifications"></div>
      <div id="notification-layer" className="[&_[aria-label=Close]]:top-1/2 [&_[aria-label=Close]]:-translate-y-1/2"></div>
    </div>
  );
}
