import { Button } from "@astryxdesign/core/Button";
import { Badge } from "./native-controls.tsx";
import { Field } from "@astryxdesign/core/Field";
import { Icon } from "@astryxdesign/core/Icon";
import { createView } from "./react-view.ts";
import { CertificatePanel } from "./certificate-panel.tsx";

export function mountShell(container: HTMLElement) {
  createView(container)(<Shell />);
}

function Shell() {
  return (
    <div className="shell" data-view="overview">
      <div className="workspace">
        <fieldset id="controls" aria-label="Network controls">
          <header className="page-header">
            <div className="page-heading">
              <div className="page-title-row">
                <h1 id="page-title" tabIndex={-1}>Network Panel</h1>
                <Badge label={<span id="access-title">Guest</span>} aria-describedby="access-description" />
              </div>
              <p id="access-description">Checking access…</p>
              <Button label="Logout" id="logout" type="button" variant="ghost" hidden />
              <form id="login-form" className="login-form">
                <Field className="key-field" label="API Key" inputID="api-key">
                  <input id="api-key" name="api-key" type="password" autoComplete="current-password" spellCheck={false} placeholder="Enter your API key" required />
                </Field>
                <Button label="Login" id="login" type="submit" />
              </form>
            </div>
            <div id="page-navigation"></div>
            <div className="page-tools">
              <dl className="device-identity" aria-label="This device">
                <div><dt>IP</dt><dd id="identity">Identifying…</dd></div>
                <div><dt>MAC</dt><dd id="device-mac">Identifying…</dd></div>
              </dl>
              <div className="refresh-status">
                <span id="updated"></span>
                <Button label="Refresh" id="refresh" type="button" />
              </div>
            </div>
          </header>

          <main className="page-content" aria-labelledby="page-title">
            <div id="overview-page" className="dashboard" data-page="overview">
              <div className="dashboard-column dashboard-main">
                <section className="panel-card selectors-card" aria-labelledby="quick-setting-title">
                  <h2 id="quick-setting-title">Quick Setting</h2>
                  <section className="setting-subsection" aria-labelledby="quick-selectors-title">
                    <div className="card-heading">
                      <h3 id="quick-selectors-title">Selectors</h3>
                      <span id="quick-selector-count" className="count" hidden>Login required</span>
                    </div>
                    <div id="quick-selectors-locked" className="empty-state">
                      <p id="quick-access-required" className="access-required">Login required</p>
                      <p id="quick-login-hint">Enter your API key above to view outbound groups and switch nodes.</p>
                    </div>
                    <div id="quick-selectors" className="selector-list" hidden></div>
                  </section>
                </section>

                <section className="panel-card device-settings" aria-labelledby="device-setting-title">
                  <h2 id="device-setting-title">Device Setting</h2>
                  <section className="setting-subsection" aria-labelledby="device-title">
                    <h3 id="device-title">Routing Rules</h3>
                    <p id="routing-change-note" className="inline-notice" data-tone="warning"><Icon icon="warning" size="sm" /><span>Changes may interrupt active connections.</span></p>
                    <div id="sets" className="set-list"></div>
                  </section>

                  <section className="setting-subsection" aria-labelledby="https-title">
                    <div className="card-heading">
                      <h3 id="https-title">HTTPS Modules</h3>
                      <span id="mitm-summary" className="mitm-summary"></span>
                    </div>
                    <div id="mitm" className="mitm-state"></div>
                    <div id="certificate-panel" className="certificate-panel" hidden>
                      <CertificatePanel>
                        <div className="certificate-content">
                          <section className="certificate-install" aria-label="Certificate installation">
                            <div id="certificate" className="certificate-identity">
                              <strong id="certificate-name"></strong>
                              <span className="certificate-fingerprint-label">SHA-256 fingerprint</span>
                              <code id="certificate-fingerprint"></code>
                            </div>
                            <p>Verify this fingerprint on your router, then install and trust the certificate.</p>
                            <div className="download-links" role="group" aria-label="Download certificate">
                              <Button label="iOS Profile" href="/ca.mobileconfig" aria-label="Download iOS certificate profile" />
                              <Button label="DER" href="/ca.cer" aria-label="Download DER certificate" />
                              <Button label="PEM" href="/ca.pem" aria-label="Download PEM certificate" />
                            </div>
                          </section>
                          <section id="certificate-test-panel" aria-labelledby="certificate-test-title" hidden>
                            <div className="certificate-test-heading">
                              <div className="certificate-test-copy">
                                <h4 id="certificate-test-title">Browser verification</h4>
                                {import.meta.env.DEV && <p>Certificate and interception checks require this browser to connect directly to dae.</p>}
                              </div>
                              <Button label="Test Certificate" id="test-certificate" type="button" hidden={import.meta.env.DEV} />
                              {import.meta.env.DEV && <Button label="Open dae to verify" href={`${__DAE_DEV_API_URL__}/#overview`} target="_blank" rel="noreferrer" />}
                            </div>
                            <dl className="certificate-results" hidden={import.meta.env.DEV}>
                              <div><dt>Certificate trust</dt><dd><span id="certificate-trust-result" className="verification-result">Not tested</span></dd></div>
                              <div><dt>HTTPS interception</dt><dd><span id="certificate-mitm-result" className="verification-result">Not tested</span></dd></div>
                            </dl>
                            <p id="certificate-test-info" hidden={import.meta.env.DEV}>Results apply to this browser only.</p>
                          </section>
                        </div>
                      </CertificatePanel>
                    </div>
                  </section>
                </section>
              </div>
              <section id="status-view" className="panel-card status-card" aria-labelledby="traffic-title"></section>
            </div>

            <div id="setting-page" data-page="setting" hidden>
              <div id="setting-navigation"></div>
              <div id="setting-content">
                <div id="setting-devices" role="tabpanel" aria-labelledby="setting-devices-tab" data-setting-section="devices">
                  <section id="devices-locked" className="setting-section" aria-labelledby="devices-locked-title">
                    <h2 id="devices-locked-title" className="setting-heading">Device Settings</h2>
                    <p className="access-required">Administrator access required</p>
                    <p id="devices-login-hint" className="muted">Log in above to manage other devices.</p>
                  </section>
                  <div id="managed-clients-view" hidden></div>
                </div>
                <div id="setting-selector" role="tabpanel" aria-labelledby="setting-selector-tab" data-setting-section="selector" hidden>
                  <section className="setting-section selectors-card" aria-labelledby="selectors-title">
                    <div className="card-heading setting-heading">
                      <h2 id="selectors-title">Outbound Nodes</h2>
                      <span id="selector-count" className="count" hidden>Login required</span>
                    </div>
                    <div id="selectors-locked" className="empty-state">
                      <p id="access-required" className="access-required">Login required</p>
                      <p id="login-hint">Enter your API key above to view outbound groups and switch nodes.</p>
                    </div>
                    <div id="selectors" className="selector-list" hidden></div>
                  </section>
                </div>
                <div id="setting-explain" role="tabpanel" aria-labelledby="setting-explain-tab" data-setting-section="explain" hidden>
                  <section id="diagnostics" className="setting-section diagnostics-card" aria-labelledby="diagnostics-title">
                    <div className="card-heading setting-heading">
                      <h2 id="diagnostics-title">Explain a request</h2>
                      <Badge label="Read-only" title="No test traffic is sent and no settings are changed." />
                    </div>
                    <div id="diagnostic-view"></div>
                  </section>
                </div>
              </div>
            </div>
          </main>
        </fieldset>

        <footer><span id="daemon-version" hidden></span></footer>
      </div>
      <div id="notifications"></div>
    </div>
  );
}
