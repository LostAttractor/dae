import { Button } from "@astryxdesign/core/Button";
import { Badge } from "@astryxdesign/core/Badge";
import { Field } from "@astryxdesign/core/Field";
import { Collapsible } from "@astryxdesign/core/Collapsible";
import { createView } from "./react-view.js";
import { CertificatePanel } from "./certificate-panel.jsx";

export function mountShell(container) {
  createView(container)(<Shell />);
}

function Shell() {
  return (
    <div className="shell" data-view="overview">
      <div className="workspace">
        <header className="page-header">
          <div className="page-heading">
            <h1 id="page-title" tabIndex="-1">Network Settings</h1>
            <p id="page-description">Routing and HTTPS preferences.</p>
          </div>
          <div id="page-navigation"></div>
        </header>

        <main className="page-content" aria-labelledby="page-title">
          <fieldset id="controls" aria-label="Network controls">
            <div className="toolbar card">
              <div className="access-context">
                <div className="access-line">
                  <Badge label={<span id="access-title">Guest</span>} aria-describedby="access-description" />
                  <Collapsible className="device-identity" defaultIsOpen={false} chevronPosition="start" trigger={<span id="identity">Identifying your device…</span>}>
                    <span id="device-mac" className="muted"></span>
                  </Collapsible>
                </div>
                <form id="login-form" className="login-form">
                  <Field className="key-field" label="API Key" inputID="api-key">
                    <input id="api-key" name="api-key" type="password" autoComplete="current-password" spellCheck={false} placeholder="Enter your API key" required />
                  </Field>
                  <Button label="Login" id="login" type="submit" />
                </form>
                <div id="session-info" className="session-info" hidden>
                  <p id="access-description">Logged in · Remembered for 7 days</p>
                  <Button label="Logout" id="logout" type="button" />
                </div>
              </div>
              <div className="refresh-controls">
                <span id="updated">Not refreshed yet</span>
                <Button label="Refresh" id="refresh" type="button" />
              </div>
            </div>

            <div id="overview-page" className="dashboard" data-page="overview">
              <div className="dashboard-column dashboard-main">
                <section className="card" aria-labelledby="device-title">
                  <h2 id="device-title">Routing Rules</h2>
                  <p id="routing-change-note" className="section-description">Apply to this device. Multiple options can be enabled. Changes may interrupt active connections.</p>
                  <div id="sets" className="set-list"></div>
                </section>

                <section className="card" aria-labelledby="https-title">
                  <h2 id="https-title">HTTPS Modules</h2>
                  <p className="section-description">Manage HTTPS modules for this device.</p>
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
                          <div className="certificate-downloads">
                            <span id="certificate-download-title">Download</span>
                            <div className="download-links" role="group" aria-labelledby="certificate-download-title">
                              <Button label="iOS Profile" href="/ca.mobileconfig" aria-label="Download iOS certificate profile" />
                              <Button label="DER" href="/ca.cer" aria-label="Download DER certificate" />
                              <Button label="PEM" href="/ca.pem" aria-label="Download PEM certificate" />
                            </div>
                          </div>
                        </section>
                        <section id="certificate-test-panel" aria-labelledby="certificate-test-title" hidden>
                          <div className="certificate-test-heading">
                            <h3 id="certificate-test-title">Browser verification</h3>
                            <Button label="Test Certificate" id="test-certificate" type="button" />
                          </div>
                          <dl className="certificate-results">
                            <div><dt>Certificate trust</dt><dd><span id="certificate-trust-result" className="verification-result">Not tested</span></dd></div>
                            <div><dt>HTTPS interception</dt><dd><span id="certificate-mitm-result" className="verification-result">Not tested</span></dd></div>
                          </dl>
                          <p id="certificate-test-info">Results apply to this browser only.</p>
                        </section>
                      </div>
                    </CertificatePanel>
                  </div>
                </section>
              </div>
              <section id="status-view" className="card status-card" aria-labelledby="traffic-title"></section>
            </div>

            <div id="tracing-page" data-page="tracing" hidden>
              <section id="diagnostics" className="card diagnostics-card" aria-labelledby="diagnostics-title">
                <h2 id="diagnostics-title">Trace a request</h2>
                <p className="section-description">See how dae would handle a request from this device. Read-only: no test traffic is sent and no settings are changed.</p>
                <div id="diagnostic-view"></div>
              </section>
            </div>

            <div id="manage-page" data-page="manage" hidden>
              <div id="manage-navigation"></div>
              <div id="manage-devices" role="tabpanel" aria-labelledby="manage-devices-tab" data-manage-section="devices">
                <div id="devices-locked" className="card">
                  <p className="access-required">Administrator access required</p>
                  <p id="devices-login-hint" className="muted">Log in above to manage other devices.</p>
                </div>
                <div id="managed-clients-view" hidden></div>
              </div>
              <div id="manage-outbounds" role="tabpanel" aria-labelledby="manage-outbounds-tab" data-manage-section="outbounds" hidden>
                <section className="card selectors-card" aria-labelledby="selectors-title">
                  <div className="card-heading">
                    <h2 id="selectors-title">Outbound Nodes</h2>
                    <span id="selector-count" className="count" hidden>Login required</span>
                  </div>
                  <p className="section-description">Choose a node for each outbound group. Changes affect all devices using that group.</p>
                  <div id="selectors-locked" className="empty-state">
                    <p id="access-required" className="access-required">Login required</p>
                    <p id="login-hint">Enter your API key above to view outbound groups and switch nodes.</p>
                  </div>
                  <div id="selectors" className="selector-list" hidden></div>
                </section>
              </div>
              <div id="manage-status" role="tabpanel" aria-labelledby="manage-status-tab" data-manage-section="status" hidden>
                <section id="global-status-view" className="card status-card" aria-labelledby="managed-global-traffic-title"></section>
              </div>
            </div>
          </fieldset>
        </main>

        <footer><span id="page-note">Routing changes may interrupt active connections.</span><span id="daemon-version" hidden></span></footer>
      </div>
      <div id="notifications"></div>
    </div>
  );
}
