import { Button } from "@astryxdesign/core/Button";
import { createView } from "./react-view.js";

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
          <nav className="page-nav" aria-label="Pages">
            <a href="#overview" aria-current="page">Overview</a>
            <a href="#tracing">Tracing</a>
            <a href="#manage">Manage</a>
          </nav>
        </header>

        <main className="page-content" aria-labelledby="page-title">
          <fieldset id="controls" aria-label="Network controls">
            <div className="toolbar card">
              <div className="access-context">
                <div className="access-line">
                  <span id="access-title" className="badge" aria-describedby="access-description">Guest</span>
                  <details className="device-identity">
                    <summary id="identity">Identifying your device…</summary>
                    <span id="device-mac" className="muted"></span>
                  </details>
                </div>
                <form id="login-form" className="login-form">
                  <div className="key-field">
                    <label htmlFor="api-key">API Key</label>
                    <input id="api-key" name="api-key" type="password" autoComplete="current-password" spellCheck={false} placeholder="Enter your API key" required />
                  </div>
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
                  <p className="section-description">Apply to this device. Multiple options can be enabled.</p>
                  <div id="sets" className="set-list"></div>
                </section>

                <section className="card" aria-labelledby="https-title">
                  <h2 id="https-title">HTTPS Modules</h2>
                  <p className="section-description">Manage HTTPS modules for this device.</p>
                  <div id="mitm" className="mitm-state"></div>
                  <details id="certificate-panel" className="certificate-panel" hidden>
                    <summary>Certificate &amp; browser verification</summary>
                    <p>Verify the CA fingerprint on your router, then install and trust the certificate before enabling modules.</p>
                    <div id="certificate" className="code-block"></div>
                    <div className="download-links"><a href="/ca.mobileconfig">iOS Profile</a><a href="/ca.cer">DER Certificate</a><a href="/ca.pem">PEM Certificate</a></div>
                    <div id="certificate-test-panel" hidden>
                      <Button label="Test Certificate" id="test-certificate" type="button" />
                      <dl className="certificate-results">
                        <dt>Browser trusts the certificate</dt><dd><span id="certificate-trust-result" className="badge">Not tested</span></dd>
                        <dt>HTTPS interception works</dt><dd><span id="certificate-mitm-result" className="badge">Not tested</span></dd>
                      </dl>
                      <p id="certificate-test-info" className="code-block">Results apply to this browser only.</p>
                    </div>
                  </details>
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
                  <p className="badge">Administrator access required</p>
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
                    <p id="access-required" className="badge">Login required</p>
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

        <footer><span id="page-note">Changes apply to new connections.</span><span id="daemon-version" hidden></span></footer>
      </div>
      <div id="notifications"></div>
    </div>
  );
}
