# dae Web

The browser application uses dae's HTTP API. This directory builds independently
of the daemon and Go toolchain. It requires Node.js 22+, npm and Make.

```sh
make
```

`src/` contains the frontend source. Make installs the dependencies pinned in
`package-lock.json` with `npm ci` when they change. The build replaces `dist/`
with the public bundle, including `index.html`. Set `DIST=/absolute/output/path` to choose another
build directory. Only deploy build output; development files stay outside it.

In the dae repository, `make web` writes the bundle to `build/web/` by default.
The daemon build copies that output into its embedding package. To update a
running installation independently, deploy the bundle and set `DAE_WEB_ROOT` to
its directory in the daemon's service environment.

The page is served at `http://ROUTER_IP:<api_port>/`. Use root-relative API paths
such as `/api/device`; `/api/`, `/ca.pem`, `/ca.cer` and `/ca.mobileconfig` belong
to the daemon. Assets can use subdirectories. Missing paths return `404`; the
server does not provide a single-page application routing fallback.

Navigation uses `/#overview`, `/#tracing` and `/#manage`. Overview is the
default; unknown fragments return to Overview. Direct links, refresh and browser
Back/Forward work through the root document. Inputs and results survive internal
navigation.

- **Overview** contains the visiting device's routing memberships and HTTPS module
  settings in separate, vertically stacked cards. At viewport widths of 1024px
  and above, settings occupy the left column and status occupies the right. Device
  and authorized global status appear one above the other within the right column.
  On narrower screens, status follows the settings and uses scope tabs. Status
  stays visible; inactive pages and scopes do not mount charts.
- **Tracing** checks connection routing, DNS policy, cached domain records,
  outbound nodes and HTTP plugins. It includes rule explanations and comparisons
  against a proposed device membership change. Checks are read-only: they send no
  target traffic and execute no scripts.
- **Manage** separates **Devices**, **Outbound nodes** and **Global status** into
  tabs. Only the selected section is displayed. Devices manages another MAC's
  memberships and HTTPS settings. Outbound node choices affect every device using
  that group. Global status uses the same snapshots as Overview. Client groups
  load only while the authorized Devices section is active. Global configuration
  is limited to the controls supported by the current HTTP API.

The API contract is documented in the dae repository at `docs/api/openapi.json`
and `docs/en/configuration/api-client.md`. Keep API requests in `src/api.js` and
presentation in the frontend; this directory does not import daemon code.

`shell.jsx` mounts the page structure once. `app.js` coordinates access, device
actions and refreshes; `navigation.js` owns page visibility, titles and history;
`manage.jsx` owns management section navigation. React owns each interactive panel:
`selectors.jsx`, `diagnostics.jsx`, `trace.jsx`, `clients.jsx`, `mitm.jsx`, and
`status.jsx`. `traffic.jsx` supplies the Recharts chart.

`react-view.js` applies the shared Astryx Theme and provides the boundary between
controllers and React. Controllers update panels through their view APIs and may
hide their hosts; only React updates the descendants. Commits finish before
native action completion restores focus. Login and certificate challenge state
remain in the existing controllers. Picker positioning, focus and scrolling use
component refs; resize/scroll listeners exist only while the picker is open.

## Components and theme

The frontend uses [Astryx](https://astryx.atmeta.com/docs/getting-started) for
buttons, membership switches and tab navigation. Colors come from GitHub's
[Primer Primitives](https://github.com/primer/primitives) Light and Dark themes,
following the system preference. `theme.js` maps Primer's semantic color tokens
to Astryx, including surfaces, controls, borders and interaction states. Existing
native fields, application layouts and charts use the same palette in `style.css`.
Fonts use the system stack; no fonts or scripts load from a CDN.

esbuild generates the theme CSS and built theme object together. Astryx's static
Layer positioning rules are emitted as `astryx-layers.css` and linked using its
stylesheet ID, so its runtime can reuse them under the daemon's `style-src 'self'`
CSP. This build adapter follows the pinned Astryx version. Deploy every generated
asset together. The frontend requires modern browser support for native popovers,
CSS scope and light/dark color values.

The pinned CLI provides component references:

```sh
npm run astryx -- component Button
npm run astryx -- component TabList
```

`certificate.js` runs the current browser's CA and interception challenges.

The **Tracing** page checks connection routing, DNS policy, cached domain records,
outbound nodes and HTTP plugins. Results start with a plain-language conclusion,
the outbound and destination, followed by any missing information and actions to
complete it. Kernel direct and userspace direct are distinct outcomes; incomplete
results never present a provisional outbound as a confirmed route. A hostname
does not resolve itself during a check. Retained candidate IPs can be selected
and checked individually, using the verified source address family. This does not
create a kernel domain mapping. Rule traces, cached records, technical fields and
raw responses are collapsed by default; the trace can be filtered by rule status.
Membership comparisons show current and proposed results side by side on wide
screens and stacked on smaller screens. **Routing
Rules** presents independent On/Off switches for this device's client memberships;
multiple memberships can be active. **Preview Routing Changes** loads impact
for one selected option when expanded. **Compare a target** opens Tracing with
that proposed change and focuses the target field. Inputs and results are
preserved when switching pages.
The **Devices** section groups device lookup, routing membership and HTTPS module
settings into separate sections. Saved settings show membership and HTTPS states
as labels; the configuration default is distinct from an enabled/disabled override.
Changing the MAC address clears the previous device's result. Client groups load when this section is active and authorized;
without access, it shows a login prompt. The diagnostics contract lives in
`docs/api/diagnostics.json`; explanations never send target traffic or execute scripts.

`use-request.js` associates asynchronous results and errors with their initiating
request. A new request, invalidation or component removal discards late replies.
Context reads and explanations have independent request state. Editing test inputs,
the analysis, identity scope or comparison invalidates the previous explanation;
device-context changes clear inherited evidence and comparisons. Losing
administrator access clears manual explanations and managed-device results.

The access toolbar shows the visiting device's IP beside its access badge;
expanding the IP reveals its MAC. The daemon version appears in the footer when
administrator status is available.

Certificate installation and browser verification expand inside **HTTPS Modules**.
Status emphasizes active connections and current upload/download rates. Cumulative
traffic, total connections, uptime, domain tables and plugins are available in
the initially collapsed connection details.
Device status continues polling without administrator access. Global status uses
the same authorization as selectors and is cleared on logout or expiry. The
visible document refreshes every two seconds; traffic rates use five-second
samples for up to one minute. Both status presentations consume the same reads,
without additional counters or polling. Counters cover userspace upstream paths,
including splice, rather than kernel passthrough or locally answered requests.
Scope tabs and management tabs support arrow keys and Home/End, selecting the
focused tab. Losing global access returns the narrow Overview to device traffic.

Traffic charts share a byte-per-second scale for upload (dashed purple) and
download (solid blue). The horizontal axis is relative to the latest completed
sample. Missing samples remain blank; a measured zero is plotted at zero.
Hover, touch or focus the chart and use the left/right arrow keys to inspect
samples. Polling updates the existing chart without replaying animations or
replacing keyboard focus. Empty histories show a waiting state. Logout and
device access loss unmount the corresponding chart.

Outbound summaries show aggregate counters and node counts. Each outbound's
node list expands independently inside a height-limited, scrollable region.
Polling preserves expanded groups, keyboard focus and the list's scroll position;
collapsed groups do not retain their node rows.

CA challenges use HTTPS on the API port; MITM challenges use virtual IP:443
origins advertised by the API. The page's CSP permits the test endpoints and paths, with exact IPv4 hosts. IPv6
uses a CSP host wildcard because Chromium rejects literal IPv6 host sources;
the request helper and daemon still require the exact advertised endpoint. Requests omit credentials, reject
redirects, disable caching and use ordinary browser TLS verification. A positive
MITM result requires both a matching browser proof and the daemon's interception
observation. Virtual targets have no upstream service; incomplete verification
cannot distinguish bypass from unreachable traffic. Results apply only to
this browser and reset on changes to device identity, MITM setting, CA or test
generation. Verification failures are not assumed to mean the CA is uninstalled.

With `global.api_key` configured, the top toolbar exchanges the key for an
HttpOnly, SameSite=Strict session cookie lasting seven days; the page never stores
the key in browser storage. Logout clears the cookie. Without a configured key,
verified direct LAN clients can read status and change selectors immediately.
The toolbar shows LAN access, with no login/logout or session cookie; every API
request revalidates LAN identity. The selectors response's `auth_mode` identifies
`api_key`, `lan` or `unix` access. Device self-service always requires direct LAN
identification. Public certificate downloads are available without login.

**Outbound Nodes** uses searchable dropdowns with per-node connectivity tests,
a selected-node **Test** button and a one-shot **Test All** action. The group's
configuration-only `track_all: true` replaces these buttons with a read-only
**Monitoring all nodes** indicator. Dropdowns have a bounded, scrollable list, truncate
long names, and support arrow keys, Home/End and Escape. Candidate controls are
created only while the dropdown is open. All action buttons have visible borders,
including **Use default** and disabled buttons. The reset control and default
labels appear only when `default_node_id` is present (explicit `selector(n)`).
Only the selected node is monitored by default. The page shows untested,
testing, healthy and unavailable states separately, with last-test times.
Visible, authorized pages poll selector state every two seconds without replacing
the search input or focused node controls. Tests use `POST /api/probes` with
`outbound` and optional `node_id`; `202` is acceptance, followed by selector polling.
Tracking is read from `SelectorState.track_all`, never changed through the API.

User actions invalidate outstanding selector reads. Both successful and failed
responses are checked for freshness before changing access or rendering state.
Polling preserves candidate controls and focus, follows configuration order,
and reports recovery after a failed refresh. A current authorization failure
clears protected state and stops polling; it is not reported as a retryable error.
Keyboard focus returns to the relevant control after an action. Requests time out after 15 seconds;
mutations are never retried automatically.

## UI conventions

The shared “Network Settings” heading and navigation share a header: the title
and current page description sit on the left, and navigation aligns to the right.
On screens up to 760px wide, navigation occupies a full row below the heading,
with three equal-width touch targets. A horizontal divider separates this header from the access
toolbar. The current page uses a stronger label and a short underline. Overview
and Manage use a centered workspace up to 1440px; Tracing uses up to 1200px.
The header, access toolbar, content and footer align within that workspace.
The access card groups device identity, access state and session information, with
refresh actions on the right or a separate row on smaller screens. Settings
precede status in reading order. Management tabs avoid stacking
unrelated controls; node groups fill a responsive grid within their section.
Panels and labels wrap at larger preferred text sizes. Keep core behavior
independent of layout width.

Overview uses separate bordered cards for routing and HTTPS settings. The cards
stack vertically within the settings column. From 1024px, the settings and status
columns share a row, with more width allocated to settings. The status card uses
a muted background and stacks device status above global status with a divider.
Smaller screens stack status below settings and use scope tabs. Status metrics
wrap according to the panel width and preferred text size. Status stays visible
on every screen size. Content scrolls vertically
when the viewport is short. A stable scrollbar gutter keeps the content width
steady while panels expand and charts resize.

Use Astryx controls for actions and tabs, and native semantic sections and forms
for application structure. Shared styles use the theme's 2px corner radius,
1rem body text and .875rem metadata. Error foregrounds, backgrounds and borders
share the Primer danger palette. Use `.badge` for states and settings sources,
`.count` for quantities, and `.status-row` / `.button-row` for consistent alignment.
Only node names deliberately truncate; full names remain accessible.

The selected navigation link identifies the page. The shared “Network Settings”
H1 receives focus after page navigation. The access toolbar follows it;
use H2 for settings and H3 for groups. Status has less visual
emphasis than settings. Keep **Default / Custom**, **Use default**, and
**Monitoring** consistent across selectors and device settings; preserve configured
names and descriptions. Optional TLS hostname and identity inputs belong in
Advanced context. Diagnostic disclosures use shaded headers, state badges and
nested guides; rules can be filtered by status. Outbound metrics pair values with
labels. Light/dark colors also apply to chart axes, series and tooltips.

Action feedback uses an Astryx toast at the bottom right without shifting page
content. Each new action replaces the previous notification. Success messages
close after five seconds, pausing on hover or focus; pending and error messages
remain until dismissed or replaced. Notifications have a close button and can be
reached with F6. Navigation has no branding block.

Refresh indicators show time since the last successful read and update while the
document is visible; hovering shows the local date and time. Errors remain visible
until a successful read. Tracing's footer describes read-only analysis; Overview
and Manage describe when changes take effect.

## Browser checks

With Node.js 22+ and Chromium installed:

```sh
make test
# Or select a Chromium executable:
CHROMIUM=/path/to/chromium make test
```

The test builds the production bundle, then uses Node's built-ins, a local API
fixture, and a temporary browser profile; no additional test packages or running
daemon are needed. It covers stale responses,
login/logout, live ordering and focus, a 1,000-node picker, probe/selection actions,
configuration defaults, description labels, timeouts, chart samples and keyboard
tooltips, access-loss recovery, and light/dark layouts from 320px to 2560px.
Text-only zoom checks all pages at twice the default size, including control
containment in narrow panels.
It also checks direct page links, browser history, mobile status,
simultaneous desktop traffic scopes, management tabs, keyboard traffic-scope
switching, independent membership switches,
context/explanation requests, invalidation of late diagnostic and routing-preview
replies, membership-context changes and protected-result cleanup.
Fixture state and browser processes are cleaned up when the test exits. These
checks validate frontend behavior; daemon authorization has its own Go tests.

To additionally exercise real browser TLS acceptance/rejection, install OpenSSL
and NSS tools and supply `CERTUTIL=/path/to/certutil make test`. The test creates
an isolated HOME/NSS database, trusts a temporary CA there, and checks trusted
and untrusted HTTPS endpoints without certificate-error bypass flags. All trust
data is removed with the temporary browser profile.
