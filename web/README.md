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

The API contract is documented in the dae repository at `docs/api/openapi.json`
and `docs/en/configuration/api-client.md`. Keep API requests in `src/api.js` and
presentation in the frontend; this directory does not import daemon code.

`app.js` coordinates access, device actions and refreshes. React components own
the interactive panels: `selectors.jsx` renders searchable node pickers and
connectivity tests, `clients.jsx` renders device memberships, and `status.jsx`
renders traffic scopes and connection details. `traffic.jsx` supplies the
Recharts chart. Login and certificate controls use native DOM modules;
`dom.js` contains their element/template lookups.

`react-view.js` provides the boundary between native controllers and React.
Controllers update a panel through its view API and can hide its host; only
React creates or updates descendants of that host. Commits finish before native
action completion restores focus. Popover positioning, focus and scrolling use
component refs; resize/scroll listeners exist only while the picker is open.
New interactive panels follow these component boundaries.

esbuild bundles all JavaScript, including React and Recharts, into local static
assets without a runtime CDN dependency. The page requires a browser with native
Popover API support.

`certificate.js` runs the current browser's CA and interception challenges.

**Routing Rules** presents independent On/Off switches for this device's client
memberships; multiple memberships can be active.

The access toolbar shows the visiting device's IP beside its access badge;
expanding the IP reveals its MAC. The daemon version appears in the footer when
administrator status is available.

On desktop, Settings places routing rules, selectors and HTTPS settings in the
main column, with traffic in a sidebar. Smaller screens put all settings before
traffic. Below 1024px, traffic starts collapsed; wider screens start expanded.
Show/Hide overrides this default until a page reload, including across polling.
Collapsed traffic does not mount charts.
Certificate installation and browser verification expand inside **HTTPS Modules**.
The **Traffic** panel switches between **This Device** and **All Devices**, with
only the active scope's chart mounted. Arrow keys and Home/End navigate the tabs.
Connection details, uptime, domain tables and plugins are collapsed by default.
Device status continues polling without administrator access. Global status uses
the same authorization as selectors and is cleared on logout or expiry. Visible
pages refresh every two seconds; traffic rates use five-second samples for up to
one minute. Counters cover userspace upstream paths, including splice, rather
than kernel passthrough or locally answered requests.

Traffic charts share a byte-per-second scale for upload (dashed purple) and
download (solid teal). The horizontal axis is relative to the latest completed
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

Settings expands up to 1600px. At 1024px and above, it uses a wider left
column for controls and a right column for traffic. Narrower screens stack
settings before traffic.
Refresh indicators show elapsed time since the last successful read: just now,
then seconds, minutes, hours or days ago. They update while the document is visible;
hovering shows the full local date and time. Refresh errors and access messages
remain visible until the next successful read.
Selector groups
wrap into columns as space permits, and traffic charts fill their panels.
Traffic metrics use two columns on small screens and narrow desktop sidebars,
and three where space permits;
chart headings and legends wrap on narrow screens. Light and dark themes
apply to chart axes, series and tooltips as well as the surrounding controls.

Keep shared styles in `style.css`: action controls at least 2.75rem tall with the same padding,
type and neutral outline; a single 4px radius; 1rem body text and .875rem metadata
(16px and 14px at the browser's default size). Text and controls follow the user's
preferred font size. Paragraphs use a 1.55 line height; section descriptions and
result summaries have bounded line lengths. Selector columns require enough
space for readable names and actions, and wrap before they become cramped.
Node options can grow to fit their two-line content. Light/dark colors come from
the root palette; errors share one foreground, background and border treatment.
Use `.badge` for states and settings sources, `.count` for quantities, and
`.status-row` / `.button-row` for consistent alignment and spacing.

Use H1 for the page (1.75rem), H2 for sections (1.25rem), and H3 for selector groups
and certificate details (1rem). Status messages are not headings. Use short action
labels and sentences for explanations. Outbound traffic details pair each value
with its label instead of joining multiple metrics into a sentence.
Keep **Default / Custom**, **Use default**, and **Monitoring** consistent
across selectors and device settings; preserve configured names/descriptions.

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
Text-only zoom checks settings at twice the default size, including control
containment in narrow panels.
It also checks mobile traffic expansion, keyboard traffic-scope switching and
independent membership switches.
Fixture state and browser processes are cleaned up when the test exits. These
checks validate frontend behavior; daemon authorization has its own Go tests.

To additionally exercise real browser TLS acceptance/rejection, install OpenSSL
and NSS tools and supply `CERTUTIL=/path/to/certutil make test`. The test creates
an isolated HOME/NSS database, trusts a temporary CA there, and checks trusted
and untrusted HTTPS endpoints without certificate-error bypass flags. All trust
data is removed with the temporary browser profile.
