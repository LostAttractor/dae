# dae Web

The browser application uses dae's HTTP API. This directory builds independently
of the daemon and Go toolchain; it currently needs only Make and standard file
utilities.

```sh
make
```

`src/` contains the frontend source. The build replaces `dist/` with the public
bundle, including `index.html`. Set `DIST=/absolute/output/path` to choose another
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

`app.js` coordinates access, device actions and refreshes; `selectors.js` owns
the searchable node picker, keyboard navigation and connectivity-test controls.
`dom.js` contains the shared element/template lookups. These are native browser
modules, with no framework or bundler. The page requires a browser with native
Popover API support.

`status.js` renders MAC-attributed device and administrative global status;
`certificate.js` runs the current browser's CA and interception challenges.
Device status continues polling without administrator access. Global status uses
the same authorization as selectors and is cleared on logout or expiry. Visible
pages refresh every two seconds; traffic rates use five-second samples for up to
one minute. Counters cover userspace upstream paths, including splice, rather
than kernel passthrough or locally answered requests.

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

Selectors use compact searchable dropdowns with per-node connectivity tests,
a selected-node **Test** button and a one-shot **Test All** action. The group's
configuration-only `track_all: true` replaces these buttons with a read-only
**Monitoring all nodes** indicator. Dropdowns have a bounded, scrollable list, truncate
long names, and support arrow keys, Home/End and Escape. Candidate controls are
created only while the dropdown is open. All action buttons have visible borders,
including **Reset Default** and disabled buttons. The reset control and default
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

The page expands up to 1920px. At 1024px and above, global and device traffic
stack in the wider left column; selectors, device settings and HTTPS modules
stack independently on the right. Narrower screens stack both columns vertically,
with traffic before settings. Selector groups
wrap into columns as space permits, and traffic charts fill their panels.

Keep shared styles in `style.css`: 44px action controls with the same padding,
type and neutral outline; a single 4px radius; 14px body text and 12px metadata.
Node options can grow to fit their two-line content. Light/dark colors come from
the root palette; errors share one foreground, background and border treatment.
Use `.badge` for states and settings sources, `.count` for quantities, and
`.status-row` / `.button-row` for consistent alignment and spacing.

Use H1 for the page (24px), H2 for sections (18px), and H3 for selector groups
and certificate details (14px). Status messages are not headings. Headings and
action labels use title case; status text and explanations use sentence case.
Keep **Default / Custom**, **Reset Default**, and **Monitoring** consistent
across selectors and device settings; preserve configured names/descriptions.

## Browser checks

With Node.js 22+ and Chromium installed:

```sh
make test
# Or select a Chromium executable:
CHROMIUM=/path/to/chromium make test
```

The test uses Node's built-ins, a local API fixture, and a temporary browser
profile; no npm packages or running daemon are needed. It covers stale responses,
login/logout, live ordering and focus, a 1,000-node picker, probe/selection actions,
configuration defaults, description labels, timeouts, and mobile/dark layouts.
Fixture state and browser processes are cleaned up when the test exits. These
checks validate frontend behavior; daemon authorization has its own Go tests.

To additionally exercise real browser TLS acceptance/rejection, install OpenSSL
and NSS tools and supply `CERTUTIL=/path/to/certutil make test`. The test creates
an isolated HOME/NSS database, trusts a temporary CA there, and checks trusted
and untrusted HTTPS endpoints without certificate-error bypass flags. All trust
data is removed with the temporary browser profile.
