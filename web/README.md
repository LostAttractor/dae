# dae Web

The browser application uses dae's HTTP API. This directory builds independently
of the daemon and Go toolchain. It requires Node.js 22.12+, npm and Make.
Application components use TypeScript/TSX. The Vite configuration, build tools
and tests are TypeScript as well; Node scripts run through the pinned `tsx` loader.

## Local development

Configure the running daemon's HTTP API address in `web/.env.local`:

```dotenv
DAE_API_URL=http://192.168.1.1:2023
```

From this directory, run:

```sh
npm ci
npm run dev
```

Open `http://127.0.0.1:5173/`. Vite serves source files and applies CSS updates
immediately. React components use Fast Refresh where supported; changes to the
application controllers reload the page. Editing frontend code does not rebuild
or restart dae. `make dev` also installs the pinned dependencies before starting
Vite. Use `npm run dev -- --port 5174` to select another local port.

`DAE_API_URL` can also be set in the command environment, which takes precedence
over `.env.local`. Use a literal IPv4 or bracketed IPv6 address, including the API
port. The local file is ignored by Git. Changing it restarts the development
server automatically. API keys belong in the page's existing login form.

The local server proxies `/api/`, `/ca.pem`, `/ca.cer` and `/ca.mobileconfig` to
dae. It checks the local request origin, translates Host and Origin for the
daemon, and preserves API headers and session cookies. It listens on loopback;
the daemon sees the development server's network connection, so device identity
and LAN permissions apply to the computer running Vite. Run Vite on the same
LAN computer as the browser when using device self-service.

Certificate trust and transparent MITM tests require a direct browser connection
to dae. The development page links to the running instance for those checks;
certificate downloads remain available locally. Development configuration is
excluded from production bundles.

Run `npm run typecheck` to check the browser and Node projects with TypeScript's
strict mode. Vite handles transpilation and hot updates; production builds also
run the type checker. `tsconfig.json` covers the browser and `tsconfig.node.json`
covers tools and test fixtures.

`src/api.generated.ts` is generated from `docs/api/openapi.json` and its local
references. Components and test fixtures derive their API field types from it.
After changing the API contract, run `npm run types:api`; `npm run types:check`
checks that the generated file matches the contract. Generated types are checked
in so the frontend build needs no Go toolchain or running daemon.

## Production build

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

Network Panel has two primary pages: **Overview** and **Setting**. Navigation
uses `/#overview`, `/#setting/devices`, `/#setting/selector` and
`/#setting/explain`. Overview is the default; unknown fragments return to
Overview. Direct links, refresh and browser Back/Forward work through the root
document. Setting remembers its selected section during internal navigation.

- **Overview** aggregates **Quick Setting**, **Device Setting** and **Status**.
  Quick Setting contains a **Selectors** subsection for frequently used outbound node selection. Device Setting
  groups the visiting device's routing memberships and HTTPS preferences. At
  viewport widths of 1024px and above, these cards occupy the left column, with
  device and authorized global status stacked in the right column. Narrower
  screens place status below the settings and use scope tabs.
- **Setting** has three sections: **Devices**, **Selector** and **Explain**.
  From 960px, a left sidebar selects the page shown on the right. Smaller screens
  use a horizontal tab bar above the content.
  Devices manages another MAC's memberships and HTTPS preferences; client groups
  load only while this authorized section is active. Selector provides node
  selection, connectivity tests and default restoration. Explain checks routing,
  DNS policy, cached records, outbound nodes and HTTP plugins, including rule
  explanations and membership comparisons. Analysis sends no target traffic and
  executes no scripts. Device inputs and explanation results survive navigation.

Quick Setting and Selector share one snapshot and mutation controller. Changing
a node in either view updates the same saved choice; the active view alone mounts
selector controls and lazily creates its node list. Navigation does not add API
reads or polling. Inactive pages and status scopes do not mount charts.

The API contract is documented in the dae repository at `docs/api/openapi.json`
and `docs/en/configuration/api-client.md`. Keep API requests in `src/api.ts` and
presentation in the frontend; this directory does not import daemon code.

`shell.tsx` mounts the page structure once. `app.ts` coordinates access, device
actions and refreshes; `navigation.tsx` owns page links, visibility, titles and history;
`setting.tsx` owns the responsive secondary navigation. React owns each interactive panel:
`selectors.tsx`, `diagnostics.tsx`, `trace.tsx`, `clients.tsx`, `mitm.tsx`, and
`status.tsx`. `traffic.tsx` supplies the Recharts chart, and `certificate-panel.tsx`
owns the certificate section's responsive disclosure state.

`react-view.ts` applies the shared Astryx Theme and provides the boundary between
controllers and React. Controllers update interactive panels through their view
APIs and may hide their hosts; React owns those panel descendants. The shell's
stable identity, login and certificate result fields are updated by their native
controllers. Disclosure state belongs to React. Commits finish before native
action completion restores focus. Picker positioning, focus and scrolling use
component refs; resize/scroll listeners exist only while the picker is open.

## Components and theme

The frontend uses [Astryx](https://astryx.atmeta.com/docs/getting-started) for
navigation, buttons, switches, fields, search, badges, feedback and disclosures.
Colors come from GitHub's
[Primer Primitives](https://github.com/primer/primitives) Light and Dark themes,
following the system preference. `theme.ts` maps Primer's semantic color tokens
to Astryx, including surfaces, controls, borders and interaction states. Existing
native fields, application layouts and charts use the same palette in `style.css`.
Fonts use the system stack; no fonts or scripts load from a CDN.

Vite generates the theme CSS and built theme object together. Astryx's static
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

`certificate.ts` runs the current browser's CA and interception challenges.

**Setting → Explain** checks connection routing, DNS policy, cached domain records,
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
Rules** shows each membership's On/Off state beside an Astryx `Switch` on the
right. The rectangular track is blue with a white thumb when on; when off it
has a neutral outline, a gray thumb and a muted circle. The input target is
48px by 44px. State labels are centered in equal-width slots, with a small
letter-spacing adjustment for On to balance the two words. Labels and switches
occupy shared columns so each row stays aligned. A separate arrow at the right
expands that rule's routing effects without changing its membership. Each arrow
has a 44px target and supports keyboard activation; multiple rules can stay open.
When space is limited, the rule name moves above the state, switch and arrow.
Changes disable controls until the request finishes;
the displayed state updates from the saved API response.
Multiple memberships can be active. Changes may interrupt active
connections, as indicated beside these actions. Routing effects load only for
expanded rules and refresh when the device context changes. Closing a rule discards
its pending response. Expanded details separate the proposed change, referenced
rules and explanatory notes with spacing and dividers. **Referenced** identifies
a client-group reference, not an evaluated match or routing result. Shared
`rules` entries appear once with a **Rules** badge; routing occurrences show
their **Policy** badge even while collapsed. DNAT expressions include their
target IP and optional port. Membership predicates show before/after values.
Rule expressions use a single-line summary while collapsed and wrap in full
when expanded. Labels and expressions keep the same first-line alignment in
both states, with vertical room for complete glyphs. The comparison button
occupies its own row. **Compare a target** opens Setting → Explain with
that proposed change and focuses the target field. Inputs and results are
preserved when switching pages.
The **Devices** section groups device lookup, routing membership and HTTPS module
settings into separate sections. Saved settings show membership and HTTPS states
as labels; the configuration default is distinct from an enabled/disabled override.
Changing the MAC address clears the previous device's result. Client groups load when this section is active and authorized;
without access, it shows a login prompt. The diagnostics contract lives in
`docs/api/diagnostics.json`; explanations never send target traffic or execute scripts.

`use-request.ts` associates asynchronous results and errors with their initiating
request. A new request, invalidation or component removal discards late replies.
Context reads and explanations have independent request state. Editing test inputs,
the analysis, identity scope or comparison invalidates the previous explanation;
device-context changes clear inherited evidence and comparisons. Losing
administrator access clears manual explanations and managed-device results.

The page header shows the visiting device's IP and MAC directly, with explicit
labels. Device settings address this MAC. An IP-only connection shows its IP and
an unavailable MAC; MAC-scoped controls remain unavailable. The daemon version
appears in the footer when administrator status is available.

**HTTPS Modules** shows its combined state in a badge beside the heading, such as
**Disabled (Default)** or **Enabled (Custom)**. Certificate installation and
browser verification sit inside this section.
They default to expanded in windows at least 768px wide and 600px tall, and
collapsed on smaller screens. Until the user toggles the section, this default
adapts to viewport changes. A manual choice is retained until the page is reloaded;
polling and navigation do not reset it.
The certificate name and fingerprint share an information block, followed by
the installation note and download buttons for the iOS profile, DER and PEM
formats. Browser verification uses a muted background, a heading and test action,
and two labelled results without row dividers. The results appear side by side
when space permits and stack on narrow screens.
Status emphasizes active connections and current upload/download rates. Below
each chart, **Connection statistics** and **Outbounds** are separate, initially
collapsed sections. Global status also has sibling **Domain Tables** and
**Plugins** sections, with counts and empty states. Cumulative totals, uptime and
direct fallback counts belong to Connection statistics. Each outbound group has
a compact name-and-count trigger; expanding it reveals its metrics and a named
node list. Long node lists scroll inside the group, leaving group headers and
the other sections in the normal page flow.
Device status continues polling without administrator access. Global status uses
the same authorization as selectors and is cleared on logout or expiry. The
visible document refreshes every two seconds; traffic rates use five-second
samples for up to one minute. Both status scopes consume the same reads,
without additional counters or polling. Counters cover userspace upstream paths,
including splice, rather than kernel passthrough or locally answered requests.
Scope tabs and mobile Setting tabs support arrow keys and Home/End, selecting the
focused tab. The desktop sidebar uses ordinary links with Tab and Enter.
Losing global access returns the narrow Overview to device traffic.

Traffic charts share a byte-per-second scale for upload (dashed purple) and
download (solid blue). The horizontal axis is relative to the latest completed
sample. Missing samples remain blank; a measured zero is plotted at zero.
Hover, touch or focus the chart and use the left/right arrow keys to inspect
samples. Polling updates the existing chart without replaying animations or
replacing keyboard focus. Empty histories show a waiting state. Logout and
device access loss unmount the corresponding chart.

Outbound summaries show the group name and node count. Expanding a group shows
its aggregate counters and nodes inside a height-limited, scrollable region.
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

With `global.api_key` configured, the header login form exchanges the key for an
HttpOnly, SameSite=Strict session cookie lasting seven days; the page never stores
the key in browser storage. Logout clears the cookie. Without a configured key,
verified direct LAN clients can read status and change selectors immediately.
The header shows LAN Access, with no login/logout or session cookie; every API
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

The shared “Network Panel” heading has an outlined access badge on its right,
with the access explanation and login controls below. On wide screens, the heading,
navigation, IP/MAC and refresh controls form one horizontal bar. Refresh uses a
36px minimum height, content width and the same metadata font size as its update time.
The device identity and refresh controls wrap together when space is limited.
On screens up to 760px, navigation and refresh share a row below the title,
followed by the device identity. Values and update errors wrap at larger preferred text sizes.

Overview / Setting navigation has a shared thin border and uses a subtle filled background for the active page;
resting links have no fill. A full-width divider separates the header from content.
Astryx `TopNav` and `TopNavItem` retain link navigation, touch and keyboard behavior.
Both pages and all Setting sections share a centered workspace up to 1440px;
switching pages preserves the workspace and navigation width. The header,
content and footer align within that workspace.

Setting uses Astryx `SideNav` / `SideNavItem` on desktop and `TabList` on smaller
screens. The sidebar occupies 180px, with a 24px gap before the content. Content
has no enclosing card border. Section headings, spacing and horizontal dividers
establish its hierarchy; device operations are stacked and node groups fill a
responsive grid. Borders mark controls, badges and discrete result groups.
Panels and labels wrap at larger preferred text sizes. Keep core behavior
independent of layout width.

Overview stacks Quick Setting and Device Setting cards in the settings column.
Selectors, Routing Rules and HTTPS Modules use the same subsection hierarchy.
Each selector pairs its group name with the selected node's health and latency
above the picker; node counts and Default / Custom state form a separate metadata
group. Long names and metadata wrap without truncating the heading. Full selector
tools retain monitoring and last-test details below the picker.
From 1024px, the settings and status
columns share a row, with more width allocated to settings. The status card uses
a muted background and stacks device status above global status with a divider.
Smaller screens stack status below settings and use scope tabs. Status metrics
wrap according to the panel width and preferred text size. Status stays visible
on every screen size. Content scrolls vertically
when the viewport is short. A stable scrollbar gutter keeps the content width
steady while panels expand and charts resize.

Use Astryx `Button`, `IconButton`, `Switch` and `TabList` for actions and view selection.
`Field` supplies labels and descriptions for native form controls, retaining
native validation, form submission and platform select menus. Node search uses
`TextInput` with a search icon and a clear button that restores input focus.
Navigation and ordinary feedback use text labels. Warnings use
an Astryx warning triangle and the Primer yellow attention palette; request errors
use a cross icon and the red danger palette. Device controls unavailable on an IP-only
connection are a warning, without a failed-update or retry message. Inline
request errors use `Banner`; unconfigured routing and outbound sections
use compact `EmptyState` messages. Native sections and forms provide the page
structure. Rectangular controls, cards, navigation items, badges and popovers
share the 4px `--radius` value through the component theme. Badges share a 1px
solid border; neutral badges have transparent backgrounds and muted text, while
semantic badges use matching Primer border, background and text colors.
Typography uses 1rem body text and .875rem metadata. Error foregrounds, backgrounds and borders share the Primer
danger palette. Use Astryx `Badge` for short states and settings sources; longer
verification results and monitoring descriptions remain wrapping text. Keep
quantities in `.count` and align related controls with `.status-row` / `.button-row`.
Node choices deliberately truncate; full names remain accessible. Avoid text
that repeats a heading or describes an obvious control. Retain warnings,
prerequisites, input constraints and limits needed to interpret results.

The selected navigation link identifies the page. The shared “Network Panel”
H1 receives focus after primary page navigation; secondary navigation retains
focus on its link or tab. Use H2 for page sections and cards, H3 for their
subsections, and H4 for selector groups inside Quick Setting. Status has less visual
emphasis than settings. Keep **Default / Custom**, **Use default**, and
**Monitoring** consistent across selectors and device settings; preserve configured
names and descriptions. Optional TLS hostname and identity inputs belong in
Advanced context. Expandable certificate, traffic, routing effects and
diagnostic sections use Astryx `Collapsible`; routing rows place their chevrons
at the right, while other sections use leading chevrons. Section
dividers distinguish related groups, and rules can be filtered by status.
Preview requests and outbound node lists are created only while expanded.
Outbound metrics pair values with
labels. Light/dark colors also apply to chart axes, series and tooltips.

Action feedback uses an Astryx toast at the bottom right without shifting page
content. Each new action replaces the previous notification. Success messages
close after five seconds, pausing on hover or focus; pending and error messages
remain until dismissed or replaced. Notifications have a close button and can be
reached with F6. Navigation has no branding block.

Refresh indicators show time since the last successful read and update while the
document is visible; hovering shows the local date and time. Errors remain visible
until a successful read. Explain identifies its read-only behavior beside its
heading. Routing warnings appear beside the affected controls; the footer holds
the daemon version.

## Browser checks

With Node.js 22.12+ and Chromium installed:

```sh
make test
# Or select a Chromium executable:
CHROMIUM=/path/to/chromium make test
```

`make test` checks the API type generation and both TypeScript projects before
running the development-server and browser checks.
Development-server checks use a minimal local API fixture to verify proxy
boundaries, login cookies, downloads and CSS updates over Vite's HMR connection.
Run these independently with `npm run test:dev`.

The browser test builds the production bundle, then uses Node's built-ins, a local API
fixture, and a temporary browser profile. Its protocol client uses Chromium's
type declarations; no running daemon or external test data is needed. It covers stale responses,
login/logout, live ordering and focus, a 1,000-node picker, probe/selection actions,
configuration defaults, description labels, timeouts, chart samples and keyboard
tooltips, access-loss recovery, and light/dark layouts from 320px to 2560px.
Text-only zoom checks all pages at twice the default size, including control
containment in narrow panels.
It also checks direct page links, browser history, mobile status,
simultaneous desktop traffic scopes, Setting tabs, shared quick/full selectors, keyboard traffic-scope
switching, independent membership switches and keyboard activation,
context/explanation requests, invalidation of late diagnostic and routing-preview
replies, membership-context changes and protected-result cleanup.
Fixture state and browser processes are cleaned up when the test exits. These
checks validate frontend behavior; daemon authorization has its own Go tests.

To additionally exercise real browser TLS acceptance/rejection, install OpenSSL
and NSS tools and supply `CERTUTIL=/path/to/certutil make test`. The test creates
an isolated HOME/NSS database, trusts a temporary CA there, and checks trusted
and untrusted HTTPS endpoints without certificate-error bypass flags. All trust
data is removed with the temporary browser profile.
