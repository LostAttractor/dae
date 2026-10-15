# dae Web

The browser application uses dae's HTTP API. This directory builds independently
of the daemon and Go toolchain. It requires Node.js 22.13+, pnpm and Make.
Application components use TypeScript/TSX. The Vite configuration, build tools
and tests are TypeScript as well; Node scripts run through the pinned `tsx` loader.

The repository root and `web/` share `pnpm-workspace.yaml` and `pnpm-lock.yaml`.
Keep these files and the root `package.json` when building the frontend without
the daemon. In the Nix development shell, pnpm is available through Corepack.
On other systems with Corepack installed, run `corepack enable pnpm` once;
the root `package.json` selects the pnpm version for local builds, CI and Docker.

## Local development

Configure the running daemon's HTTP API address in `web/.env.local`:

```dotenv
DAE_API_URL=http://192.168.1.1:2023
```

From this directory, run:

```sh
pnpm install --frozen-lockfile
pnpm run dev
```

Open `http://127.0.0.1:5173/`. Vite serves source files and applies CSS updates
immediately. React components use Fast Refresh where supported; changes to the
application controllers reload the page. Editing frontend code does not rebuild
or restart dae. `make dev` also installs the pinned dependencies before starting
Vite. Use `pnpm run dev --port 5174` to select another local port.

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

HTTPS acceptance and transparent MITM tests require a direct browser connection
to dae. The development page links to the running instance for those checks;
certificate downloads remain available locally. Development configuration is
excluded from production bundles.

Run `pnpm run typecheck` to check the browser and Node projects with TypeScript's
strict mode. Vite handles transpilation and hot updates; production builds also
run the type checker. `tsconfig.json` covers the browser and `tsconfig.node.json`
covers tools and test fixtures.

`src/api.generated.ts` is generated from `docs/api/openapi.json` and its local
references. Components and test fixtures derive their API field types from it.
After changing the API contract, run `pnpm run types:api`; `pnpm run types:check`
checks that the generated file matches the contract. Generated types are checked
in so the frontend build needs no Go toolchain or running daemon.

## Production build

```sh
make
```

`src/` contains the frontend source. Make runs `pnpm install --frozen-lockfile`
against the root lockfile before each build, reusing already installed packages.
The build replaces `dist/`
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

Deploy all generated chunks and `.gz` sidecars together. Content-hashed JS/CSS
under `assets/` are cached for one year; HTML and unhashed files are not cached.
Never change the contents of an existing hashed asset name. Charts load on demand,
so retain older hashed assets if open pages must continue working across updates.

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
  From 768px, a sidebar beside the content lists the sections; narrower screens
  use a tab bar above the content.
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
`setting.tsx` owns the secondary navigation. React owns each interactive panel:
`selectors.tsx`, `diagnostics.tsx`, `trace.tsx`, `clients.tsx`, `mitm.tsx`, and
`status.tsx`. `traffic.tsx` supplies the Recharts chart, and `certificate-panel.tsx`
owns the certificate section's responsive disclosure state.

`react-view.ts` provides the boundary between controllers and React and disables
Base UI's inline style elements, which the daemon's CSP rejects. Controllers update interactive panels through their view
APIs and may hide their hosts; React owns those panel descendants. The shell's
stable identity, login and certificate result fields are updated by their native
controllers. Disclosure state belongs to React. Commits finish before native
action completion restores focus. Picker positioning, focus and scrolling use
component refs; resize/scroll listeners exist only while the picker is open.

## Components and theme

The interface uses [Kumo](https://kumo-ui.com), the component library and design
system behind Cloudflare's dashboard, with [Phosphor](https://phosphoricons.com)
icons. Kumo builds on [Base UI](https://base-ui.com), which supplies keyboard,
focus and screen-reader behavior. Kumo owns the palette, typography, spacing and
component appearance; the application does not override its tokens. Layouts use
[Tailwind CSS](https://tailwindcss.com) utility classes in the components, and
`style.css` holds only rules that utilities cannot express. Light and dark modes
follow the system preference: `color-mode.ts` sets the `data-mode` attribute
that selects Kumo's palette. Traffic charts use Kumo's categorical chart colors.
Fonts use the system stack; no fonts or scripts load from a CDN.
[DESIGN.md](DESIGN.md) holds the visual rules: surfaces, lines, spacing and
alignment, type roles and the choice of controls.

The Tailwind Vite plugin compiles utilities from the application and Kumo's
published components into one stylesheet. It finds utilities as complete tokens in
the source, so write each class literally and separate it from template
expressions: `gap-5 ${extra}`, never `gap-5${extra}`. Base UI normally injects a small
`<style>` element for popup scroll locking; `react-view.ts` disables it through
Kumo's `CSPProvider`, and `style.css` carries that rule so the daemon's
`style-src 'self'` CSP holds. The browser checks fail on any CSP violation.
Deploy every generated asset together. The frontend requires browsers supported
by Tailwind CSS v4.

Component references and examples are at <https://kumo-ui.com>.

`certificate.ts` runs the current browser's CA trust and interception challenges.

**Setting → Explain** checks connection routing, DNS policy, cached domain records,
outbound nodes and HTTP plugins. Results start with a plain-language conclusion,
the outbound and destination, followed by any missing information and actions to
complete it. Kernel direct and userspace direct are distinct outcomes; incomplete
results never present a provisional outbound as a confirmed route. A hostname
does not resolve itself during a check. Retained candidate IPs can be selected
and checked individually, using the verified source address family. This does not
create a kernel domain mapping. Rule traces, cached records, technical fields and
raw responses are collapsed by default; the trace can be filtered by rule status.
Expanded sections grow with the page: rule traces, node lists, cached records and
raw responses never scroll inside their section. The note that a check applies to
new connections sits under the Result heading, since it qualifies every result.
The outcome card stays on the base surface; an amber ring and warning icon mark an
incomplete result, and a red ring and prohibition icon mark a blocked connection.
Membership comparisons show current and proposed results side by side on wide
screens and stacked on smaller screens. **Routing
Rules** shows each membership's On/Off state beside a Kumo `Switch` on the
right; the adjacent label carries the state without relying on color. A label
around the switch extends its target to 48px by 44px. State labels are centered
in equal-width slots. Labels and switches
occupy shared columns so each row stays aligned. A separate arrow at the right
expands that rule's routing effects without changing its membership. Each arrow
has a 36px target and supports keyboard activation; multiple rules can stay open.
When space is limited, the rule name moves above the state, switch and arrow.
Changes disable controls until the request finishes;
the displayed state updates from the saved API response.
Multiple memberships can be active. Changes may interrupt active
connections, as a warning under the **Routing Rules** label states. Routing effects load only for
expanded rules and refresh when the device context changes. Closing a rule discards
its pending response. Expanded details separate the proposed change, referenced
rules and explanatory notes with spacing and dividers. **Referenced** identifies
a client-group reference, not an evaluated match or routing result. A small policy
indicator beside the rule status is green for **Applies**, gray for **Does not
apply** and amber for **Unknown**. Its accessible label and hover text identify
the policy and state. Expanded details show **Rules** and the full **Policy**
badge in a separate row. An applicable policy does not establish a rule match; conditions
and earlier decisions still matter. Missing ingress with multiple active policies
leaves applicability unknown.
Shared fragments retain their policy occurrences; global system/plugin references
appear once. DNAT expressions include their
target IP and optional port. Membership predicates show before/after values.
Rule expressions use a single-line summary while collapsed and wrap in full
when expanded. Labels and expressions keep the same first-line alignment in
both states, with vertical room for complete glyphs. The comparison button
occupies its own row. **Compare a target** opens Setting → Explain with
that proposed change and focuses the target field. Inputs and results are
preserved when switching pages.
The **Devices** section looks up another device by MAC, then shows its settings
with the same controls as Overview: a switch row per routing rule and the
three-way HTTPS module choice. Its router default depends on the source IP the
device connects from, which the page cannot see, so that choice reads **Router
default** without a value. Each change saves for the looked-up MAC and reloads its
settings in place, keeping focus on the changed control. Changing the MAC address
clears the previous device's result; without access, the section shows a login prompt. The diagnostics contract lives in
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

**HTTPS Modules** offers one choice among **Router default (On/Off)**, **On** and
**Off**; the API reports the router default, and choosing it clears the device
override. Without a trusted CA, interception breaks the device's HTTPS
connections, so the section tracks this browser's CA test between its heading and
the choice: an amber warning banner until the CA is verified, a green line once it
is, and a red alert with **Test again** in the banner's place when modules are on
and verification failed. The Devices page shows the same amber banner for the
looked-up device. While modules are on,
the page runs the certificate test by itself when it finds them on, when they are
turned on and when the device or CA changes; these runs report on the page without
a toast. The development server cannot reach the test endpoints, so it keeps the
warning. Certificate installation and
browser verification occupy a separate subsection and remain available without MITM or a device MAC.
They default to expanded in viewports at least 768px wide and 600px tall, and
collapsed on smaller screens. Until the user toggles the section, this default
adapts to viewport changes. A manual choice is retained until the page is reloaded;
polling and navigation do not reset it.
The certificate name shares a row with one **Download** menu listing the
configuration profile, DER and PEM formats with where each is used; the profile
opens normally so Safari can offer to install it. The fingerprint and installation
note follow. Browser verification is a framed block with a heading, a test action
and two labelled results shown as tinted pills. The results appear side by side
when space permits and stack on narrow screens.
Status emphasizes active connections and current upload/download rates. Below
each chart, **Connection statistics** and **Outbounds** are separate, initially
collapsed sections. Global status also has sibling **Domain Tables** and
**Plugins** sections, with counts and empty states. Cumulative totals, uptime and
direct fallback counts belong to Connection statistics. Outbound groups are rows
of one framed list, each with a compact name-and-count trigger; expanding a row
reveals its metrics and a named node list. Long node lists scroll inside the group, leaving group headers and
the other sections in the normal page flow.
Device status continues polling without administrator access. Global status uses
the same authorization as selectors and is cleared on logout or expiry. The
visible document refreshes every two seconds; traffic rates use five-second
samples for up to one minute. Both status scopes consume the same reads,
without additional counters or polling. Counters cover userspace upstream paths,
including splice, rather than kernel passthrough or locally answered requests.
Scope tabs and the narrow-screen Setting tabs support arrow keys and Home/End,
selecting the focused tab. Setting sections are links in both forms, so each keeps
its address; the sidebar is reached with Tab, followed with Enter, and marks the
current section with `aria-current="page"`.
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

CA verification sends a same-origin `POST /api/certificate/tests` to issue a
temporary certificate and new key held only in memory. It then reads
`/api/certificate/tests/{id}` over HTTPS on the same API port and checks the
challenge ID and CA fingerprint. A proof requires this or a newer challenge
certificate for the initiating source/router IP pair. Management certificates
and older challenge connections receive `409` and close; the browser retries up
to eight times within a shared ten-second deadline. A previously accepted
management certificate warning cannot validate the temporary leaf. This works
from HTTP and HTTPS pages, independently of device identity and MITM state.
Success consumes the challenge; unfinished challenges expire after one minute.
Each source IP may have at most 8 pending challenges, with a global limit of 64;
excess requests return `429`. Certificate validity includes five extra minutes
for client clock skew, capped by CA expiry, without extending the challenge deadline.
Once none remain for the address pair, new connections use the original
management certificate again. Clients sharing a source IP share this temporary
selection; other source IPs are unaffected. The daemon initializes a persistent
CA when needed. Management certificates and keys also persist; tests never
rewrite them, and ordinary restarts reuse them while discarding all challenges.
HTTP and HTTPS serve the same page and API; only the challenge's HTTPS GET permits
the initiating HTTP setup page at the same IP and port to read across protocols.
Ordinary `/api/certificate` metadata remains same-origin.

MITM challenges use virtual IP:443 origins advertised by the API. The page's CSP permits the test endpoints and paths, with exact IPv4 hosts. IPv6
uses a CSP host wildcard because Chromium rejects literal IPv6 host sources;
the request helper and daemon still require the exact advertised endpoint. Requests omit credentials, reject
redirects, disable caching and use ordinary browser TLS verification. A positive
MITM result requires both a matching browser proof and the daemon's interception
observation. Virtual targets have no upstream service; incomplete verification
cannot distinguish bypass from unreachable traffic. Results apply only to
this browser. CA changes reset both results; changes to device identity, MITM setting or test
generation reset only interception results. Success does not prove system-wide
CA installation. Verification failures are not assumed to mean the CA is
uninstalled. Users relying on a management certificate exception may temporarily
lose new HTTPS connections while a challenge is pending; the page offers an
HTTP setup link to install and trust the CA.

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

The shared “Network Panel” heading has a neutral access badge on its right,
with the access explanation and login controls below. The header is a full-width
surface bar above the page canvas. On wide screens, the heading, navigation,
IP/MAC and refresh controls form one horizontal row.
The device identity and refresh controls wrap together when space is limited.
Below 768px, navigation and refresh share a row below the title,
followed by the device identity.

Overview / Setting navigation uses Kumo's segmented `Tabs`, rendered as links so
direct addresses, Back/Forward and keyboard selection keep working. The header
bar's bottom border separates it from content. Both pages and all Setting
sections share a centered workspace up to 1440px; switching pages preserves the
workspace and navigation width. The header, content and footer align within that
workspace.

From 768px, Setting places a sticky section sidebar beside the content, so the
section list stays in view beside long results. Its links use the item styles of
Kumo's dashboard sidebar menu, set directly on the page canvas without a panel or
border; Kumo's `Sidebar` module itself is not used, since it also bundles tooltips,
scroll areas and resizing, about 40 KB, for three links. The section card is thus
the only framed surface beside it. Each section link has a dimmed icon and a
13px label, and the current section has a filled background (the recessed surface
in light mode, where Kumo's tint barely differs from the canvas); a focus ring
marks the keyboard focus on any item, including the current one. Narrower screens use Kumo's
underline `Tabs` above the content. Each section is a Kumo `LayerCard`, like the
Overview cards; device operations are stacked and node groups fill a responsive
grid of framed tiles that share a height within each row. Keep core behavior
independent of layout width.

Overview stacks Quick Setting and Device Setting cards in the settings column.
Selectors, Routing Rules and HTTPS Modules use the same subsection hierarchy,
separated by hairline dividers. Each selector tile pairs its group name with the
selected node's health and latency above the picker; node counts and
Default / Custom state form a separate metadata group. Long names and metadata
wrap without truncating the heading. Full selector tools retain monitoring and
last-test details below the picker.
From 1024px, the settings and status
columns share a row, with more width allocated to settings. The status card
stacks device status above global status with a divider.
Smaller screens stack status below settings and use scope tabs. Status metrics
wrap according to the panel width. Status stays visible on every screen size.
Content scrolls vertically when the viewport is short. A stable scrollbar gutter
keeps the content width steady while panels expand and charts resize.

Node search uses `InputGroup` with a search icon and
a clear button that restores input focus. The node menu is a Kumo `Popover`
spanning the picker row, lifted like Kumo's menus; its trigger matches `Select`. It renders into a layer at the end of the controls
fieldset, so it paints above the cards and is disabled with the other controls
while an action runs. Opening it centers the selected node.
`notice.tsx` pairs Kumo's warning, error and success colors with Phosphor icons for
single-line notices, banners and notifications, centering each icon on its text. Device controls unavailable on an IP-only
connection are a warning, without a failed-update or retry message. Longer verification results and monitoring descriptions remain
wrapping text. Node choices deliberately truncate; full names remain accessible.
Avoid text that repeats a heading or describes an obvious control. Retain
warnings, prerequisites, input constraints and limits needed to interpret
results.

The selected navigation link identifies the page. The shared “Network Panel”
H1 receives focus after primary page navigation; secondary navigation retains
focus on its tab. Use H2 for page sections and cards, H3 for their
subsections, and H4 for selector groups inside Quick Setting. Keep **Default / Custom**, **Use default**, and
**Monitoring** consistent across selectors and device settings; preserve configured
names and descriptions. Optional TLS hostname and identity inputs belong in
Advanced context. Expandable certificate, traffic, routing effects and
diagnostic sections use Kumo's `Collapsible` with a trailing caret. Sections open
flush with their heading and grow with their content; nested details, such as the
destination list and response JSON, use Kumo's indented panel. Collapsed
content stays in the document; previews and outbound node lists are created only
while expanded. Section dividers distinguish related groups, and rules can be
filtered by status. Outbound metrics pair values with labels. Light/dark colors
also apply to chart axes, series and tooltips.

Action feedback uses a Kumo toast at the bottom right without shifting page
content. Each new action replaces the previous notification. Success messages
close after five seconds, pausing on hover or focus; pending and error messages
remain until dismissed or replaced. Errors are announced assertively.
Notifications have a close button and can be reached with F6. Navigation has no
branding block.

Refresh indicators show time since the last successful read and update while the
document is visible; hovering shows the local date and time. Errors remain visible
until a successful read. Explain identifies its read-only behavior beside its
heading. Routing warnings appear beside the affected controls; the footer holds
the daemon version.

## Browser checks

With Node.js 22.13+, Chromium, OpenSSL and NSS `certutil` installed:

```sh
make test
# Or select a Chromium executable:
CHROMIUM=/path/to/chromium make test
```

`make test` checks the API type generation and both TypeScript projects before
running the development-server and browser checks.
Development-server checks use a minimal local API fixture to verify proxy
boundaries, login cookies, downloads and CSS updates over Vite's HMR connection.
Run these independently with `pnpm run test:dev`.

The browser test builds the production bundle, then uses Node's built-ins, a local API
fixture, and a temporary browser profile. Its protocol client uses Chromium's
type declarations; no running daemon or external test data is needed. It covers stale responses,
login/logout, live ordering and focus, a 1,000-node picker, probe/selection actions,
configuration defaults, description labels, timeouts, chart samples and keyboard
tooltips, access-loss recovery, and light/dark layouts from 320px to 2560px.
Every page is checked for CSP violations. Headless Chromium reports no pointing
device, so the test launches it with an emulated mouse; touch emulation covers
coarse pointers.
It also checks direct page links, browser history, mobile status,
simultaneous desktop traffic scopes, the Setting sidebar and narrow-screen tabs, shared quick/full selectors, keyboard traffic-scope
switching, independent membership switches and keyboard activation,
context/explanation requests, invalidation of late diagnostic and routing-preview
replies, membership-context changes and protected-result cleanup.
Fixture state and browser processes are cleaned up when the test exits. These
checks validate frontend behavior; daemon authorization has its own Go tests.

The Nix development shell provides OpenSSL and NSS tools for real browser
TLS acceptance/rejection checks. Outside that shell, install `openssl` and NSS
`certutil` on `PATH` before running `make test`. The test creates
an isolated HOME/NSS database, trusts a temporary CA there, and checks trusted
and untrusted HTTPS endpoints without certificate-error bypass flags. All trust
data is removed with the temporary browser profile.
