# dae Web design rules

These rules keep the panel visually consistent. [Kumo](https://kumo-ui.com), the
design system behind Cloudflare's dashboard, owns the tokens: palette, type scale,
radii, shadows and component appearance. These rules decide how Kumo's pieces are
combined. Shared class recipes live in `src/ui.ts`; use them rather than writing
new borders, fills or shadows, and do not override Kumo tokens or add colors.

## Principles

- **One frame per level.** Spacing, hairline dividers and type establish hierarchy
  before frames do. Never frame a block inside another frame.
- **The same job looks the same.** Every single-choice trigger looks like Kumo's
  `Select`; every section name uses the same text role; every list uses the same
  rows.
- **Content grows with the page.** Expanding a section lengthens the page. Inner
  scrolling is limited to the node menu and long Status node lists.
- **Align to the content edge.** Inside a card, titles, disclosure triggers, list
  frames and code blocks share one left edge.

## Surfaces

| Surface | Use | Recipe |
| --- | --- | --- |
| Canvas | Page background | Kumo canvas |
| Card | Each top-level section | Kumo `LayerCard`: title strip, body `p-4 md:p-5` |
| Frame | A self-contained block in a card: selector tile, login prompt, browser verification, Explain outcome | `framed` |
| Framed list | Comparable entries, such as outbound groups | `framedList`, rows `px-4` |
| Nested details | Details of the row above: routing effects, rule details | `nested` |
| Code | Fingerprints, expressions, raw values | `codeBlock` |
| Floating | Node menu, chart tooltip | `floating` |

- A list is one framed list with hairline-divided rows, never a stack of
  separately framed boxes.
- Frames are outlined, not filled: Kumo's subtle text reaches 4.5:1 contrast only
  on the base surface. Code blocks use the recessed fill and default-color text.
- A frame's state changes only its outline color (amber for incomplete, red for
  blocked) plus an icon beside the heading; the surface stays base.
- Floating layers follow Kumo's menus: control surface, `shadow-lg` and an
  outline. Dark mode barely shows shadows, so its control surface is one step
  lighter than cards.
- The Setting sidebar sits on the canvas without a frame, so the section card is
  the only framed surface beside it.

## Lines

- Outlines (`ring-kumo-line`) draw frames and controls. Like Kumo, they are
  `ring` box-shadows painted just outside the element. Anything that clips its
  overflow must leave room for them and for focus rings; `Disclosure` panels keep
  a 4px gutter for this.
- Hairlines (`border-kumo-hairline`) separate sections and rows inside a card or
  frame.

## Spacing and alignment

Spacing follows Tailwind's 4px scale.

| Relation | Space |
| --- | --- |
| Card body padding | 16px; 20px from 768px |
| Between cards, and between the Setting sidebar and content | 16px; 20px from 768px |
| Subsections in a card | Hairline with 20px above and below (`mt-5 border-t pt-5`) |
| Group label to its content | 12px (`mb-3`) |
| Group label to its description or warning | 6px, forming one heading unit |
| Controls in a row | 8px (`gap-2`) |
| Stacked fields | 16px (`gap-4`) |
| List rows | 10px vertical padding (`py-2.5`); 16px horizontal inside a frame |
| Nested details | 2px rule, 16px indent |

- Spacing is measured between visible edges. Rows with 44px touch targets already
  carry space around their text, so the margin after them shrinks to keep the
  visible gap.
- Disclosures open flush with their heading; only nested details indent. A
  disclosure that ends its card is marked `last`, so the card's padding alone
  follows its content.
- The header, page content and footer share one centered workspace (1384px
  content, 16px gutters; 28px from 768px). The current Setting sidebar item starts
  at the workspace edge, aligned with the page title.

## Typography

| Role | Style | Use |
| --- | --- | --- |
| Page title | 18px semibold | "Network Panel" |
| Outcome | 20px semibold | Explain conclusion |
| Metric | 24px semibold, tabular | Status rates and counts |
| Card title | `cardTitle`: 16px semibold | Card strips, Explain Result |
| Group label | `groupLabel`: 13px medium, subtle | Subsection names above their controls |
| Body | 14px | Content and field labels |
| Hint | 13px, subtle | Counts, hints and notes, on the base surface only |
| Code | 12px monospace | Code blocks |

- Section and subsection names use Title Case (Quick Setting, Routing Rules);
  prose, field labels and actions use sentence case.
- A field label never repeats its group label more strongly; when the group label
  names the only control, the control takes an accessible name instead.
- Warning text keeps the default color and the amber icon carries the tone, since
  Kumo's warning text is below 4.5:1 in light mode.
- Numbers use tabular figures.

## Controls

- Kumo components: `Button` and `LinkButton` for actions, `Input`, `InputArea`
  and `InputGroup` for text, `Select` for choices, `Switch` for memberships, `Tabs`
  for views (segmented for pages, underline for scopes and the narrow Setting
  navigation), `Popover` for menus, `Badge` for short states, `Banner` for
  unavailable sections and errors, `Empty` for unconfigured sections, `Collapsible`
  for disclosures and `Toast` for action feedback. The wide Setting navigation
  copies the item styles of Kumo's sidebar menu, because the `Sidebar` module
  costs about 40 KB; weigh a component's bundle size against what the page uses.
- The node picker is a `Popover` with search, but its trigger matches `Select`:
  control surface and an up-down caret.
- On/off settings are switch rows: the name on the left, an On/Off label beside
  the switch, switches aligned in one column.
- A setting that can follow a router default is one `Select` among **Router
  default (current value)**, **On** and **Off**. Choosing the default clears the
  override, so there is no separate reset button. When the default cannot be
  known, the choice reads **Router default** and a note says what it depends on.
- Several formats of one download share one **Download** menu that names each
  format and where it is used, rather than a row of download buttons.
- A prerequisite whose absence breaks something is an amber banner (title and
  consequence) between its group label and the control, 12px from each. When the
  page can verify it, a verified state shrinks to a green line under the label,
  and a failure turns the banner red in place, with a retry action. Short
  cautions, such as Routing Rules' interruption note, stay one-line notices.
- Notices, banners, notifications and outcome headings center their icon on
  their text block, one line or several, the same way a banner centers its
  action; text wraps beside the icon. `notice.tsx` supplies the icons and colors,
  so do not offset icons by hand.
- Notifications use Kumo's default toast surface with a 1px outline; the icon
  carries the tone. Kumo's toned variants draw a 0.3px ring that renders unevenly
  and color warning text below 4.5:1. The close button is centered on the message
  like the icon, and the message keeps clear of it.
- One primary button per form; other actions are secondary.
- Targets are at least 36px; membership switches extend to 48 by 44px.
- Every focusable element shows a focus ring. Where Kumo marks focus only with a
  tint, as on sidebar items, add `focus-visible:ring-2 focus-visible:ring-kumo-brand`.
- Badges: green for available or enabled, blue for running tests, amber for
  warnings, red for failures and neutral otherwise.

## Motion

Use only Kumo's built-in transitions: disclosure height, tab indicator, popups
and toasts. Do not add decorative motion.

## Checking

`SCREENSHOT_DIR=/tmp/shots make test` saves light and dark screenshots from 320px
to 2560px wide. Review new or changed UI in both modes and at a narrow width, and
zoom in on frames to check that their outlines are complete.
