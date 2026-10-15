// Shared visual roles; web/DESIGN.md describes when to use each.

// Text roles on Kumo's type scale (12, 13, 14 and 16px). Card titles lead their card;
// group labels sit quietly above the controls they name.
export const cardTitle = "text-base font-semibold text-kumo-default";
export const groupLabel = "text-sm font-medium text-kumo-subtle";

// A block framed inside a card uses the same outline as Kumo's cards and controls.
// Subtle text keeps 4.5:1 contrast only on the base surface, so frames are not filled.
const outline = "rounded-lg ring ring-kumo-line";
export const framed = `${outline} p-4`;
// One frame around a list; rows are divided by hairlines and share the frame's inset.
export const framedList = `${outline} divide-y divide-kumo-hairline`;
// Details that belong to the row above, ruled like Kumo's nested collapsible panel.
export const nested = "border-l-2 border-kumo-fill pl-4";

// Code, fingerprints and raw values.
export const codeBlock = "rounded-lg bg-kumo-recessed px-3 py-2.5 font-mono text-xs/relaxed";

// Floating layers follow Kumo's menus: a control surface lifted by a shadow. Dark mode
// barely shows shadows, so the control surface is one step lighter than cards there.
export const floating = "rounded-lg bg-kumo-control shadow-lg ring ring-kumo-line";
