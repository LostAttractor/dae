---
name: dae-docs
description: Write or review dae documentation, including design structure, developer guides, bilingual sync, and Surge module compatibility scope.
---

# dae Documentation

- Keep `docs/zh` and `docs/en` counterparts in sync, writing each side in its own language; link to the existing side when a translation is missing. After doc changes, run the checks in `docs/en/development/contribute.md`.
- Document current usage, behavior, and design; omit work logs and experiment summaries.
- Limit Surge module compatibility docs to API support, behavior differences, and limitations. Omit external script test procedures and results.
- Organize `docs/*/design` by project capabilities and architecture. Describe responsibilities, state models, constraints, and tradeoffs; do not structure or name docs around reviews, fix history, or ablation studies.
- Put test procedures and performance measurement methods in developer docs.
