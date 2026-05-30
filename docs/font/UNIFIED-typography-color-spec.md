# Maljan Web UI — Unified Typography & Color Specification

**Single source of truth.** This document merges all four external research reports in
`docs/font/` *and* the current implemented state of the web UI. It is intended to lose
nothing from the four reports: every recommendation, numeric value, table, source and
caveat is carried over, with attribution and with divergences made explicit. Where the
four reports disagree, the disagreement is shown and the decision we shipped is recorded.

Date: 2026-05-30. Stack: Next.js 16.2.4 + React 19 + Tailwind CSS v4 (CSS `@theme`
tokens) + recharts. Theme: dark only. Product: dense, dark, data-heavy multi-agent
malware / threat-intelligence dashboard (GitHub + VirusTotal + Linear in feel).

---

## 0. Source reports (and how they are labelled here)

| ID | File | One-line stance |
|----|------|-----------------|
| **R1** | `The Legibility-Centric Dashboard_ A Technical Guide to Typography and Color for High-Density Security Analytics.md` | Keep Inter + JetBrains Mono; build a "legibility-centric" multi-scale system; APCA > 40; flags `#757f8a` muted as failing. |
| **R2** | `compass_artifact_wf-8017352f-5078-436d-8c1d-21e77340d603_text_markdown.md` | Keep Inter + JetBrains Mono (concrete anti-Geist-at-14px argument); the eye-fatigue is brightness/halation + a muted grey that fails AA on lighter surfaces; raise muted to `#8d97a3`; staged rollout. |
| **R3** | `report.md` | Keep Inter + JetBrains Mono; 5-step solid-hex ramp with warmer primary `#e8ecf1`; Apple-style negative tracking at UI sizes; full APCA Lc table; subpixel default (do NOT force `antialiased`). |
| **R4** | `Typography and Color System Specification.md` | Propose **Geist Sans** (Inter fallback) + JetBrains Mono; cool-slate greys; **desaturated GitHub-light semantic palette**; positive tracking on microcopy; APCA-audited. |

> **Note on R4 completeness:** R4's type-scale numeric table (D2) and many inline values
> were embedded as **images** (`![][imageN]` reference-style links whose base64 data sits
> after line ~340). Those pixel-encoded numbers are not text-extractable. Everything
> textual in R4 — its font stacks, the full color/semantic **hex** values, its CSS `@theme`
> + `@layer base` block (which gives h1 24px / h2 20px / h3 16px and the 11px microcopy
> rule), its prose for all seven findings, its comparison table, and its sources — **is**
> captured below. The only R4 content not reproduced verbatim is the image-rendered px/rem
> in D2, and R4's D6 CSS supplies the equivalent heading/microcopy sizes in text.

---

## 1. CURRENT IMPLEMENTED STATE (live in the repo)

Files: `apps/web/src/app/globals.css`, `apps/web/src/app/layout.tsx`,
`apps/web/src/app/fonts/InterVariable.woff2` (vendored).

### 1.1 Fonts (shipped)
- **Sans = self-hosted full-feature InterVariable** via `next/font/local`
  (`src: "./fonts/InterVariable.woff2"`, `weight: "100 900"`, `display: "swap"`,
  `variable: "--font-inter"`). Switched away from `next/font/google` because the Google
  Fonts build omits the character-variant / stylistic-set tables — verified in-browser
  that `cv05`/`cv08`/slashed-zero rendered identically on/off on the GF build, and now
  render distinctly with the self-hosted file.
- **Mono = JetBrains Mono** via `next/font/google` (`variable: "--font-jetbrains"`,
  `display: "swap"`). Its `zero`/`liga`/`tnum` features work in the GF build, so no
  self-host needed.
- Stacks (in `globals.css @theme`):
  - `--font-sans: var(--font-inter), "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;`
  - `--font-mono: var(--font-jetbrains), "JetBrains Mono", "SFMono-Regular", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;`

### 1.2 Color tokens (shipped) with measured WCAG contrast on all four surfaces

Surfaces: canvas `#0d1117`, surface `#161b22`, elevated/hover `#1c2333`, active `#21262d`.
Borders: `#30363d`, `#21262d`. Contrast measured live in-browser (sRGB relative luminance).

| Token | Hex | vs `#0d1117` | vs `#161b22` | vs `#1c2333` | vs `#21262d` | Verdict |
|-------|-----|------|------|------|------|---------|
| `--text-primary` | `#e6edf3` | 16.02 | 14.64 | 13.29 | 12.88 | AAA all |
| `--text-secondary` | `#9aa4af` | 7.48 | 6.84 | 6.21 | 6.02 | AAA/AA all |
| `--text-muted` | `#8d97a3` | 6.39 | 5.84 | 5.30 | 5.14 | **AA all (fixed)** |
| `--text-tertiary` | `#768491` | 4.94 | 4.51 | 4.10 | 3.97 | AA on canvas/surface; AA-large on raised/active |
| `--text-disabled` | `#5a6571` | 3.19 | 2.91 | 2.64 | 2.56 | disabled/placeholder only |

Semantic / accent (shipped — the desaturated "GitHub-light" set from R4, with the
link/accent split from R2):
- `--status-red: #ff7b72`, `--status-orange: #ffa657`, `--status-green: #7ee787`,
  `--status-blue: #79c0ff`, `--status-purple: #d2a8ff`.
- `--accent: #4493f8` (UNCHANGED — kept dark so `bg-accent text-white` buttons stay
  legible), `--accent-hover: #388bfd`, `--accent-strong: #58a6ff` (links only).

### 1.3 Type scale (shipped)
- `--text-xs: 0.8125rem` (**13px**), line-height `1.125rem` (18px, ratio ~1.38) — the
  dominant body/data size (was 12px).
- `--text-sm: 0.875rem` (14px), line-height `1.375rem` (22px) — forms / prose. Long-form
  NARRATIVE reading blocks were bumped 13 → 14px (executive summary, capability evidence
  quotes, agent arguments, attribution summary, defense rationale, pipeline claim text,
  cancel-confirm copy — 7 sites) so prose reads at the reports' comfortable body size while
  dense tables/IOC cells stay at 13px.
- **Full graduated scale completed** — every step now has an intentional line-height and a
  negative tracking that scales with size (the "tok" model): `--text-base` 16px / LH 24px /
  `-0.014em`; `--text-lg` 18px / LH 24px (NO letter-spacing token — `text-lg` is shared by
  the positive-tracked brand wordmark and by `<h1>` titles that already get −3% from
  `@layer base`, so a token here would fight both); `--text-xl` 20px / LH 26px / `-0.02em`;
  `--text-2xl` 24px / LH 32px / `-0.03em`; `--text-3xl` 30px / LH 34px / `-0.03em`;
  `--text-4xl` 36px / LH 40px / `-0.032em`.
- Micro-label floor raised: every `text-[10px]` / `text-[9px]` / `text-[8px]` → `text-[11px]`
  (84 occurrences across 15 files). `text-[11px]` is the floor; recharts ticks bumped
  `fontSize 11 → 12`.

### 1.4 Letter-spacing (shipped — "tok" negative tracking)
- Body (global, inherited): **`-0.011em`** (−1.1%).
- `@layer base { h1: -0.03em; h2: -0.025em; h3: -0.02em; }` (−3% / −2.5% / −2%). Scoped to
  `@layer base` so the positive `.tracking-wider` utility (in `@layer utilities`) still
  wins on uppercase section labels — negative tracking on small all-caps would cramp them.
- `text-2xl` display: `-0.03em` (−3%).
- Uppercase micro-labels / section headers keep **positive** `tracking-wider` (+0.05em).
  Verified: h1 "zararli.apk" = −0.54px (−3%); h2 "Verdict & Severity" (uppercase) = +0.65px.

### 1.5 OpenType / rendering (shipped)
- Body: `font-feature-settings: "liga" 1, "calt" 1, "cv05" 1, "cv08" 1, "cv09" 1, "case" 1;`
  (cv09 = flat-top 3; `case` re-centers brackets / braces / hyphens / colons to cap height for
  the many uppercase tracking-wider labels) `font-variant-numeric: tabular-nums slashed-zero;`
  `font-optical-sizing: auto;` `text-rendering: optimizeLegibility;`
  `-webkit-font-smoothing: antialiased;` `-moz-osx-font-smoothing: grayscale;`. R3's `ss02`
  "Disambiguation" set is reached granularly via cv05/cv08/cv09 rather than one bundle.
- **Optical sizing verified live:** InterVariable's `opsz` axis responds (a 120px probe is
  −52px narrower at `opsz 32` vs `opsz 14`), so `font-optical-sizing: auto` automatically gives
  large titles/numbers the Display optical cut and body the Text cut — Inter's own equivalent
  of a separate "Inter Display" face, with no extra font file.
- Mono (`code, kbd, samp, pre, .font-mono`): `font-variant-numeric: tabular-nums slashed-zero;`
  `font-feature-settings: "liga" 0, "calt" 0, "zero" 1;` (ligatures OFF so `->`/`!=`/`==`
  stay literal in IOCs/rules).
- **De-emphasis tiers now applied** (were defined but unused): `::placeholder` → tertiary
  (`#768491`, ~4.9 AA on the `#0d1117` inputs, one step below the muted label tier); disabled
  form controls (`input/textarea/select:disabled`) → SOLID `--text-disabled` (plus
  `-webkit-text-fill-color`) instead of opacity — opacity on text can disable Windows ClearType
  subpixel AA, so six ghost/outline buttons also switched `disabled:opacity-50 →
  disabled:text-text-disabled` (filled buttons keep opacity, which is conventional there).
- **User contrast control:** `@media (prefers-contrast: more)` lifts every tier toward the
  bright band — primary → `#f0f6fc` (R4's brighter value, reserved for this mode), secondary
  `#c9d1d9`, muted `#b1bac4`, tertiary `#9aa4af`, disabled `#768491`, accent-strong `#79c0ff`.
  Pure CSS, OS-driven, nothing to persist; tokens are `var()`-resolved so every utility updates.
- **Warm reading surface:** `--bg-reading: #1b1c21` (slightly lighter + warmer than the cool
  `#161b22` surface, lowering blue-on-blue halation) applied to the full-width executive-summary
  narrative pane; cool data surfaces unchanged.
- Token-bypassing hardcoded chart hex synced to the new palette: `timeline` `AGENT_COLORS`
  (5 series) and `capabilities` heatmap end-point (`#e5484d → #ff7b72`).

### 1.6 Verification (shipped)
- `tsc --noEmit` = 0 errors; `eslint .` = 0 errors (13 pre-existing, unrelated warnings).
- Visual sweep (dashboard / summary / signatures / samples / network): readable, calmer
  semantics, slashed-zero visible, no overflow (one fix: samples Size column `w-20 → w-24`).
- Build fix shipped alongside: `samples/page.tsx` `"use client"` restored to line 1.
- **2026-05-30 Group-A pass — measured live in-browser:** body features =
  `calt, case, cv05, cv08, cv09, liga`; `opsz` axis responds (−52px on a 120px probe);
  placeholder = `rgb(118,132,145)` = tertiary while input text stays primary; reading pane bg
  = `rgb(27,28,33)` = `#1b1c21`; narrative prose = 14px; `prefers-contrast: more` rule present
  in the cascade. Full WCAG + APCA matrix recomputed on all four surfaces + the reading surface:
  primary Lc 92–95 / WCAG 12.9–16.0 (AAA), secondary Lc 49–52 / 6.02–7.48, muted Lc 43–45 /
  5.14–6.39 (**AA on all four**), tertiary Lc 33–35 / 3.97–4.94 (placeholder/non-essential),
  disabled Lc 19–22 / 2.56–3.19 (disabled-only). Semantic text AA+ on every surface (red
  6.04–7.51; orange/green/blue/purple 7.8–12.3); links (`#58a6ff`) 6.03–7.49.
- **Solid-fill audit (#8):** the only status fill bearing text — the red cancel button — uses
  dark text on `#ff7b72` = **7.51** (white-on-red would be 2.52, hence `text-bg-deep`); dark-on-
  green/orange 9.8–12.3. White-on-`--accent` buttons = **3.10** (clears the 3:1 UI-component
  bar but is below 4.5 normal-text); pre-existing and deliberately retained per the "keep
  `--accent`" decision — flagged here, not changed.
- Pre-existing build error fixed in passing: `reports/page.tsx` had `"use client"` on line 2
  (below a `getErrorMessage` import) — the same W10 regression fixed earlier in
  samples/audit/dashboard/jobs; restored to line 1.

---

## 2. Type families & strategy

### 2.1 Apple (all reports agree)
- **SF Pro** is a variable family with optical sizes: **SF Pro Text** (≤19pt) has wider
  apertures / slightly heavier strokes / looser spacing for small sizes; **SF Pro Display**
  (≥20pt) tightens tracking and refines strokes (R1, R2, R4). R2: per WWDC20 "The details
  of UI typography," with SF Pro variable the Text↔Display transition is now continuous
  **between 17 and 28 points** (no hard 20pt break) and the tracking tables were updated.
  R3: SF Pro has 3 axes `wght` 100–900, `wdth`, `opsz`, switching Text/Display at the 20pt
  boundary.
- **SF Mono** is the monospace; SF numerals are proportional by default (R2/R4).
- **License: registered Apple developers only, for Apple-platform apps — NOT web-embeddable**
  (all four). On the web you approximate via the system stack
  `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, ...`.

### 2.2 Google (all reports agree)
- **Roboto** → **Roboto Flex** (variable; R3: 12 axes incl. weight/width/optical-size/grade)
  and **Google Sans Text** under Material 3. R4: Roboto Flex axes incl. `wght`, `GRAD`,
  `wdth`, `opsz`. M3 type scale = **15 tokens** across Display/Headline/Title/Body/Label
  (R3). Roboto / Roboto Flex are **Apache-2.0**, freely web-embeddable; **Google Sans Text
  is reserved to Google's own products** (all four).

### 2.3 Open web options (all reports)
- **Inter** (SIL OFL): tall x-height, ink-traps + contrast features in its "text" optical
  size, data-grade OpenType (`tnum`, slashed-zero/`zero`, contextual alternates, `cv*`,
  8 stylistic sets incl. `ss02` disambiguation). R1/R2/R3 endorse.
- **Geist / Geist Mono** (Vercel, OFL; "influenced by Inter, Univers, SF Mono, SF Pro,
  Suisse International"): sharper/"technical" personality (R1/R2/R3 as alternative; **R4
  recommends as primary**). R2 caveat: independent testing reports Geist's tight apertures
  "start to feel cramped at 14px" on Windows ClearType — a real risk for a dense dashboard.
- **IBM Plex Sans/Mono** (Carbon family, OFL): extensive OpenType, optimized for technical
  reading; Plex Mono has **no ligatures** (R1/R2/R3).
- **JetBrains Mono** (OFL): maximizes lowercase x-height, disambiguates `0/O/1/l/I`, ships
  **138–139 code ligatures** plus a dedicated **JetBrains Mono NL (No Ligatures)** build
  with identical metrics (R2), `calt`/`ss01`/`ss02`/`zero`/`frac` (R3).

### 2.4 Family recommendation per report
- **R1:** Inter (UI) + JetBrains Mono (mono). Alternatives table: IBM Plex Sans/Mono
  (max precision), Geist (developer aesthetic).
- **R2:** Inter + JetBrains Mono. Optional display face **Inter Display** for large titles.
  Geist Sans is the swap candidate only if it holds up at 14px on Windows.
- **R3:** Inter + JetBrains Mono (decision matrix below). Roboto Flex and IBM Plex Sans are
  viable alternatives; Geist strong for brand but newer/less battle-tested.
- **R4:** **Geist Sans** (primary) with **Inter** fallback + **JetBrains Mono** / Geist Mono.

R3 decision matrix (verbatim values): Inter (OFL, full web-embed, "ss02, tnum, zero, cv11,
8 stylistic sets", best open UI sans → **Keep**); JetBrains Mono (OFL, 139 ligatures,
calt/ss01/ss02/zero/frac → **Keep**); SF Pro (proprietary, no web, exclude); Roboto Flex
(Apache-2.0, viable, fewer data features); IBM Plex (OFL, Plex Mono no ligatures); Geist
(OFL, newer, less battle-tested).

### 2.5 Font stacks proposed (D1 of each report)
- **R1:** sans `'Inter', system-ui, -apple-system, sans-serif`; mono
  `'JetBrains Mono', 'IBM Plex Mono', 'Courier New', monospace`.
- **R2:** sans `'InterVariable', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif`;
  mono `'JetBrains Mono', 'JetBrains Mono NL', ui-monospace, 'SFMono-Regular', 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace`;
  display `'Inter Display', 'InterVariable', 'Inter', -apple-system, ...`. R2 also says load
  InterVariable via `@font-face` / `next/font/local`, gated by
  `@supports (font-variation-settings: normal)` with a static-Inter fallback.
- **R3:** sans `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif`;
  mono `JetBrains Mono, ui-monospace, "SF Mono", "Cascadia Code", "Segoe UI Mono", "Fira Code", Menlo, Consolas, monospace`;
  display = same as sans (no separate display face).
- **R4:** sans `"Geist Sans", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif`;
  mono `"Geist Mono", "JetBrains Mono", "IBM Plex Mono", Menlo, Monaco, Consolas, "Liberation Mono", monospace`.

**Decision shipped:** Inter (self-hosted InterVariable, for the real `cv*`/`ss*` tables) +
JetBrains Mono. 3 of 4 reports back Inter; R2's concrete "Geist cramped at 14px on Windows"
argument is decisive for our dense + Windows context. R4's Geist remains the documented
alternative.

---

## 3. Type scale

### 3.1 Principles (all reports)
- Dense/"productive" systems reject editorial ratios; they collapse hierarchy into narrow,
  predictable bands (R1, R4). R4: productive scales on a tight **Major Second (1.125)** or
  fixed px increments, not a Major Third (1.25).
- **IBM Carbon "productive" anchors at a 14px base** with tight leading (R1, R2, R4);
  body-compact-01 = 14px/18px/+0.16px, label-01 = 12px/16px/+0.32px, code-01 = 12px/16px
  Plex Mono /+0.32px (R2).
- **GitHub Primer**: rem tokens on a 4px grid, system-font stacks, weights
  light/normal/medium/semibold; **explicitly advises against using color as the primary
  emphasis method and against altering letter-spacing** ("Please refrain from altering
  letter-spacing on our products") (R2).
- **Linear** (closest aesthetic precedent — Inter, near-black, low-chroma): body 16px/400/
  1.5 / −0.05px tracking; captions 12px/400/1.4; display tracking −3.0px@80px scaling to
  −0.6px@28px; subsection heads weight 510; **13px mono** token for "code in product
  screenshots and status/ID tokens" — exactly our IOC-hash / MITRE-ID case (R2, R3).
- **Apple HIG**: 11 semantic text styles `.largeTitle`(34pt) … `.caption2`(11pt); iOS body
  17pt, macOS body 13pt, minimum text style 11pt; size-specific **tracking tables**
  (R1, R2, R3). Apple tracking examples (R3): **17pt = −0.43px, 13pt = −0.08px, 12pt = 0px,
  28pt = +0.38px**; R2/R4: SF Pro Text 17pt ≈ −0.43px, Display 28pt ≈ −0.8px. (Apple uses
  NEGATIVE tracking at body/large and POSITIVE tracking at small.) NOTE: R3 applies negative
  at UI sizes; R1 and Material apply **positive** tracking at small sizes — see §3.6 divergence.
- **Material 3** type scale tokens (R2, R3): Body Large 16sp/24/+0.5px/400; Body Medium
  14sp/20/+0.25px/400; Body Small 12sp/16/+0.4px/400; Title Medium 16sp/24/+0.15px/500;
  Label Large 14sp/20/+0.1px/500; Label Small 11sp/16/+0.5px/500. M3 puts **positive**
  tracking on small text, negative on large.
- **Minimum comfortable sizes (dense, dark):** R1 — body table cells 14px, narrative 16px,
  labels 11–12px; R2 — 14px body / 13px mono cells / 12px metadata / 11px uppercase labels
  (weight 500+), never below 11px essential; R3 — 14px body, 13px table data, 12px minimum,
  never below 12px readable; R4 — 14px running text minimum, 11px metadata floor, below 11px
  the screen's emission glow collapses glyph counters (compensate with heavier weight +
  positive tracking).

### 3.2 R1 full multi-scale (verbatim)

| Token | px | rem | LH | Tracking | Weight | Role |
|---|---|---|---|---|---|---|
| display-large | 48 | 3.0 | 1.2 | −0.01em | 500 | Main dashboard title |
| display-medium | 32 | 2.0 | 1.25 | −0.005em | 500 | Section headers |
| display-small | 24 | 1.5 | 1.33 | 0 | 500 | Secondary headers |
| heading-large | 20 | 1.25 | 1.33–1.4 | 0 | 500 | Table column headers |
| heading-medium | 18 | 1.125 | 1.33 | 0 | 500 | Panel headers |
| body-large | 16 | 1.0 | 1.5 | 0 | 500 | Narrative paragraphs |
| body-base | 14 | 0.875 | 1.5 | 0 | 500 | Primary data table cells |
| body-small | 12 | 0.75 | 1.33 | +0.01em | 400 | Metadata labels, captions |
| label-large | 12 | 0.75 | 1.33 | +0.02em | 400 | Small uppercase tags, status badges |
| label-base | 11 | 0.6875 | 1.2 | +0.02em | 300 | Muted/disabled text |

### 3.3 R2 scale (verbatim)

| Token | px | rem | LH | Tracking | Weight | Role |
|---|---|---|---|---|---|---|
| display | 28 | 1.75 | 34px (1.21) | −0.4px (−0.014em) | 600 | page title (rare) |
| title-lg | 22 | 1.375 | 28px (1.27) | −0.3px | 600 | section title |
| title-md | 18 | 1.125 | 24px (1.33) | −0.2px | 600 | card/panel header |
| body-lg | 16 | 1.0 | 24px (1.5) | 0 | 400 | dialog/emphasis body |
| body | 14 | 0.875 | 20px (1.43) | 0 | 400 | default body/narrative |
| body-compact | 14 | 0.875 | 18px (1.29) | 0 | 400 | table cells, dense rows |
| metadata | 12 | 0.75 | 16px (1.33) | +0.16px | 400 | timestamps, secondary meta |
| label | 11 | 0.6875 | 16px (1.45) | +0.4px, uppercase | 500 | section labels, column heads |
| mono-md | 13 | 0.8125 | 20px (1.54) | 0 | 400 | hashes/IOCs in cells |
| mono-sm | 12 | 0.75 | 18px (1.5) | 0 | 400 | inline mono, badges |
| code-block | 13 | 0.8125 | 20px (1.54) | 0 | 400 | YARA/Sigma/Suricata blocks |

### 3.4 R3 scale (verbatim)

| Token | px | rem | LH | Tracking | Weight | Role |
|---|---|---|---|---|---|---|
| display-lg | 32 | 2.0 | 1.1 (35px) | −0.4px | 600 | Page title |
| display-md | 24 | 1.5 | 1.15 (28px) | −0.26px | 600 | Section header, panel title |
| display-sm | 20 | 1.25 | 1.2 (24px) | −0.45px | 500 | Card title, sub-section |
| headline | 18 | 1.125 | 1.3 (23px) | −0.44px | 500 | Widget header, table group label |
| body | 14 | 0.875 | 1.5 (21px) | −0.15px | 400 | Default body, descriptions |
| body-sm | 13 | 0.8125 | 1.4 (18px) | −0.08px | 400 | Table cell content, metadata |
| label | 12 | 0.75 | 1.35 (16px) | 0 | 500 | Uppercase section labels, badges |
| caption | 12 | 0.75 | 1.35 (16px) | 0 | 400 | Timestamps, file sizes, minor meta |
| code | 13 | 0.8125 | 1.5 (20px) | 0 | 400 | Monospace: YARA, Sigma, hashes |
| data | 13 | 0.8125 | 1.4 (18px) | 0 | 450* | Tabular numeric: scores, counts, MITRE IDs |

*450 = Inter variable medium-regular intermediate. R3 derives tracking from Apple's HIG
table: 14px −0.15px, 13px −0.08px, 12px 0px, 20px −0.45px, 18px −0.44px, 24px −0.26px,
32px −0.4px (interpolated).

### 3.5 R4 scale (token names/roles in text; px/rem/LH/tracking were images)
Tokens: `display-lg` (primary page/main screen headers), `title-lg` (structural container /
section headers), `title-md` (component headers, modal titles, field groups), `title-sm`
(form labels, input titles, row indicators), `body-md` (general paragraphs / running prose),
`body-sm` (table cell content, log values, status details), `label-caps` (small uppercase
metadata, column headers), `mono-data` (SHA-256 hashes, IPs, domains, IOC indicators),
`mono-code` (inline code, YARA/Sigma rules). Built on a **Major Second (1.125)** scale with
condensed leading (1.15–1.2 headers, 1.35–1.4 body). From R4's D6 CSS (text): **h1 = 24px /
LH 28px / −0.015em / 600; h2 = 20px / LH 24px / −0.01em / 600; h3 = 16px / LH 20px /
−0.005em / 500;** microcopy `.micro-tag` = **11px / LH 14px / +0.06em / 600 / uppercase**
(positive tracking + heavier weight to counter halation at micro sizes).

### 3.6 Divergence — tracking at SMALL sizes (important)
- **R3** (Apple-faithful at UI sizes): apply **negative** tracking even at 12–16px
  (−0.15px@14, −0.08px@13).
- **R1, R4, Material 3**: apply **positive** tracking at small/label sizes (+0.01..+0.06em),
  negative only at large/display.
- **GitHub Primer**: don't alter letter-spacing at all.
- **Apple's own tables** use **negative at body+ and positive only below ~caption**; the
  zero crossing is ~12pt.

**Decision shipped:** mild negative on body (−1.1%), strong negative on headings/large
display (−2%…−3%), but **positive `tracking-wider` preserved on small uppercase labels**
(via `@layer base` scoping). This follows R4/R1/Apple's "positive on small caps, negative
on large" split rather than R3's negative-everywhere.

**Decision shipped (sizes):** body bumped 12 → **13px** (the 13px "data/compact" sweet spot
common to R2/R3); forms stay 14px; micro-label floor raised to **11px** (R1/R2/R3/R4 all set
an 11px floor); large display (24px) tightened. We did not adopt a full 14px running-body
because the app is intentionally denser than a marketing site (a 14px body remains the
documented heavier-comfort alternative).

---

## 4. Weights

- **Body / table data: 400** (R1/R2/R3/R4). On macOS grayscale AA light-on-dark renders
  lighter, so do not go below 400 (R2).
- **Secondary emphasis / labels / column headers / active nav: 500** (all).
- **Headings / KPI values / strong emphasis: 600** (all). R2: KPI/headline 600; R4: page
  titles/section headers 600.
- **Avoid 100–300 on dark** (all): Apple HIG warns Ultralight/Thin/Light "can be difficult
  to see"; on near-black they bloom and thin out (R2/R3/R4). R4: thin lines lose contrast
  and "dissolve" into the surrounding pixels.
- **Avoid 700+ for dense headers** (R2/R4): over-bold adds noise and bold counters bloom
  with halation; reserve Bold (700) for rare large display or critical alerts/severity
  badges (R3).
- **Variable-font intermediates:** R2 — Linear's 510 for subsection heads, or 450 medium-
  regular; R3 — `font-variation-settings: "wght" 450` for key metrics; R4 — a dark-theme
  weight multiplier (~0.9) and `GRAD`-axis trick to reduce weight in dark mode without
  layout shift. Optimal range on dark: **400–600** (all).

---

## 5. Text color & contrast (the most-detailed area)

### 5.1 Solid hex vs alpha — UNANIMOUS: use **solid hex**
- Alpha text re-composites differently over each surface → 4 surfaces give 4 unpredictable
  effective colors / contrasts (R1/R2/R3/R4). On Windows Chromium, opacity on text can
  **disable ClearType subpixel AA**, giving jagged edges (R4); alpha can trigger grayscale
  AA (thinner/fuzzier) on some renderers (R3); compositing overhead at scale (R3/R4).
- GitHub Primer ships **solid-hex** foreground tokens; Material 3 reserves alpha for
  disabled states only (R2/R3).

### 5.2 Avoid pure white/black; off-white band; halation; astigmatism
- Never `#ffffff` body text on near-black — it maximizes **halation** (optical bloom / glow)
  (all). Cap primary in the **`#e6edf3`–`#f0f6fc`** band (R2/R4); R3 narrows to
  `#e6eaef`–`#f0f6fc`.
- Off-black background not pure black — `#0d1117` is correctly off-black (all).
- Astigmatism prevalence cited (justifies off-white): **R2 ≈ 40.4% pooled adult worldwide
  (US 11–46%)**; **R3 ≈ 50%**; **R4 30–60%**.
- High contrast **also** fatigues: R2 — target a "Goldilocks" band ~AAA(7:1)…~15:1, not
  21:1; R3 — contrast >15:1 can cause discomfort over long sessions; consider warmer
  `#e4e9ef` (14.5:1) if fatigue persists.

### 5.3 Grey temperature
- `#0d1117` is a cool, blue-tinted near-black. R2/R4: keep greys **cool/low-chroma slate**
  so text integrates; warm greys look muddy against the cool canvas. **R3 dissents
  slightly**: a *barely* warmer off-white (e.g. `#e8ecf1`, B only +5 over R, vs `#e6edf3`'s
  B +8) reduces the same-hue "chromatic halo" — i.e. R3 wants the primary marginally warmer
  to avoid blue-on-blue glow, while keeping the ramp neutral-cool overall.

### 5.4 Text ramps — each report verbatim

**R1** (3-step, vs `#0d1117`):
| Token | Hex | Contrast | APCA |
|---|---|---|---|
| text-primary | `#E6EDF3` | 7.2:1 (AAA) | ~55 |
| text-secondary | `#9AA4AF` | 4.8:1 (AA) | ~45 |
| text-muted | `#757F8A` | 3.2:1 (**Fail**) | ~35 |
R1 note: change muted to **`#606973`** for 4.5:1 AA. (R1's contrast figures for
primary/secondary are lower than R2/R3's recomputation — see §5.6.)

**R2** (computed vs `#0d1117`, L_bg≈0.0056):
| Color | Hex | Contrast |
|---|---|---|
| Primary | `#e6edf3` | ~15.8 |
| Secondary | `#9aa4af` | ~7.5 |
| Tertiary/metadata | `#768491` | ~4.9 |
| Muted (old) | `#757f8a` | ~4.65 (but **~3.7 on `#21262d`** → fails AA on the two lightest surfaces) |
| Disabled | `#5a6571` | ~3.1 |
R2 fix: muted → **`#8d97a3`** (~6.4 on canvas, ~4.95 on `#21262d`, passes everywhere), or
restrict `#757f8a` to the darkest surface / large text only. R2 shipped ramp:
text-primary `#e6edf3` (~15.8, AAA), secondary `#9aa4af` (~7.5, AAA), tertiary `#768491`
(~4.9, AA — darkest surface only), muted `#8d97a3` (~6.4, AAA — all-surface), disabled
`#5a6571` (~3.1, disabled only), text-onEmphasis `#ffffff` (check per fill).

**R3** (5-step, vs `#0d1117`, with APCA Lc):
| Token | Hex | Contrast | WCAG | APCA Lc |
|---|---|---|---|---|
| text-primary | `#e8ecf1` | 15.95 | AAA | −97 |
| text-secondary | `#9fa7b3` | 7.80 | AAA | −72 |
| text-tertiary | `#7d8693` | 5.14 | AA | −58 |
| text-quaternary | `#656d78` | 3.62 | AA Large | −42 |
| text-disabled | `#555c66` | 2.80 | — | −28 |
R3 hue note: primary `#e8ecf1` is R232 G236 B241 (B +5 over R) — intentionally less blue
than `#e6edf3` (B +8) to cut halation; ramp steps reduce all channels roughly equally
(neutral-cool).

**R4** (4-step, vs `#0d1117`; ratios were images → "passes" verdicts in text):
| Token | Hex | Role | Verdict |
|---|---|---|---|
| text-primary | `#f0f6fc` | display titles, headers, inputs | AAA |
| text-secondary | `#c9d1d9` | body copy, data labels, table values | AAA |
| text-muted | `#8b949e` | metadata, captions, helper text | AA |
| text-disabled | `#6e7681` | disabled buttons, inactive placeholders | AA Large |

### 5.5 Text-on-background pairing matrices — each report verbatim

**R1:** primary `#E6EDF3` / secondary `#9AA4AF` / muted `#757F8A` on every surface
(`#0d1117` 7.2/4.8/3.2; `#161b22` 6.8/4.6/3.0; `#1c2333` 6.5/4.4/2.9; `#21262d` 6.2/4.2/2.8).
Same three tokens across surfaces; R1 notes muted is weakest and should darken.

**R2:** primary `#e6edf3` and secondary `#9aa4af` pass on all four surfaces. For muted/
tertiary on `#1c2333` and `#21262d`, **always use `#8d97a3`** (or make text large/bold) —
never `#757f8a` or `#768491`. Per-surface: canvas → tertiary `#768491` (~4.9 ✓); surface
→ `#8d97a3` (~5.6 ✓, `#768491` ~4.5 borderline); raised → `#8d97a3` (~5.1 ✓, `#768491`
fails ~4.0); lightest → `#8d97a3` (~4.95 ✓, `#757f8a`/`#768491` fail ~3.7–3.9).

**R3:** `#e8ecf1` / `#9fa7b3` / `#7d8693` across surfaces — canvas 15.95/7.80/5.14;
`#161b22` 14.58/7.13/4.70; `#1c2333` 13.23/6.47/4.26; `#21262d` 12.83/6.27/4.13. Quaternary
`#656d78` and disabled `#555c66` only on `#0d1117`/`#161b22` (AA-Large there).

**R4:** primary `#f0f6fc` / secondary `#c9d1d9` / muted `#8b949e` mapped across canvas
`#0d1117`, surface `#161b22`, elevated `#1c2333`, active `#21262d`, with recommended
structural borders `#30363d` (canvas/surface) and `#444c56` / `#484f58` (raised/active).
(Ratios image-encoded; all marked "passes.")

### 5.6 Note on R1's lower primary/secondary ratios
R1 lists primary `#E6EDF3` at 7.2:1 and secondary `#9AA4AF` at 4.8:1, whereas R2 and R3
recompute the same/near-identical colors at ~15.8 and ~7.5. Our **own live measurement
confirms R2/R3** (primary `#e6edf3` = 16.02, secondary `#9aa4af` = 7.48 on `#0d1117`). R1's
figures appear under-stated; treat R2/R3 (and our measured values in §1.2) as authoritative.

### 5.7 Semantic + link/accent — each report verbatim

- **R1:** keep existing tokens (red `#f85149`, orange `#d29922`, green `#3fb950`, blue
  `#4493f8`, purple `#bc8cff`); enforce ≥4.5:1 for semantic text; green ~6.1:1, link/accent
  `#4493f8` ~7.5:1. Mapped as semantic-success/warning/error/info/link.
- **R2:** keep GitHub's dark palette (well-calibrated, all ≥5.6:1); verified verbatim from
  shipped `@primer/primitives dark.css`: accent `#4493f8` (~6.1), red `#f85149` (~5.6),
  green `#3fb950` (~7.5), orange `#d29922` (~7.5), purple `#bc8cff` (~7.5). For small inline
  links prefer **`#58a6ff`** (~7.0). Use bright red for short tokens only (limit chromatic
  fatigue); severe orange-red `#db6d28` (~4.7) for high-priority fills/borders, not small text.
- **R3:** brighten red from `#f85149` (5.65:1) → **`#ff6b62`** (6.79:1) preserving hue;
  others already AA+ (accent `#4493f8` 6.11, warning `#d29922` 7.50, success `#3fb950`
  7.45, info/purple `#bc8cff` 7.51). Danger `#ff6b62` for critical alerts/severity:critical.
- **R4:** desaturate to soft GitHub-light variants to stop "vibration"/chromatic aberration:
  **error `#ff7b72`, warning `#ffa657`, success `#7ee787`, info `#79c0ff`, purple `#d2a8ff`,
  link `#58a6ff`** (all "passes AA/AAA"). R4 examples: success `#3fb950 → #7ee787`, warning
  `#d29922 → #ffa657`, error `#f85149 → #ff7b72`, accent `#4493f8 → #58a6ff`.

**Decision shipped (semantic):** adopt **R4's desaturated palette** for `--status-*`
(red `#ff7b72`, orange `#ffa657`, green `#7ee787`, blue `#79c0ff`, purple `#d2a8ff`) for the
calmer text/tint look; **keep `--accent #4493f8`** (R2's reasoning) so white-on-fill buttons
stay legible; add **`--accent-strong #58a6ff`** (R2/R3/R4) for hyperlink text only; the one
solid-red button (`bg-status-red text-white`) switched to dark text for contrast on the
lighter red. (We did NOT adopt R1/R2's "keep GitHub palette as-is" nor R3's milder `#ff6b62`;
the 2-vs-2 split was resolved toward R4's calmer text palette since the dominant use is text/
tints, with `--accent` kept for fills.)

---

## 6. Accessibility

### 6.1 WCAG 2.2 (all)
- Normal text **4.5:1**; large text (≥18px regular / ≥14px bold) and UI components/icons
  (SC 1.4.11) **3:1**; thresholds unchanged from 2.1. R1 also cites the 7:1 AAA aspiration
  for sustained reading.

### 6.2 APCA (WCAG 3 draft) — each report's levels
- **R1:** target **APCA > 40** for dark-mode primary text; "perceptually comfortable
  contrast" beats maximizing ratio.
- **R2** (Myndex "APCA in a Nutshell", verbatim): **Lc 90** = preferred for fluent/body text
  ≥18px/300 or 14px/400; **Lc 75** = minimum for body ≥24px/300, 18px/400, 16px/500,
  14px/700; **Lc 60** = minimum for non-body content; **Lc 15** = point of invisibility.
  WCAG 2 "far overstates contrast for dark colors to the point that 4.5:1 can be functionally
  unreadable when near black." Ship colors that pass **both** WCAG 2.2 and APCA.
- **R3** (full dark-mode Lc table, negative polarity): **−90** preferred body (18px/300 or
  14px/400); **−75** minimum body (24px/300, 18px/400, 14px/700); **−60** content
  (captions/subheads); **−45** large/bold (36px normal or 24px bold); **−30** less-critical
  (placeholders/disabled, min 5.5px stroke); **−15** decorative. Maps its ramp: primary −97,
  secondary −72, tertiary −58.
- **R4:** **Lc 90** preferred long-form/body; **Lc 75** minimum reading; **Lc 60** component/
  labels/buttons; **Lc 45** large/headings; **Lc 30** spot (placeholders/disabled). APCA is
  polarity-aware and accounts for size/weight/spatial-frequency, fixing WCAG 2's dark-mode
  "false passes."

### 6.3 Dark-mode specifics (all)
- Halation worst with pure white on pure black; disproportionately affects astigmatism/
  myopia. Mitigate: off-white not white; off-black not black; slightly larger sizes; a touch
  more weight; avoid ultra-thin strokes (R1/R2/R3/R4).
- AA minimums on dark: ≥14px/400 ≥4.5:1 for body; 11px allowed only for labels at weight
  500+ and ≥4.5:1 (R2).

**Decision shipped:** target WCAG AA on all four surfaces (achieved & measured, §1.2) while
keeping primary off-white (`#e6edf3`, not `#ffffff`/`#f0f6fc`) for halation comfort.

---

## 7. Rendering / OpenType

### 7.1 Numerals & disambiguation (strong consensus)
- **`tabular-nums` (`tnum`)** on every table/score/port/timestamp/KPI/hash so columns align
  and live numbers don't jitter (all four). Exposed as Tailwind `.tabular-nums`.
- **Slashed zero** (`zero` / `slashed-zero`): Inter needs it explicitly; JetBrains Mono ships
  a dotted zero by default (R2). Disambiguates `0` vs `O` in hashes/keys (all).
- **Disambiguation glyphs:** R2 — Inter `cv05`; R3 — Inter `ss02` (reshapes I/l/1/0/O); R4 —
  `cv05` (tailed l), `cv08` (serifed I), `cv09` (flat-top 3), plus `case` (centers brackets/
  braces/hyphens/colons to caps). R1 — stylistic sets `ss01–ssXX` to vary forms.

### 7.2 Ligatures / contextual alternates
- Enable `liga` + `calt` for Inter UI text (Inter's `calt` adjusts punctuation by context).
- **Disable ligatures in monospace data cells** (JetBrains Mono NL build, or `"liga" 0,
  "calt" 0`) so `->`, `!=`, `==` in IOCs/rules never fuse; optionally enable inside syntax-
  highlighted rule blocks (R2/R3/R4). R3 differentiates `.font-code` (calt on for rule
  blocks) vs `.font-code-raw` (`font-variant-ligatures: none` for raw hashes).

### 7.3 Optical sizing
- R1/R2: `font-optical-sizing: auto` so InterVariable / Inter Display use the display cut at
  large sizes and text cut for body (Apple's principle on the open web). R4: Roboto Flex /
  SF `opsz` axis.

### 7.4 `-webkit-font-smoothing` — DIVERGENCE
- **R1:** `-webkit-font-smoothing: antialiased` + `font-smooth: never` for crispest dark text
  (disables OS subpixel hinting / "bleeding" at edges).
- **R2:** `antialiased` (macOS-only; Firefox-macOS `grayscale`) makes light-on-dark *lighter/
  thinner*, **countering subpixel "bloat"** → usually desirable on dark; pair with weight
  ≥400; inert on Windows/Linux anyway.
- **R3:** **Do NOT override**; keep browser default subpixel-antialiased — it uses LCD
  subpixels to add ~0.5px perceived stroke weight (a free readability boost on dark);
  `antialiased` thins strokes and worsens halation. If text feels heavy, lighten the color,
  not the smoothing.
- **R4:** on macOS `antialiased` thins light text to counter emission glow; on Windows keep
  subpixel to avoid pixelation.

**Decision shipped:** `-webkit-font-smoothing: antialiased` + `-moz-osx-font-smoothing:
grayscale` (R1/R2/R4 majority; the user runs Windows where it is inert anyway). R3's dissent
is recorded — revisit if a light theme ships or Mac users report thin text.

### 7.5 `text-rendering`
- R1: enable kerning/ligatures globally; R2: scope `optimizeLegibility` to headings; R3:
  `optimizeLegibility` can add ~200ms on text blocks >1000 chars — fine for static headers,
  avoid on frequently re-rendered data cells. R4: `optimizeLegibility` in base.

**Decision shipped:** `text-rendering: optimizeLegibility` on body (acceptable given our
table cells are not >1000-char blocks).

### 7.6 Representative CSS snippets (from the reports)
- **R1:** `.text-container { -webkit-font-smoothing: antialiased; font-smooth: never; }`;
  `code, pre, .table-cell-numerical { font-feature-settings: 'tnum' on, 'zero' on; }`;
  `.article-body p { font-feature-settings: 'liga' 1, 'clig' 1; }`.
- **R2:** `:root { font-feature-settings: 'liga' 1, 'calt' 1, 'cv05' 1; font-variant-numeric:
  tabular-nums slashed-zero; font-optical-sizing: auto; -webkit-font-smoothing: antialiased; }`;
  numeric `.tnum/td.num/.score/.port/.timestamp { 'tnum' 1, 'zero' 1 }`; mono `.mono/code.ioc/
  td.hash { 'liga' 0, 'calt' 0, 'zero' 1; tabular-nums }`; rule blocks `pre.rule/.yara/.sigma/
  .suricata { 'liga' 1, 'calt' 1 }`; label `.label { 0.6875rem / 1rem / 0.04em / uppercase /
  500 / secondary }`.
- **R3:** `.font-data { 'ss02' 1, 'tnum' 1, 'zero' 1, 'liga' 1, 'calt' 1; tabular-nums }`;
  `.font-code { 'calt' 1, 'zero' 1, 'ss01' 1; font-variant-ligatures: contextual }`;
  `.font-code-raw { font-variant-ligatures: none; 'zero' 1, 'tnum' 1 }`; `.dark-boost {
  font-variation-settings: 'wght' 450 }`; no smoothing override.
- **R4:** base `code, pre, kbd, samp, .mono-data { 'tnum' 1, 'zero' 1, 'cv05' 1, 'cv08' 1,
  'cv09' 1, 'calt' 1, 'case' 1; tabular-nums slashed-zero }`; `.micro-tag { 0.6875rem /
  0.875rem / 0.06em / 600 / uppercase }`; h1 24/28/−0.015em/600, h2 20/24/−0.01em/600,
  h3 16/20/−0.005em/500.

---

## 8. Apple vs Google philosophy — what to borrow

- **Apple:** content-deference; one family with optical sizes + automatic size-specific
  tracking/leading; restrained weights; proportional numerals; tight, decisive hierarchy via
  size/weight/color; layered "materials"/vibrancy for depth (R1/R2/R3/R4). **Borrow:**
  optical sizing, size-specific tracking tables, weight restraint, "let type defer to data,"
  strict hierarchy.
- **Google (M3):** token-driven, role-based emphasis (`on-surface` / `on-surface-variant`);
  variable fonts (Roboto Flex `GRAD`/`opsz`); explicit per-token tracking; tonal surface
  overlays for elevation; responsive type scale across breakpoints; opacity ramp 87/60/38%
  (R1/R2/R3/R4). **Borrow:** the token/role architecture (maps directly to Tailwind
  `@theme`), the on-surface emphasis tiers (implemented as solid hex, not opacity), tonal
  layering.
- **Synthesis (all four converge):** a **legibility-centric** system — Google's token/role
  structure + emphasis tiers, with Apple's discipline (one sans + one mono, optical sizing,
  restrained weights, size-specific tracking, deferential numerals). **GitHub Primer** is the
  closest real-world precedent (dark, dense, code/data) and **Linear** the closest aesthetic
  precedent (Inter, near-black, low-chroma neutrals) — both validate this direction.

R1 comparison axes: Information Hierarchy, Typography System (rigid/optical vs flexible/
responsive), Materiality (materials/blur vs layered surfaces), Color System, Core Strength
(precision vs flexibility). R3 axes: optical sizing, type-scale density, weight range,
tracking, text color (system grays vs opacity), dark approach, font features, monospace. R4
axes: default typeface, monospace, optical sizing mode, line-height strategy, tracking model,
token structure, adaptivity, layering, contrast standard.

---

## 9. Consensus / divergence / decisions (master table)

| Topic | R1 | R2 | R3 | R4 | Shipped |
|---|---|---|---|---|---|
| UI sans | Inter | Inter | Inter | **Geist** (Inter fb) | **Inter (self-hosted InterVariable)** |
| Mono | JetBrains Mono | JetBrains Mono (+NL) | JetBrains Mono | JBM / Geist Mono | JetBrains Mono |
| Primary text | `#E6EDF3` | `#e6edf3` | `#e8ecf1` (warmer) | `#f0f6fc` | **`#e6edf3`** |
| Secondary | `#9AA4AF` | `#9aa4af` | `#9fa7b3` | `#c9d1d9` | **`#9aa4af`** |
| Muted | `#757F8A`→`#606973` | **`#8d97a3`** | `#7d8693` | `#8b949e` | **`#8d97a3`** |
| Tertiary | — | `#768491` | `#7d8693` | — | **`#768491`** |
| Disabled | — | `#5a6571` | `#555c66` | `#6e7681` | **`#5a6571`** |
| Semantic | keep GitHub | keep GitHub (+`#58a6ff` links) | brighten red `#ff6b62` | **desaturate (pastels)** | **R4 pastels + accent kept + `#58a6ff` links** |
| Body size | 14 | 14 (13 mono) | 14 (13 data) | 14 | **13 (xs); 14 forms** |
| Label floor | 11 | 11 | 12 | 11 | **11** |
| Small-size tracking | positive | (Apple tables) | **negative** | positive | **positive on caps, negative on body/large** |
| Heading tracking | −0.005..−0.01em | −0.2..−0.4px | −0.26..−0.45px | −0.005..−0.015em | **−2%..−3% (−0.02..−0.03em)** |
| Solid hex vs alpha | solid | solid | solid | solid | solid |
| Font smoothing | antialiased+`font-smooth:never` | antialiased | **subpixel (no override)** | antialiased (mac) | **antialiased** |
| tnum + slashed-zero | yes | yes | yes | yes | **yes (global)** |
| Disambiguation | ssXX | cv05 | ss02 | cv05/cv08/cv09/case | **cv05/cv08** |
| APCA target | >40 | Lc 90/75/60 | Lc table −90…−15 | Lc 90/75/60/45/30 | WCAG AA measured (APCA-aware) |

---

## 10. Sources (merged from all four reports)

**Primary / official**
- Apple HIG — Typography: https://developer.apple.com/design/human-interface-guidelines/typography
- Apple HIG — Color: https://developer.apple.com/design/human-interface-guidelines/color
- Apple HIG — Dark Mode: https://developer.apple.com/design/human-interface-guidelines/dark-mode
- Apple HIG — Materials: https://developer.apple.com/design/human-interface-guidelines/materials
- Apple Fonts (SF Pro / SF Mono license): https://developer.apple.com/fonts/
- Apple WWDC20 "The details of UI typography": https://developer.apple.com/videos/play/wwdc2020/10175/
- Material 3 — Typography overview: https://m3.material.io/styles/typography/overview
- Material 3 — Type scale tokens: https://m3.material.io/styles/typography/type-scale-tokens
- Material 3 — Applying type: https://m3.material.io/styles/typography/applying-type
- Material 3 — Color roles: https://m3.material.io/styles/color/roles
- Material 2 — Dark theme: https://m2.material.io/design/color/dark-theme.html
- WCAG 2.2: https://www.w3.org/TR/WCAG22/
- APCA "In a Nutshell": https://git.apcacontrast.com/documentation/APCA_in_a_Nutshell.html
- APCA easy intro: https://git.apcacontrast.com/documentation/APCAeasyIntro.html
- APCA calculator: https://apcacontrast.com/
- APCA / Myndex (SAPC-APCA repo): https://github.com/Myndex/SAPC-APCA
- APCA dark-mode discussion: https://github.com/Myndex/SAPC-APCA/discussions/74
- WCAG3 issue (halation/APCA): https://github.com/w3c/wcag3/issues/221
- ARC (APCA Readability Criterion): https://www.readtech.org/ARC/
- GitHub Primer — Typography: https://primer.style/foundations/typography
- GitHub Primer — Color: https://primer.style/foundations/color/overview/ and https://primer.style/product/getting-started/foundations/color-usage
- GitHub Primer — shipped dark tokens: https://unpkg.com/@primer/primitives/dist/css/functional/themes/dark.css
- IBM Carbon — Typography: https://carbondesignsystem.com/elements/typography/overview/ , /type-sets/ , /style-strategies/
- Vercel Geist — Typography / Font: https://vercel.com/geist/typography , https://vercel.com/font
- Inter (rsms): https://rsms.me/inter/ and https://d.rsms.me/inter-website/v3/
- Inter — Google Fonts: https://fonts.google.com/specimen/Inter
- JetBrains Mono: https://www.jetbrains.com/lp/mono/ and https://github.com/JetBrains/JetBrainsMono and OpenType-features wiki: https://github.com/JetBrains/JetBrainsMono/wiki/OpenType-features
- IBM Plex: https://github.com/IBM/plex/
- Geist Mono — Google Fonts: https://fonts.google.com/specimen/Geist+Mono ; geist npm: https://npmjs.com/package/geist
- MDN — font-variant-numeric: https://developer.mozilla.org/en-US/docs/Web/CSS/font-variant-numeric
- MDN — font-smooth: https://developer.mozilla.org/en-US/docs/Web/CSS/font-smooth
- Linear redesign (Inter/Inter Display, LCH theming): https://linear.app/now/how-we-redesigned-the-linear-ui and DESIGN.md mirror: https://github.com/voltagent/awesome-design-md/blob/main/design-md/linear.app/DESIGN.md
- Wear OS type scale: https://developer.android.com/design/ui/wear/guides/styles/typography/type-scale-tokens

**Secondary / supporting (as cited by the reports)**
- Inter stylistic sets / Tailwind: https://lexingtonthemes.com/blog/inter-stylistic-sets-css-tailwind.html
- Tabular numbers in CSS: https://blog.authon.dev/tabular-numbers-in-css-font-variant-numeric-vs-monospace-hacks
- Designing for data density: https://paulwallas.medium.com/designing-for-data-density-what-most-ui-tutorials-wont-teach-you-091b3e9b51f4
- APCA explainers: https://www.accessibilitychecker.org/blog/apca-advanced-perceptual-contrast-algorithm/ , https://www.webyes.com/blogs/colour-contrast-accessibility/ , https://capellic.com/insights/accessible-colors
- Dark-mode eye strain / pure-black alternatives: https://www.brandhero.design/blog/dark-mode-eye-strain-when-it-helps-hurts , https://www.dmitrysergushkin.com/blog/alternatives-to-using-pure-black-000000-for-text-and-backgrounds , https://raisproject.com/dark-mode-font-readability/
- Dark mode for low vision: https://www.perkins.org/resource/dark-mode-for-low-vision/
- Variable fonts in dark mode (weight trick): https://css-tricks.com/using-css-custom-properties-to-adjust-variable-font-weights-in-dark-mode/ , https://css-tricks.com/dark-mode-and-variable-fonts/ , https://www.letterhend.com/blog/optimizing-variable-fonts-techniques-for-maintaining-text-sharpness-when-switching-to-dark-mode/
- Apple HIG typography (Figma write-up): https://gist.github.com/eonist/b9c180a67980c6e18a5184f19bff68fa
- CSS letter-spacing vs tracking conversion: https://stackoverflow.com/questions/2760784/how-to-calculate-css-letter-spacing-v-s-tracking-in-typography
- Dynamic text contrast / smoothing: https://miunau.com/posts/dynamic-text-contrast-in-css/
- Monospace fonts 2026 roundup: https://madegooddesigns.com/monospace-font/
- IBM Plex Sans / Geist library notes: https://designmd.app/library/ibm-plex-sans-typography , https://designmd.app/library/vercel-geist-minimal

---

## 11. Open / future items

### 11.A Group A — previously "not yet shipped", now SHIPPED (2026-05-30)
- ~~Tertiary / disabled tiers defined but unused~~ → **DONE**: placeholders → tertiary;
  disabled form controls + 6 ghost buttons → solid `--text-disabled`.
- ~~`cv09` (flat-top 3) + `case`; R3's `ss02`~~ → **DONE**: cv09 + case enabled on the body;
  ss02's goal met granularly via cv05/cv08/cv09.
- ~~User-selectable contrast control~~ → **DONE**: `@media (prefers-contrast: more)` (R4's
  `#f0f6fc` becomes the high-contrast primary).
- ~~Warmer/dimmer "reading" surface for narrative panes~~ → **DONE**: `--bg-reading: #1b1c21`
  on the executive-summary pane.
- ~~Validate every pair with an APCA tool~~ → **DONE**: full WCAG + APCA matrix recomputed
  live (§1.6). A physical non-Retina ClearType laptop pass is still nice-to-have, but
  `-webkit-font-smoothing` is inert on Windows so the residual risk is low.
- ~~MISP/severity fill audit~~ → **DONE** (§1.6): only the red cancel button carries text on a
  solid status fill (passes at 7.51); white-on-accent (3.10) flagged + retained.
- **Inter Display** as a separate face → effectively **DONE without a new file**: the
  self-hosted InterVariable carries the `opsz` axis and `font-optical-sizing: auto` is on, so
  the Display optical cut is applied automatically at large sizes (verified, §1.6).
- **14px running body** → applied as a **targeted** narrative-prose bump (7 sites → 14px);
  dense data deliberately stays at 13px. Genuinely-open: a full 14px *global* body, only if the
  app is ever made less dense.

### 11.B Group B — deliberate divergences, re-evaluated (2026-05-30)
Each report-conflict where the non-divergent option was chosen was re-examined; recommendation
+ disposition:
1. **Geist Sans (R4) vs Inter** — **KEEP Inter** (not applied). Inter is self-hosted with the
   full cv05/cv08/cv09/case + opsz tables we now depend on for hash/IOC disambiguation (3/4
   reports called this essential); only R4 leaned Geist, and with an "Inter fallback". `opsz`
   already covers Geist's display-cut appeal. Switching = high risk, marginal gain.
2. **Subpixel (R3) vs `-webkit-font-smoothing: antialiased`** — **KEEP antialiased** (not
   applied). Inert on the user's Windows anyway; on macOS the R1/R2/R4 majority favours
   antialiased on dark (thins light-on-dark, less halation). R3's +0.5px-weight point is a 1/4
   minority and works against the fatigue-reduction goal.
3. **Negative tracking at small sizes (R3) vs positive on small caps** — **already reconciled**
   (effectively applied). Small *lowercase* body/data already carries −1.1% from the global body
   rule (≥ R3's −0.08px@13); positive `tracking-wider` is kept only on small *uppercase* labels,
   which is correct per R1/R4/Apple/Material. No change.
4. **Brighter/warmer primary `#f0f6fc`(R4) / `#e8ecf1`(R3) vs `#e6edf3`** — **partially applied**:
   `#f0f6fc` adopted as the `prefers-contrast: more` primary (its correct home — the bright end
   of the band = more halation, so wrong as the default). `#e6edf3` stays default (validated AAA,
   user-approved). `#e8ecf1` (R3's barely-warmer) left as a one-line swap; the warm `--bg-reading`
   surface already mitigates R3's blue-on-blue halo for the narrative pane.
5. **Red `#ff6b62`(R3) vs `#ff7b72`(R4)** — **KEEP `#ff7b72`** (not applied). It is the calmer,
   less-vibrating desaturated pastel consistent with the other four R4 semantics; mixing R3's
   hotter red would break palette cohesion and there is no contrast reason (6.04–7.51, AA+).

---

## 12. Per-report caveats, confidence & process notes (so nothing is lost)

### R1 (Legibility-Centric)
- Thesis: judge every decision by whether it makes individual text easier to read — a
  "legibility-centric" system synthesizing Apple's rigor (hierarchy, optical glyph shaping)
  with Google's scalable token framework.
- The blueprint (D1–D6) is presented as copy-paste-ready Tailwind/CSS config.
- Caveat: its primary/secondary contrast figures (7.2 / 4.8:1) are under-stated vs
  recomputation and our measurement (see §5.6).

### R2 (compass) — staged rollout + caveats & confidence
- **Stage 1 (ship now, highest ROI / lowest risk):** (1) muted `#757f8a → #8d97a3` globally —
  any muted text on `#1c2333`/`#21262d` must measure ≥4.5:1; (2) `tabular-nums slashed-zero`
  on numeric cells + `liga 0 / calt 0` on mono IOC/hash cells; (3) keep primary `#e6edf3` —
  do NOT "upgrade" to `#ffffff`/`#f0f6fc` for body.
- **Stage 2 (1–2 days):** implement the D2 scale (14px base, 12px metadata, 11px uppercase)
  as Tailwind utilities; constrain weights to 400/500/600 (remove any 300/700 in dense areas);
  add `font-optical-sizing: auto`; load InterVariable + Inter Display.
- **Stage 3 (ongoing):** run every text/bg pair through a WCAG 2.2 checker AND an APCA tool —
  promotion threshold body ≥4.5:1 WCAG **and** Lc ≥75 (target Lc 90) on its actual surface;
  test on a non-Retina Windows/ClearType laptop, not only Mac Retina.
- **What would change these recommendations:** if users report halation even at `#e6edf3`, add
  a user contrast control (don't dim globally); if a more distinctive brand is needed, Geist
  Sans is the swap candidate but only after confirming 14px Windows rendering; for multi-hour
  sessions consider a warmer/dimmer reading surface for narrative panes.
- **Confidence:** HIGH on font choice, scale, weights, WCAG/APCA thresholds, OpenType, and the
  muted-grey defect (ratios ±0.1). Primer dark hexes (`#4493f8`/`#3fb950`/`#d29922`) are
  verbatim from shipped `@primer/primitives dark.css`. The four-surface ratios are R2's own
  sRGB computations (not vendor-published) — re-verify with axe/Lighthouse on rendered colors.
  Apple tracking values (−0.43px/−0.8px) and 14/13px platform body sizes come from well-
  regarded secondary write-ups. `-webkit-font-smoothing` is contested. Astigmatism ~40.4% is
  an epidemiological range. Recommending `#e6edf3` over Primer's brighter shipped `#f0f6fc` is
  a reasoned long-session deviation, not an error.

### R3 (report.md) — per-recommendation confidence
- **HIGH:** keep Inter + JetBrains Mono; the fatigue is NOT contrast failure (current colors
  pass) but cool-tinted primary fighting the blue bg (halation), too few ramp steps, missing
  OpenType features, and loose data line-height; adopt the 5-step solid-hex ramp; 14px body /
  13px table / 12px metadata; Apple-style negative tracking at UI sizes; `ss02`/`tnum`/`zero`.
- **MEDIUM:** avoid `-webkit-font-smoothing: antialiased` (keep subpixel); brighten red
  `#f85149 → #ff6b62`.
- Note: primary `#e8ecf1` at 15.95:1 sits at the upper edge of comfortable — if fatigue
  persists use warmer `#e4e9ef` (14.5:1).

### R4 (Specification) — notes
- APCA-audited across elevations (min Lc 60 body / Lc 45 small labels).
- Cool-slate grey ramp thermally aligned to the navy `#0d1117` canvas to avoid muddy brown
  undertones (explicit hue alignment).
- Frames the system (esp. negative letter-spacing) as a large perceived-quality win — read the
  "instant quality" claims as enthusiasm, not measured fact.
- Reminder: R4's D2 numeric scale values were image-encoded and are not reproduced verbatim;
  its D6 CSS heading/microcopy sizes (§3.5, §7.6) are the text-available equivalents.
