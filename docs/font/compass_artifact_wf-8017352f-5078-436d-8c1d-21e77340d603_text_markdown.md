# Typography & Text-Color Specification for a Dark, Dense, Data-Heavy SOC Dashboard

**Bottom line: keep Inter + JetBrains Mono and keep your existing background/border tokens — they are the correct, defensible foundation. Your eye-fatigue problem is not low contrast; it is (1) near-white primary text causing halation on near-black, (2) one muted grey (`#757f8a`) that quietly fails AA on your two lightest surfaces, (3) over-saturated semantic colors used for long text runs, and (4) missing tabular numerals/ligature controls in data cells. Fix those four things with the solid-hex ramp, density-first 14px scale, and OpenType settings below and you reach Apple/Google-grade comfort without changing fonts.**

---

## A. Executive Summary

- **Inter + JetBrains Mono are right.** Inter ships tabular numerals, slashed-zero, contextual alternates, and optical "text"/"display" cuts; JetBrains Mono maximizes lowercase x-height and disambiguates 0/O/1/l/I — both critical for hashes/IOCs. SF Pro is **licensed to registered Apple developers only, for building apps on Apple's platforms**, so it cannot be web-embedded. Borrow Apple's *method*, not its font.
- **Your contrast is already high; brightness management is the issue.** Primary `#e6edf3` scores ~15.8:1 on `#0d1117` — well into AAA. Fatigue comes from luminance/halation and rendering, not from failing ratios.
- **Never use `#ffffff` for body text on near-black.** Pure white maximizes halation (optical bloom) — worst for the ~40% of adults with astigmatism. Cap primary at off-white `#e6edf3`.
- **Use solid hex, not alpha, for text.** Alpha text re-composites differently over each of your four surfaces, giving four unpredictable contrast ratios. Solid hex is deterministic — it is what GitHub Primer ships.
- **Fix the muted grey.** `#757f8a` is 4.65:1 on `#0d1117` but drops to ~3.7:1 on `#21262d`, failing AA body text on your two lightest surfaces. Replace with `#8d97a3` (~6.4:1) for all-surface safety.
- **Adopt a density-first 14px base scale** (GitHub/Carbon "productive" convention), 12px metadata, 11px uppercase labels — not the 16px marketing default.
- **Tabular numerals + slashed-zero everywhere numbers align.** `font-variant-numeric: tabular-nums slashed-zero` keeps columns of hashes, ports, scores, and ATT&CK IDs aligned and unambiguous.
- **Disable ligatures in data cells** (use JetBrains Mono NL or `calt 0`/`liga 0`); optionally enable them only in syntax-highlighted YARA/Sigma/Suricata blocks.
- **Restrict weights to 400–600.** Avoid Thin/Light (100–300) on dark (strokes thin/bloom); avoid 700+ for dense headers (visual noise).
- **Validate against both WCAG 2.2 and APCA.** WCAG over-states contrast near black; APCA (Lc) is the better dark-mode model. Ship colors that pass both.

---

## B. Findings by Research Area

### 1. Type Families & Strategy

**Apple (SF Pro).** San Francisco uses *optical sizes*: SF Pro Text (≤19pt) has wider spacing and slightly heavier strokes for small sizes; SF Pro Display (≥20pt) has tighter spacing and refined strokes. Apple type designer Loïc Sander confirmed at WWDC20 ("The details of UI typography") that "with SF Pro becoming a variable font, there is no hard break around 20 points anymore and the design now transitions from Text to Display between 17 and 28 points… we've had to update the tracking tables." SF Mono is the monospace (used in Xcode); SF numbers are proportional by default. **License: registered Apple developers only, for designing/developing applications for Apple's platforms — not embeddable on the web.**

**Google (Material 3).** Roboto is the default; M3 Expressive moves to Roboto Flex (variable weight 100–1000, plus width axis). Web font stack guidance is `Roboto, Noto, sans-serif`. Google Sans Text is reserved for Google's own products. Roboto is freely available via Google Fonts under the Apache 2.0 license.

**Open web options.** Inter (SIL OFL), Geist/Geist Mono (Vercel, OFL — explicitly "influenced by Inter, Univers, SF Mono, SF Pro, Suisse International"), IBM Plex (Carbon's family, OFL), JetBrains Mono (OFL).

**Recommendation:** **Inter** (UI sans) + **JetBrains Mono** (monospace). Inter has a tall x-height, ink-traps and contrast-enhancing details in its "text" optical size, and the OpenType features (tnum, slashed-zero, contextual alternates) that data UI needs. JetBrains Mono "maximizes the height of the lowercase" for crisper small rendering, ships **138–139 code ligatures plus a dedicated JetBrains Mono NL (No Ligatures) build with identical metrics** — so you can drop ligatures in data cells with zero layout shift. Optional display face: **Inter Display** (the variable display optical cut) for large page titles only. A credible alternative to Inter is **Geist Sans** if you want a sharper, more "technical" personality — but note independent testing reports Geist's tight apertures "start to feel cramped at 14 pixels" on Windows ClearType, which is a real risk for a dense dashboard, so Inter remains the safer pick for 14px body.

### 2. Type Scale

**Apple** applies *size-specific tracking* automatically: positive tracking at small sizes for legibility, negative at headline sizes. Published spec examples: **SF Pro Text 17pt body = −0.43px tracking; SF Pro Display 28pt ≈ −0.8px.** Leading is size-derived. iOS body defaults to 17pt; macOS body 13pt; minimum text style 11pt.

**Material 3** type scale (Roboto), exact tokens from `m3.material.io/styles/typography/type-scale-tokens`:
- Body Large: 16sp / 24sp line-height / +0.5px tracking / weight 400 (`--md-sys-typescale-body-large-tracking: 0.03125rem`)
- Body Medium: 14sp / 20sp / +0.25px / 400
- Body Small: 12sp / 16sp / +0.4px / 400
- Title Medium: 16sp / 24sp / +0.15px / 500 (`tracking: 0.009375rem`)
- Label Large: 14sp / 20sp / +0.1px / 500
- Label Small: 11sp / 16sp / +0.5px / 500

M3, like Apple, puts **positive** tracking on small text and negative on large.

**Density systems.** IBM Carbon "productive" uses a **14px base** (vs 16px expressive): body-compact-01 = 14px / 18px line-height / +0.16px; label-01 = 12px / 16px / +0.32px; code-01 = 12px / 16px (IBM Plex Mono) / +0.32px. GitHub Primer uses rem-based tokens on a 4px grid, system-font stacks, weights light/normal/medium/semibold, and explicitly advises **against using color as the primary emphasis method** and **against altering letter-spacing** ("Please refrain from altering letter-spacing on our products"). Linear uses Inter with tight tracking (−0.011em body, −0.022em display) on a near-black canvas, plus Inter Display for headings.

**Minimum comfortable sizes (dense UI):** 14px body/narrative; 13px monospace cells (mono reads visually larger at equal px); 12px metadata; 11px uppercase labels (weight 500+, positive tracking). Do not go below 11px for any essential text.

### 3. Weights

- **Body / table data:** 400 (Regular). Under macOS grayscale AA, light-on-dark renders slightly lighter, so do not go below 400.
- **Secondary emphasis / labels / column headers:** 500 (Medium).
- **Headings / KPI values / strong emphasis:** 600 (SemiBold).
- **Avoid 100–300 on dark.** Apple's HIG explicitly warns Ultralight/Thin/Light "can be difficult to see"; on near-black they bloom and thin out. Google's Wear guidance echoes this: "be careful of using too light a weight type for body text."
- **Avoid 700+ for dense headers** — over-bold adds noise; reserve for rare large display.
- Use the **variable** fonts (InterVariable, JetBrains Mono variable) to access intermediate weights (e.g. 450, or Linear's 510 for subsection heads) from a single file.

### 4. Text Color & Contrast (most important)

**Solid hex vs alpha.** Use **solid hex**. Alpha text (`rgba(255,255,255,.7)`) re-composites over every surface — over `#0d1117`, `#161b22`, `#1c2333`, and `#21262d` it produces four different effective colors and four different contrast ratios, which is unmanageable for a multi-surface SOC layout. Primer ships solid-hex foreground tokens for exactly this reason; Material 3 reserves alpha for disabled states only.

**Why avoid `#fff`; ideal off-white.** Pure white on near-black maximizes halation — the optical bloom where letters appear to glow/bleed. It disproportionately affects people with astigmatism, whose **estimated pooled worldwide prevalence in adults is approximately 40.4%** (US figures range 11–46%). Cap primary text in the `#e6edf3`–`#f0f6fc` band. I recommend **`#e6edf3`** (~15.8:1) over Primer's brighter shipped `#f0f6fc` (~16.5:1) for long-session reading — it sheds a little bloom while staying crisp.

**Hue/temperature.** `#0d1117` is a cool, blue-tinted near-black. Keep the grey ramp **slightly cool/low-chroma** so text integrates rather than reading "dirty." Do not introduce warm greys against this cool canvas — the temperature mismatch looks muddy. This matches Linear's desaturated-blue neutrals and Primer's neutral scale.

**Measured WCAG 2.2 contrast (computed against `#0d1117`, relative luminance L_bg ≈ 0.0056):**

| Color | Hex | Contrast vs #0d1117 |
|---|---|---|
| Primary text | #e6edf3 | ~15.8:1 |
| Secondary text | #9aa4af | ~7.5:1 |
| Tertiary/metadata | #768491 | ~4.9:1 |
| Muted (current) | #757f8a | ~4.65:1 |
| Disabled | #5a6571 | ~3.1:1 |
| Blue/link | #4493f8 | ~6.1:1 |
| Red | #f85149 | ~5.6:1 |
| Green | #3fb950 | ~7.5:1 |
| Orange | #d29922 | ~7.5:1 |
| Purple | #bc8cff | ~7.5:1 |

**The critical defect:** muted text degrades on lighter surfaces. `#757f8a` is 4.65:1 on `#0d1117` but only ~3.7:1 on `#21262d` — it **fails AA body text on your two lightest surfaces.** Fix: bump muted to **`#8d97a3`** (~6.4:1 on `#0d1117`, ~4.95:1 on `#21262d`, passes everywhere), or restrict `#757f8a` to the darkest surface and large/non-essential text only.

**Semantic / accent text.** Apple and Google keep accent *text* legible by using lighter, slightly desaturated tints on dark rather than the saturated fill color. Your semantic set is GitHub's dark palette and is well-calibrated (all ≥5.6:1). Verified against Primer's currently shipped `dark.css`: `--fgColor-accent: #4493f8`, ANSI green `#3fb950`, ANSI yellow `#d29922`, danger family around `#f85149`/`#da3633`, done/purple `#bc8cff`/`#ab7df8`. Watch the blue at ~6.1:1 — fine for links/large text, but for small inline links prefer GitHub's brighter `#58a6ff` (~7.0:1). Use bright red `#f85149` for short tokens (severity tags), not long runs, to limit chromatic fatigue.

### 5. Accessibility

- **WCAG 2.2:** 4.5:1 normal text; 3:1 large text (≥18px regular / ≥14px bold) and UI components/icons (SC 1.4.11). Thresholds unchanged from 2.1.
- **APCA (WCAG 3 draft), per Myndex "APCA in a Nutshell":** perceptually uniform; dark mode yields negative Lc. **"Lc 90 • Preferred level for fluent text and columns of body text with a font no smaller than 18px/weight 300 or 14px/weight 400." "Lc 75 • The minimum level for columns of body text with a font no smaller than 24px/300 weight, 18px/400, 16px/500 and 14px/700." Lc 60 is the minimum recommended for non-body content text. "Consider Lc 15 the point of invisibility for many users."** Because WCAG 2 "far overstates contrast for dark colors to the point that 4.5:1 can be functionally unreadable when a color is near black," APCA is the better dark-mode guide — ship colors that pass both.
- **Dark-mode specifics.** Halation (light bleeding past glyph edges) is worst with pure white on pure black and disproportionately affects astigmatism/myopia. Mitigations: off-white not white; off-black not black (`#0d1117` is correctly off-black); slightly larger sizes; a touch more weight; avoid ultra-thin strokes. High contrast can *also* fatigue (21:1 black-on-white triggers migraines for some), so target a "Goldilocks" band for primary body of roughly **AAA (7:1) up to ~15:1, not 21:1.**
- **AA minimums on dark:** ≥14px/400 at ≥4.5:1 for body; 11px allowed only for labels at weight 500+ and ≥4.5:1.

### 6. Rendering / OpenType

- **`font-variant-numeric: tabular-nums`** on every table, score, port, timestamp, and KPI — locks digit widths so columns of hashes/scores/IPs align. Exposed as `.tabular-nums` in Tailwind.
- **Slashed zero** (`"zero" 1` / `slashed-zero` for Inter; JetBrains Mono ships a dotted zero by default) — disambiguates 0 from O in hashes and keys.
- **Contextual alternates / ligatures (`calt`, `liga`):** enable for Inter UI text (Inter's `calt` adjusts punctuation by context). For JetBrains Mono, **disable ligatures in data cells** (use the NL build or `"liga" 0, "calt" 0`) so `->`, `!=`, `==` inside IOCs/rules are never visually fused; optionally enable in syntax-highlighted rule blocks where fusing aids reading.
- **Optical sizing (`opsz`).** InterVariable and Inter Display expose an optical-size axis — `font-optical-sizing: auto;` lets large titles use the display cut and body the text cut automatically (Apple's principle, implemented on the open web).
- **Disambiguation alternates.** Inter's stylistic sets/character variants (e.g. `cv05`) improve 1/l/I separation; at minimum combine slashed-zero + tabular-nums.
- **`-webkit-font-smoothing`.** This is **macOS-only** (`-moz-osx-font-smoothing: grayscale` is Firefox-macOS-only); neither affects Windows/Linux. `antialiased` switches macOS from subpixel to grayscale AA, which makes light-on-dark text *lighter and thinner* — this **counters the subpixel "bloat" that light-on-dark text suffers**, so for a dark UI it is usually desirable. Trade-off: glyphs render slightly lighter, so pair it with weight ≥400 and don't also dim primary text. (Note the dissent: subpixel rendering is technically sharper; if your audience is heavily Windows, the property is moot there anyway.)

### 7. Apple vs Google Philosophy — what to borrow

- **Apple:** content-deference; one family with optical sizes and automatic size-specific tracking/leading; restrained weights; proportional numerals; tight hierarchy. **Borrow:** optical sizing, size-specific tracking, weight restraint, "let type defer to the data."
- **Google (M3):** token-driven, role-based emphasis (`on-surface` / `on-surface-variant`); variable fonts; explicit tracking tables; tonal surfaces for elevation rather than borders. **Borrow:** the token architecture (maps directly to Tailwind `@theme`), the on-surface emphasis tiers, contrast-as-tone for layering.
- **Synthesis for a SOC tool:** use Google's **token/role system** and emphasis tiers, with Apple's **discipline** (one sans + one mono, optical sizing, restrained weights, tight size-specific tracking, numbers that defer). GitHub Primer is your closest real-world precedent (dark, dense, code/data-heavy) and Linear your closest aesthetic precedent (Inter, near-black, low-chroma neutrals) — both validate this exact direction.

---

## C. Apple vs Google Comparison Table

| Dimension | Apple (HIG / SF Pro) | Google (Material 3 / Roboto) |
|---|---|---|
| Core font | SF Pro (variable, optical sizes) | Roboto / Roboto Flex (variable) |
| Web availability | Apple-platform apps only (not embeddable) | Free via Google Fonts (Apache 2.0) |
| Optical sizing | Yes, automatic (Text↔Display 17–28pt) | Roboto Flex `opsz` axis |
| Tracking | Size-specific, automatic, negative at large | Explicit per-token, positive at small |
| Weights | Restrained; warns against Thin/Light | Plain + brand; 400 / 500 / 700 |
| Numerals | Proportional by default | Proportional; tabular available |
| Text-color model | Semantic, auto light/dark | Token roles (on-surface / on-surface-variant), tonal |
| Emphasis method | Weight + size + restrained color | Tone (on-surface vs on-surface-variant) + weight |
| Elevation | Material/blur | Tonal surface overlays |
| Best to borrow | Optical sizing, tracking, restraint | Token/role architecture, emphasis tiers |

---

## D. Implementation Appendix

### D1. Font stacks (exact CSS font-family strings)

```css
/* Sans (UI + narrative) */
--font-sans: 'InterVariable', 'Inter', -apple-system, BlinkMacSystemFont,
  'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;

/* Monospace (hashes, IOCs, IPs, rules, code) */
--font-mono: 'JetBrains Mono', 'JetBrains Mono NL', ui-monospace,
  'SFMono-Regular', 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace;

/* Optional display (large page titles only) */
--font-display: 'Inter Display', 'InterVariable', 'Inter',
  -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
```
Load InterVariable via `@font-face`/`next/font/local`, gated with `@supports (font-variation-settings: normal)` and falling back to static Inter — Inter's own recommended pattern.

### D2. Type scale

| Token | px | rem | line-height | letter-spacing | weight | role |
|---|---|---|---|---|---|---|
| display | 28 | 1.75 | 34px (1.21) | −0.4px (−0.014em) | 600 | page title (rare) |
| title-lg | 22 | 1.375 | 28px (1.27) | −0.3px | 600 | section title |
| title-md | 18 | 1.125 | 24px (1.33) | −0.2px | 600 | card / panel header |
| body-lg | 16 | 1.0 | 24px (1.5) | 0 | 400 | dialog / emphasis body |
| body | 14 | 0.875 | 20px (1.43) | 0 | 400 | default body / narrative |
| body-compact | 14 | 0.875 | 18px (1.29) | 0 | 400 | table cells, dense rows |
| metadata | 12 | 0.75 | 16px (1.33) | +0.16px | 400 | timestamps, secondary meta |
| label | 11 | 0.6875 | 16px (1.45) | +0.4px, uppercase | 500 | section labels, column heads |
| mono-md | 13 | 0.8125 | 20px (1.54) | 0 | 400 | hashes / IOCs in cells |
| mono-sm | 12 | 0.75 | 18px (1.5) | 0 | 400 | inline mono, badges |
| code-block | 13 | 0.8125 | 20px (1.54) | 0 | 400 | YARA/Sigma/Suricata blocks |

### D3. Dark-mode text color ramp

| Token | Hex | Role | Contrast vs #0d1117 | WCAG verdict |
|---|---|---|---|---|
| text-primary | #e6edf3 | body, hashes, primary values | ~15.8:1 | AAA |
| text-secondary | #9aa4af | labels, secondary data | ~7.5:1 | AAA |
| text-tertiary | #768491 | metadata on darkest surface | ~4.9:1 | AA (body, #0d1117 only) |
| text-muted | #8d97a3 | safe muted, all surfaces | ~6.4:1 | AAA |
| text-disabled | #5a6571 | disabled only (non-essential) | ~3.1:1 | Fails body (OK for disabled) |
| text-onEmphasis | #ffffff | text on saturated fills | n/a (per fill) | check per fill |

### D4. Text-on-background pairing matrix

| Background | primary | secondary | tertiary / muted |
|---|---|---|---|
| #0d1117 (canvas) | #e6edf3 (~15.8:1) | #9aa4af (~7.5:1) | #768491 (~4.9:1) ✓ |
| #161b22 (surface) | #e6edf3 (~14.6:1) | #9aa4af (~6.9:1) | #8d97a3 (~5.6:1) ✓ — avoid #768491 (~4.5:1 borderline) |
| #1c2333 (raised) | #e6edf3 (~13.3:1) | #9aa4af (~6.3:1) | #8d97a3 (~5.1:1) ✓ — #768491 fails (~4.0:1) |
| #21262d (lightest) | #e6edf3 (~12.9:1) | #9aa4af (~6.1:1) | #8d97a3 (~4.95:1) ✓ — #757f8a/#768491 fail (~3.7–3.9:1) |

**Rule:** primary and secondary pass on all four surfaces. For muted/tertiary text on `#1c2333` and `#21262d`, always use `#8d97a3` (or make the text large/bold) — never `#757f8a` or `#768491`.

### D5. Semantic + link/accent colors

| Name | Hex | Contrast vs #0d1117 | Notes |
|---|---|---|---|
| accent / link | #4493f8 | ~6.1:1 | use #58a6ff (~7.0:1) for small inline links |
| danger / error | #f85149 | ~5.6:1 | short tokens only; avoid long runs |
| warning | #d29922 | ~7.5:1 | matches Primer ANSI yellow |
| success | #3fb950 | ~7.5:1 | matches Primer ANSI green |
| info / done (purple) | #bc8cff | ~7.5:1 | |
| severe (orange-red) | #db6d28 | ~4.7:1 | high-priority fills/borders, not small text |

### D6. Recommended font-feature-settings & rendering CSS

```css
:root {
  font-family: var(--font-sans);
  font-feature-settings: 'liga' 1, 'calt' 1, 'cv05' 1; /* Inter UI defaults */
  font-variant-numeric: tabular-nums slashed-zero;      /* align + 0≠O */
  font-optical-sizing: auto;
  -webkit-font-smoothing: antialiased;                  /* macOS: lighter on dark */
  -moz-osx-font-smoothing: grayscale;
}
h1, h2, h3 { text-rendering: optimizeLegibility; }       /* headings only */

/* Numeric / aligned data */
.tnum, td.num, .score, .port, .timestamp {
  font-variant-numeric: tabular-nums slashed-zero;
  font-feature-settings: 'tnum' 1, 'zero' 1;
}

/* Monospace data cells — ligatures OFF for IOC/hash safety */
.mono, code.ioc, td.hash {
  font-family: var(--font-mono);
  font-feature-settings: 'liga' 0, 'calt' 0, 'zero' 1;
  font-variant-numeric: tabular-nums;
}

/* Rule code blocks — ligatures OPTIONAL */
pre.rule, .yara, .sigma, .suricata {
  font-family: var(--font-mono);
  font-feature-settings: 'liga' 1, 'calt' 1;
}

/* Uppercase section labels */
.label {
  font-size: 0.6875rem; line-height: 1rem;
  letter-spacing: 0.04em; text-transform: uppercase; font-weight: 500;
  color: var(--color-text-secondary);
}
```

**Tailwind v4 `@theme` tokens (drop-in):**

```css
@theme {
  /* Surfaces — your existing values, kept */
  --color-canvas: #0d1117;
  --color-surface: #161b22;
  --color-raised: #1c2333;
  --color-overlay: #21262d;
  --color-border: #30363d;
  --color-border-muted: #21262d;

  /* Text ramp — solid hex, halation-managed */
  --color-text-primary: #e6edf3;
  --color-text-secondary: #9aa4af;
  --color-text-tertiary: #768491;   /* darkest surface only */
  --color-text-muted: #8d97a3;      /* all-surface safe — replaces #757f8a */
  --color-text-disabled: #5a6571;

  /* Semantic */
  --color-accent: #4493f8;
  --color-accent-strong: #58a6ff;   /* small inline links */
  --color-danger: #f85149;
  --color-warning: #d29922;
  --color-success: #3fb950;
  --color-info: #bc8cff;
  --color-severe: #db6d28;
}
```

---

## E. Sources

1. Apple HIG — Typography: https://developer.apple.com/design/human-interface-guidelines/typography
2. Apple Fonts (SF Pro / SF Mono, license terms): https://developer.apple.com/fonts/
3. Apple WWDC20 — "The details of UI typography" (optical sizes, tracking tables): https://developer.apple.com/videos/play/wwdc2020/10175/
4. Material 3 — Typography: https://m3.material.io/styles/typography
5. Material 3 — Type scale tokens: https://m3.material.io/styles/typography/type-scale-tokens
6. Material 3 — Color roles: https://m3.material.io/styles/color/roles
7. WCAG 2.2: https://www.w3.org/TR/WCAG22/
8. APCA — "In a Nutshell" (Lc levels): https://git.apcacontrast.com/documentation/APCA_in_a_Nutshell.html
9. APCA / Myndex — Why APCA + repo: https://github.com/Myndex/SAPC-APCA
10. GitHub Primer — Typography: https://primer.style/foundations/typography
11. GitHub Primer — Color usage / UI color system: https://primer.style/foundations/color/overview/
12. GitHub Primer — shipped dark tokens (`@primer/primitives` dark.css): https://unpkg.com/@primer/primitives/dist/css/functional/themes/dark.css
13. IBM Carbon — Typography (productive vs expressive, type sets): https://carbondesignsystem.com/elements/typography/overview/ and https://carbondesignsystem.com/guidelines/typography/type-sets/
14. Vercel Geist — Typography: https://vercel.com/geist/typography
15. Inter (rsms): https://rsms.me/inter/
16. JetBrains Mono (features, NL build, ligatures): https://www.jetbrains.com/lp/mono/ and https://github.com/JetBrains/JetBrainsMono
17. MDN — font-variant-numeric: https://developer.mozilla.org/en-US/docs/Web/CSS/font-variant-numeric
18. MDN — font-smooth / -webkit-font-smoothing: https://developer.mozilla.org/en-US/docs/Web/CSS/font-smooth
19. Linear — UI redesign (LCH theming, Inter/Inter Display): https://linear.app/now/how-we-redesigned-the-linear-ui

---

## Recommendations (staged, with thresholds)

**Stage 1 — Ship now (highest ROI, lowest risk):**
1. Replace muted `#757f8a` → `#8d97a3` globally. *Threshold to confirm:* any muted text on `#1c2333`/`#21262d` must measure ≥4.5:1.
2. Apply `font-variant-numeric: tabular-nums slashed-zero` to all numeric/data cells and `font-feature-settings: 'liga' 0, 'calt' 0` to monospace IOC/hash cells.
3. Confirm primary stays `#e6edf3` (do not "upgrade" to `#ffffff` or `#f0f6fc` for body).

**Stage 2 — Type scale + weights (1–2 days):**
4. Implement the D2 scale (14px base, 12px metadata, 11px uppercase labels) as Tailwind text utilities.
5. Constrain weights to 400/500/600; audit and remove any 300 or 700 in dense areas.
6. Add `font-optical-sizing: auto` and load InterVariable + Inter Display.

**Stage 3 — Validation (ongoing):**
7. Run every text/background pair through both a WCAG 2.2 checker and an APCA tool (Lc). *Promotion threshold:* body must hit ≥4.5:1 WCAG **and** Lc ≥75 (target Lc 90) on its actual surface.
8. Test on a non-Retina Windows/ClearType laptop, not just a Mac Retina display, since `-webkit-font-smoothing` is inert there and Inter at 14px is where rendering problems surface.

**What would change these recommendations:**
- If a meaningful share of users report halation/eye strain even at `#e6edf3`, add a user-selectable contrast control (Linear's model: base + accent + contrast variables) rather than dimming globally.
- If you later need a more distinctive brand voice, Geist Sans is the swap candidate — but only after confirming it holds up at 14px on Windows; otherwise keep Inter.
- If analysts run multi-hour sessions, consider offering a slightly warmer/dimmer "reading" surface variant for long narrative panes, keeping the cool data surfaces unchanged.

---

## Caveats & Confidence

- **High confidence:** font recommendation, type scale, weight guidance, WCAG/APCA thresholds, OpenType settings, and the muted-grey defect (computed from luminance; ratios are accurate to ±0.1). The Primer dark semantic hexes (`#4493f8`, `#3fb950`, `#d29922`) are confirmed verbatim from the currently shipped `@primer/primitives/dist/css/functional/themes/dark.css`.
- **Computed, not vendor-published:** the exact contrast ratios for your four surfaces against the text ramp are my sRGB relative-luminance calculations, not figures published by GitHub/Google. They are reliable but should be re-verified in your build with an automated checker (axe/Lighthouse) against rendered colors, since border/shadow compositing can shift effective background luminance slightly.
- **Source-quality note:** several supporting data points (Apple tracking values like −0.43px/−0.8px; the 14px/13px platform body sizes) come from well-regarded secondary write-ups of Apple's spec rather than a single canonical Apple table, because Apple distributes tracking values across Design Resources files and WWDC material rather than one web page. The *principle* (size-specific tracking, Text↔Display 17–28pt) is confirmed directly from Apple's WWDC20 session.
- **`-webkit-font-smoothing` is contested.** It genuinely helps light-on-dark on macOS but is inert on Windows/Linux and some engineers consider it a regression for dark-on-light. The recommendation is scoped to your dark UI; re-evaluate if you ever ship a light theme.
- **Astigmatism prevalence (~40.4% pooled adult worldwide; 11–46% US)** is an epidemiological range, not a precise figure for your user base — cited to justify off-white over pure white, which is low-risk regardless.
- **GitHub default dark primary text:** Primer currently ships `#f0f6fc` as the brightest foreground; I deliberately recommend the slightly dimmer `#e6edf3` for halation comfort in a long-session SOC context. This is a reasoned deviation, not an error — both are valid; pick `#f0f6fc` only if analysts report the text feels too dim.
