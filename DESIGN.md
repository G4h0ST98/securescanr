# index.html — Design Essence Document

> Purpose: this file captures the full design intent, inspiration, and system behind
> `frontend/index.html` so that ANY model or developer continuing the work preserves
> its essence. Read this before touching that file. Written by Claude (Fable 5), July 2026.

---

## 1. The Core Concept — "The page behaves like a scan"

SecureScanr is a security scanner. The redesign's single organizing idea:
**the homepage itself performs a scan while you watch.** Every theatrical moment on the
page is a scanner behavior made visible:

- A **boot sequence** preloader (the engine starting up)
- A **scanline** sweeping the hero (the probe)
- A **live terminal** that types out an audit of a demo site and stamps a red F (the findings)
- A **marquee** of real header/check names (the checklist)
- A **blueprint grid** section listing all 14 dimensions (the attack surface map)
- A **scroll-driven scene** where a score of 100 visibly bleeds down to 40/F as
  deductions land one by one (the grading)
- A fixed **HUD telemetry readout** showing scroll % and current section (the instrument panel)

Urgency comes from **facts staged dramatically** — never from fear-mongering, fake
scarcity, invented statistics, countdowns, or fake user counts. This is a hard rule
from the owner. The drama is in the truth: attackers scan the public web constantly,
most sites have gaps, finding out is free and takes ~30 seconds.

## 2. Inspiration / Lineage

The visual language is drawn from the Awwwards Site-of-the-Day vocabulary
(studio portfolio / premium product sites, e.g. work by Locomotive, Obys, Studio Freight-era sites):

- **Oversized uppercase display type** as the primary visual element (no hero illustration)
- **Hollow/outline text** (`-webkit-text-stroke`) that fills with color on hover
- **Serif italic × grotesk contrast** — one editorial serif voice cutting through mono/grotesk
- **Mono microcopy everywhere** — tiny letter-spaced uppercase labels doing wayfinding
- **Section numbering** ("01 / SURFACE") like chapters of a dossier
- **Film grain** overlay (SVG feTurbulence, animated in steps) for physical texture
- **mix-blend-mode: difference** fixed nav that self-inverts over any background
- **Scroll-pinned narrative scene** (300vh+ section, sticky viewport, progress-driven state)
- **Infinite marquee** band as a rhythm break
- **Magnetic buttons** on fine pointers
- **Terminal/HUD/reticle iconography** — the "techy" layer: corner ticks, dashed
  crosshair rings, text scramble-decode, blinking telemetry dot, custom thin scrollbar

## 3. Design Tokens

```css
--ink:       #050607;   /* page black — nearly pure, not gray */
--ink-2:     #0b0d10;   /* raised surfaces (terminal, hovered plans, dimensions bg) */
--accent:    #00e5b0;   /* brighter evolution of brand #00d4aa — CTAs, success, focus */
--accent-dk: #00d4aa;   /* original brand teal, used for scrollbar hover */
--red:       #ff4d5e;   /* failures, deductions, the F stamp */
--amber:     #ffb020;   /* warnings (dmarc p=none) */
--text:      #eceee9;   /* warm off-white body text */
--muted:     #8a8f98;   /* secondary text */
--muted-2:   #565b64;   /* tertiary / labels */
--line:      rgba(236,238,233,.14);  /* strong hairlines */
--line-soft: rgba(236,238,233,.07);  /* soft hairlines */
--ease-out:  cubic-bezier(.16, 1, .3, 1);  /* THE easing — use for all entrances */
```

Score color logic (used in verdict scene): score ≥ 80 → accent, ≥ 60 → amber, else red.

## 4. Typography

| Role | Font | Usage |
|---|---|---|
| Display / body | **Space Grotesk** (400–700) | headlines, UI, body. Display headlines: uppercase, `letter-spacing: -.035em`, `line-height: .92–1.02` |
| Editorial voice | **Instrument Serif** (italic) | one serif moment per section — the humanity against the machine. Always italic when used as accent |
| Machine voice | **JetBrains Mono** | terminal, labels, nav links, HUD, deduction lines. Labels: 9.5–11px, `letter-spacing: 2–3px`, uppercase |

Scale: hero h1 `clamp(50px, 9.8vw, 142px)`; section h2 `clamp(34px, 5.4vw, 72px)`;
verdict score `clamp(120px, 22vw, 300px)`; finale link `clamp(46px, 10.5vw, 150px)`.

## 5. Page Map (order matters — it's a narrative)

1. **#boot** — 3-line mono boot log, wipes up after ~950ms. Skipped under reduced motion.
2. **header** — fixed, `mix-blend-mode: difference`, mono uppercase links.
   **Grouped, not flat** — the IA carried over from WebAudit, identical on every page:
   `Scan · Tools ▾ · Plans · World Index · More ▾ · Get API access →`
   where Tools = Versus / Generators / Security.txt / API Docs / Learn / Badge and
   More = Methodology / About / SecurityHeaders Alt / Compliance Report / Status.
   A flat list strands eight pages in the footer — don't reintroduce one.
   Panels are opaque `--ink-2` on a hairline border; the trigger's `+` rotates 45°.
   Mobile: "MENU +" opens a fullscreen overlay listing every link under mono group headers.
   **Docked state:** past `scrollY > 40` the header gains `.docked`, which switches
   `mix-blend-mode` to `normal` and fades in a `header::before` backdrop
   (`rgba(5,6,7,.82)` + 14px blur + hairline bottom border). Without this, difference
   blending lets scrolled headlines pass *through* the nav glyphs instead of behind
   them, and the two tangle illegibly. `.nav-inner` needs `position: relative; z-index: 1`
   to sit above the backdrop. An **open dropdown forces the same state** (JS toggles it
   on mouseenter/focusin), otherwise the panel blends into whatever is behind the header.
   Every page carries this — keep it consistent.
3. **#hero** — kicker → giant h1 ("FIND THE *GAPS* BEFORE THEY DO." — GAPS is hollow
   stroke, hover-fills accent; final period is an accent dot) → 2-col row: copy+CTA left,
   terminal right (hidden < 900px). Terminal `.term-body` has `min-height: 22em` which
   RESERVES the fully-typed height — do not remove, it prevents the bottom-aligned hero
   row from growing/shifting while lines type in. Hero fits exactly in 768px viewport height.
4. **marquee** — real check names, CSS translateX(-50%) loop, content duplicated 2× for seam.
5. **#dimensions** — "Fourteen ways in. / One scan to see them all." Blueprint aesthetic:
   `--ink-2` bg + 44px teal grid lines (two linear-gradients). 14 rows injected by JS
   (numbered 01–14, name, one-line why-it-matters). Hover: row fills **accent**, text inverts
   to ink, indents 18px. (Was originally a paper-white inverted section; owner preferred
   all-dark cohesion — the grid keeps it a distinct "moment.")
6. **#verdict** — 340vh tall, sticky inner viewport. Left: huge tabular-nums score +
   grade pill, dashed crosshair rings rotating slowly behind. Right: serif-accented title
   ("Every site starts at 100. / *Then the findings land.*") + 5 deduction rows.
   Scroll progress drives it: each row has `data-at` (progress threshold) and `data-pts`;
   when passed, row lights up, points subtract, the displayed number eases toward the
   target (lerp ×0.14/frame). 100 → 40, A+ → F, teal → amber → red.
   **The five deductions use SecureScanr's REAL scoring weights** (CSP −20, HSTS −20,
   X-Frame-Options −10, DMARC p=none −5, cookie missing HttpOnly −5 — per methodology).
   Never invent weights.
7. **#creed** — the manifesto band. Instrument Serif, centered, huge:
   "Attackers scan sites like yours every day. The only question is whether *you see the
   gaps first.*" (accent italic tail). This line is sacred — keep it.
8. **#access** — pricing triptych in a hairline-bordered grid: Free ₹0 / Pro ₹499 ($7 intl,
   highlighted, corner ticks) / Agency ₹999 ($28 intl). Footnote: ₹99 one-time scan,
   ₹249 compliance report, Razorpay-India/LemonSqueezy-intl.
9. **#finale** — outline mega-type "WHAT'S YOUR GRADE?" links to scan.html, fills accent
   on hover. Easter egg below: **press S anywhere → scan.html** (disabled in inputs/textareas).
10. **footer** — 4-column, mono column headers, full site links.

## 6. The Techy/HUD Layer (added in round 2)

- **#hud** — fixed bottom-left telemetry: pulsing accent dot + `SCROLL 042% · 02 / VERDICT`.
  Mono 9.5px, `mix-blend-mode: difference`, hidden < 900px, `aria-hidden`.
  Section map: 00/INIT (hero), 01/SURFACE, 02/VERDICT, 03/CREED, 04/ACCESS, 05/SCAN.
- **Scramble decode** — mono labels (`.hero-kicker, .sec-num, .v-label, .finale-kicker`)
  decode from random chars (`#%&$@01<>/*+=`) over ~16–40 frames when they enter viewport. Once.
- **[data-ticks]** — reticle corner brackets (top-left + bottom-right L-shapes, accent 55%)
  on the terminal and the Pro plan card.
- **Crosshair rings** — two concentric circles behind the verdict score; outer one dashed,
  rotating 60s/turn.
- **Stamp jitter** — the F grade badge does a 2-step glitch settle after stamping.
- **Custom scrollbar** — thin, dark thumb, accent on hover.

## 7. Motion Rules

- Entrances: `.rv` class — `translateY(26px) + opacity 0 → none/1`, `.7s var(--ease-out)`,
  IntersectionObserver adds `.in` once (threshold .12, rootMargin -6% bottom).
  `.rv` is in the HTML but content is visible-by-default philosophy for dynamic content:
  the 14 dimension rows are JS-injected with their own observer pass, and a `<noscript>`
  fallback row exists.
- Terminal typing: command line types at 24ms/char; output lines appear whole with
  200–420ms gaps; grade stamps 380ms after the summary line. Starts when terminal is 30%
  visible, +1.1s (so it plays after the boot wipe).
- **Everything respects `prefers-reduced-motion: reduce`**: boot removed, typing renders
  final state instantly, marquee/scanline/grain/rings frozen, verdict shows final 40/F
  state, scramble skipped, magnetic disabled. Both a CSS media query and a JS `RM` flag
  handle this — keep both when editing.
- Magnetic buttons only when `(pointer: fine)`.
- Scroll handlers are rAF-throttled and `{ passive: true }`.

## 8. Voice & Copy Rules

- Tone: **calm authority with stakes.** Facts staged dramatically, never hype.
- FORBIDDEN: fake scarcity, countdown timers, invented statistics ("87% of sites…"),
  fake user counts, "hurry", "trusted by X" claims without receipts.
- Proof line format: `No signup · 14 dimensions · ~30 seconds` (mono, letterspaced).
- The 14 dimensions framing: headers(6) + CORS + fingerprint + TLS + email-DNS +
  CAA/DNSSEC + cookies + cross-origin isolation + page integrity = 14. Keep consistent.
- Every failing check "comes with the exact fix / ready to paste" — this is the product's
  core promise, repeat it at hero, dimensions footer, verdict caption, creed sub.
- Prices are real: Free ₹0, Pro ₹499/mo ($7 intl), Agency ₹999/mo ($28 intl),
  OTS ₹99, Compliance ₹249 ($3). Don't drift from CLAUDE.md.

## 9. Technical Constraints

- **Vanilla only** — no frameworks, no build step (project rule). One HTML file,
  inline CSS + JS. Google Fonts via @import (Space Grotesk, Instrument Serif, JetBrains Mono).
- Keep: gtag snippet, favicons, all SEO meta, canonical, JSON-LD Organization block,
  google-site-verification, indexnow-key meta.
- All internal links are relative (scan.html, plans.html, …) — file:// testable.
- `100svh` (not vh) for hero/sticky heights.
- HTML entities: the file avoids raw `<` in JS strings where it could confuse parsers.
- Verify with headless Chrome (puppeteer lives in `~/node_modules`); check hero fits
  768px viewport height, no console errors (favicon 404s over file:// are expected),
  and screenshot #dimensions, #verdict mid-scroll (~75%), #creed, #access, #finale, mobile 390px.

## 9b. Tool Pages (scan.html and friends)

index.html is a narrative; tool pages are instruments. Two rules learned on scan.html:

- **The input is the product.** Don't spend the fold on copy. Order is
  kicker → headline → **the control** → proof line → explanation → chips.
  Hero uses `min-height: min(100svh, 840px)` — a hard `100svh` strands the control
  mid-screen on tall desktops. Verify the control's `bottom` sits well above the fold
  at 1368×590 (a laptop with browser chrome), not just at 1440×900.
- **No borrowed theatre.** Tool pages inherit the system (tokens, type, docked nav,
  grain, hairlines, footer) but not index's set-pieces — no boot sequence, no marquee,
  no verdict scene, no creed, no finale mega-type. Where removing one leaves a
  structural gap, close it with a hairline, not another spectacle.

## 10. What NOT To Do

- Don't add slide-ins from the sides, parallax, scale-pops, or scroll-jacking.
- Don't re-introduce the light/paper section unless redesigning the whole rhythm.
- Don't let the terminal grow while typing (keeps `min-height: 22em`).
- Don't animate anything the RM flag doesn't gate.
- Don't replace the creed line or soften the hero headline into marketing mush.
- Don't use pure #000 or pure #fff anywhere; the palette is warm-black/warm-white.
- Don't add a second accent color; teal + red + amber is the complete emotional range
  (teal = you're safe, red = finding, amber = warning).
