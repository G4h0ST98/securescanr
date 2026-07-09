# WebAudit v2 — Claude Code Master Brief

Read this entire document before writing a single line of code.
Project root: ~/Desktop/2026/WebAudit

---

## CONTEXT

WebAudit (webaudit.in) is a freemium web security scanner for pentesters and developers.
Stack: Python/Flask backend (Railway) + vanilla HTML/CSS/JS frontend (Cloudflare Pages).
Current state: working scanner, basic UI, no login, no multi-page site, no auth.
Goal: ship a complete, competition-crushing product.

---

## AESTHETIC DIRECTION — READ THIS FIRST

Before touching any file, internalize this design philosophy:

**Tone**: Industrial precision. Think terminal meets high-end SaaS. Dark by default.
Security tools are used by people who distrust fluff. Every pixel must earn its place.

**References to channel**:
- Vercel's dashboard (clean data density)
- Wiz.io (serious security, premium feel)
- Linear.app (micro-interactions, speed)

**Typography**: Use `Space Mono` for grades/scores/code (Google Fonts CDN).
Use `DM Sans` for all body/UI text. Never Inter, never Roboto.

**Colors**:
- Background: #0a0b0d (near black)
- Surface: #111318
- Border: #1e2128
- Accent: #00d4aa (teal — security green)
- Danger: #ff4757
- Warning: #ffa502
- Success: #2ed573
- Text primary: #e8eaf0
- Text muted: #6b7280

**Motion**: Subtle, purposeful. Fade-ins on scroll. Grade badge counts up on reveal.
Scanner progress feels alive — not a spinner, a real progress bar with stage labels.

**The one thing users remember**: The grade badge. Make it ICONIC.
Large, bold letter in a thick bordered box. Color coded. Slight glow matching grade color.
A+ glows green. F glows red. First thing they see. Last thing they forget.

---

## PHASE 1 — WEBSITE RESTRUCTURE (Multi-page)

Create these pages. Each is a separate HTML file:

### index.html — Landing page (NOT the scanner)
This is the marketing page. Scanner moves to scan.html.

Sections in order:
1. **Hero** — Full viewport. Dark. Headline: "Know your attack surface." 
   Subheadline: "Instant security audit — headers, TLS, DNS, cookies. Free scan, no login."
   CTA button: "Scan a website →" links to scan.html
   Small social proof line: "Used by pentesters across India"

2. **How it works** — 3 steps horizontal:
   "Paste URL" → "We scan 20+ security checks" → "Get instant PDF report"
   Clean icons (SVG inline, no libraries), minimal text.

3. **What we check** — 4 cards in a grid:
   - HTTP Security Headers (6 checks)
   - TLS / SSL Certificate (expiry, cipher, protocol)
   - DNS Security (SPF, DMARC)
   - Cookie Security (Secure, HttpOnly, SameSite)
   Each card: icon + title + 2-line description. Dark surface cards, teal border on hover.

4. **Why WebAudit** — 3 columns:
   - "100% free scan" — no account needed
   - "PDF report included" — client-ready output  
   - "Built for India" — ₹499/month for API access

5. **Footer** — WebAudit · webaudit.in · Built for pentesters, by pentesters.

### scan.html — The actual scanner (move current index.html content here)
Keep all current functionality. Improve the loading state and results display (see Phase 3).
Add a nav link back to index.html (← back to home).

### pricing.html — Pricing page
Two tiers only:

**Free**
- Unlimited scans
- Full on-screen report
- No account needed
- Rate limited: 10 scans/hour

**Pro — ₹499/month**
- Everything in Free
- PDF report download
- API access (key via email for now, Razorpay coming)
- Priority scanning
- CTA: "Get API access" → mailto:hello@webaudit.in (for now)

### about.html — About page
Short. Who built it, why, what problem it solves.
Mention: SatarkScan (sister project, free Android UPI fraud detector).
Link to GitHub.

---

## PHASE 2 — NAVIGATION

Add a consistent nav to ALL pages:

```
WebAudit          [Scan] [Pricing] [About]         [Get API access →]
```

- Logo: "Web**Audit**" — "Web" in text-muted, "Audit" in accent color #00d4aa
- Links: 13px, muted color, hover → primary
- CTA button: teal background, dark text, small, rounded
- Sticky on scroll, slight blur backdrop
- Mobile: hamburger menu

---

## PHASE 3 — SCAN PAGE IMPROVEMENTS (scan.html)

### Loading state — COMPLETELY REDESIGN
Current: broken spinning URL text. 

New design:
- Full-width progress bar (teal, animated fill)
- 5 stage labels that highlight as each completes:
  `Connecting` → `Headers` → `TLS` → `DNS` → `Cookies`
- Each stage shows a checkmark when done
- Estimated time: "~8 seconds"
- The URL being scanned shown cleanly above, NOT spinning

### Grade badge — make it iconic
- Large (120px) bordered box, thick border (3px)
- Grade letter: 72px, Space Mono font, bold
- Score below: "88 / 100"  
- Color + subtle box-shadow glow matching grade:
  - A+/A: border #2ed573, glow rgba(46,213,115,0.2)
  - B: border #00d4aa, glow rgba(0,212,170,0.2)
  - C: border #ffa502, glow rgba(255,165,2,0.2)
  - D: border #ff6b35, glow rgba(255,107,53,0.2)
  - F: border #ff4757, glow rgba(255,71,87,0.2)

Add below grade: "Most sites score D–F. That's normal."

### Module cards — improve layout
Current 4 module cards are fine. Improve:
- Add subtle left border color matching severity (green=pass, amber=warning, red=fail)
- Show deduction number clearly: "-20 pts" in red badge
- Expand/collapse each section with smooth animation
- Copy-to-clipboard button on every fix code block (show ✓ Copied for 2 seconds)

### Results page context line
Below the grade badge, add:
"Scanned [url] on [date] · [scan time]ms · Powered by WebAudit"

---

## PHASE 4 — PDF REPORT REDESIGN

The current PDF is functional but looks like a school report. Redesign for pentesters.

**Design goal**: A document a pentester hands to a CTO and feels proud of.

### Cover page
- Full dark background (#0a0b0d) with light text — YES, dark PDF is fine for digital delivery
- WebAudit wordmark top-left (large, teal accent on "Audit")
- "WEB SECURITY ASSESSMENT" in small caps, muted, below wordmark
- Massive grade badge centered — 200px, thick border, glow via box-shadow
- Score: "88 / 100" below badge in large type
- Target URL in monospace below score
- Date + "Generated by WebAudit · webaudit.in" bottom right
- Thin teal horizontal rule separating header from content

### Executive summary (page 2)
New section pentesters need:
- 2-column layout: left = score breakdown table, right = risk summary
- Risk summary: traffic-light system
  - CRITICAL findings: red count badge
  - IMPORTANT findings: amber count badge  
  - MINOR findings: green count badge
- One paragraph plain-English summary: 
  "This site scored F (25/100). 2 critical issues were found that expose users to XSS and MITM attacks. Immediate action recommended on CSP and HSTS headers."
  Generate this dynamically based on actual findings.

### Per-section pages
Each section (Headers, TLS, DNS, Cookies) gets consistent styling:
- Section header: dark band with section title + icon + overall result badge
- Table rows: alternating subtle background (#111318 / #0a0b0d)
- Status indicators: colored left border on each row (red=fail, green=pass, amber=warn)
- Fix code blocks: monospace, slightly lighter background, teal left border
- Severity chips: "CRITICAL" / "IMPORTANT" / "MINOR" — pill shaped, color coded

### Recommendations page (last)
Current design is fine but improve:
- Number each finding
- Add effort estimate: "Low effort" / "Medium effort" / "High effort"
- Add impact: "High impact" / "Medium impact"
- Group by: Fix today / Fix this week / Fix this month

### Footer on every page
Left: "Confidential · WebAudit Security Assessment"
Right: "Page X of N · webaudit.in"
Thin top border in teal

---

## PHASE 5 — SEO + META

Add to ALL HTML pages:

```html
<meta name="description" content="...">
<meta property="og:title" content="...">
<meta property="og:description" content="...">
<meta property="og:image" content="https://webaudit.in/og-image.png">
<meta property="og:url" content="https://webaudit.in/[page]">
<link rel="canonical" href="https://webaudit.in/[page]">
```

Also create: `sitemap.xml` listing all 4 pages.

---

## TECHNICAL CONSTRAINTS

- Vanilla HTML/CSS/JS only — NO frameworks, NO npm, NO build step
- Google Fonts allowed via CDN: DM Sans + Space Mono
- All JS inline in each HTML file (single file per page)
- No localStorage/sessionStorage
- Backend API is at https://api.webaudit.in
- PDF generation is in backend/report/pdf.py (WeasyPrint)
- All frontend files go in frontend/ folder
- After all changes: git add, commit, push to GitHub (Railway + Cloudflare auto-deploy)

---

## EXECUTION ORDER

Do these in strict order. Complete each fully before moving to next.

1. Read CLAUDE.md for full project context
2. Read frontend/index.html to understand current state
3. Read backend/report/pdf.py to understand current PDF
4. Execute Phase 4 first (PDF redesign) — backend change, push separately
5. Execute Phase 1 + 2 (new pages + nav) — create index.html, scan.html, pricing.html, about.html
6. Execute Phase 3 (scan page improvements)
7. Execute Phase 5 (SEO meta tags + sitemap)
8. Run deploy-check.sh — must pass all checks
9. Git commit and push everything

---

## QUALITY BAR

Before considering any phase done, ask:
- Would a senior pentester pay ₹499/month for this?
- Does the PDF look better than what I'd make in Word?
- Is the grade badge the first thing your eye goes to?
- Does the landing page explain the product in 5 seconds?

If any answer is no — keep going.
