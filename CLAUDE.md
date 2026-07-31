# WebAudit — Claude Code Memory File

## Project Status
**LAUNCHED** — May 2026. WebAudit scores B 78/100 on its own scan.
All core features are live. Focus is now on SEO content, distribution, and post-launch polish.

---

## What is WebAudit
A freemium web security analysis tool for pentesters and developers.
Users paste a URL and get an instant security report covering HTTP headers,
TLS/SSL, DNS records, and cookie security. Free tier shows results on screen.
Paid tier (Pro) unlocks PDF report export and API access at ₹499/month (India) or $7/month (international).

**Target users:** Indian freelance pentesters who need client-facing PDF reports.
**Positioning:** Replacement for SecurityHeaders.com API (shutdown April 2026) with more features.
**Main competitor:** SiteSecurityScore (sitesecurityscore.com) — global tool, USD pricing, requires work email.
**Our moat:** No login, instant scan, INR pricing, Hall of Fame, India-first focus, Versus mode.
**Monetization:** Razorpay (India, ₹499/mo Pro / ₹999/mo Agency) + LemonSqueezy (international, $7/mo Pro / $28/mo Agency), IP-based routing.

---

## Tech Stack
- **Backend:** Python (Flask) — runs scanning logic + payment webhooks
- **Frontend:** Vanilla HTML + CSS + JS (no frameworks, no build step)
- **PDF generation:** WeasyPrint (server-side, no cost)
- **Database:** SQLite at `/data/usage.db` (Railway persistent volume)
- **Hosting:** Cloudflare Pages (frontend) + Railway (backend at api.webaudit.in)
- **Payments:** Razorpay (India) + LemonSqueezy (international)
- **Email:** Resend (API key delivery emails via webaudit.in domain)
- **Domain:** webaudit.in

---

## Project Structure
```
WebAudit/
├── CLAUDE.md              ← this file (Claude's memory)
├── DEPLOY.md              ← deployment guide
├── .gitignore
├── backend/
│   ├── app.py             ← Flask app, all API routes
│   ├── db.py              ← SQLite helpers (quota, api_keys, halloffame_cache)
│   ├── Procfile           ← gunicorn start command for Railway
│   ├── nixpacks.toml      ← WeasyPrint system deps for Railway
│   ├── requirements.txt   ← pinned Python dependencies
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── headers.py     ← HTTP security header checks + CORS + server fingerprint + security.txt
│   │   ├── tls.py         ← TLS/SSL certificate checks
│   │   ├── dns.py         ← DNS security checks (SPF, DMARC, DKIM, CAA, DNSSEC)
│   │   ├── cookies.py     ← Cookie security attribute checks
│   │   └── page.py        ← Page Analysis (mixed content, SRI, base tag, external deps)
│   └── report/
│       ├── __init__.py
│       └── pdf.py         ← PDF generation with WeasyPrint (fixed column alignment)
└── frontend/
    ├── index.html         ← marketing landing page
    ├── scan.html          ← scanner UI + Score Improvement Simulator + scan history
    ├── plans.html         ← pricing page with Razorpay/LS checkout (₹499/mo)
    ├── dashboard.html     ← customer dashboard (API key + usage)
    ├── halloffame.html    ← India's Web Security Report Card (10 Indian sites)
    ├── world-security-index.html ← Global security index (auto-refreshed weekly via GitHub Actions)
    ├── versus.html        ← side-by-side URL comparison (unique feature)
    ├── generators.html    ← CSP, HSTS, Permissions-Policy, CORS header generators
    ├── security-txt.html  ← security.txt validator + generator (RFC 9116)
    ├── methodology.html   ← how scoring works
    ├── about.html         ← about page
    ├── api-docs.html      ← REST API documentation
    ├── report.html        ← shareable report viewer (no login required)
    ├── terms.html         ← terms of service
    ├── refund.html        ← refund policy
    ├── sitemap.xml        ← XML sitemap for SEO
    ├── robots.txt         ← robots.txt pointing to sitemap
    ├── security.txt       ← RFC 9116 security disclosure
    ├── .well-known/
    │   └── security.txt   ← canonical security.txt location
    └── learn/
        ├── content-security-policy.html
        ├── hsts.html
        ├── x-frame-options.html
        ├── dns-email-security.html
        ├── tls-ssl-guide.html
        ├── security-txt-guide.html
        └── securityheaders-alternative.html  ← SEO article targeting "SecurityHeaders.com alternative"
```

---

## All API Endpoints
```
POST /api/scan                    ← free scan — returns grade, headers (no fix), TLS, DNS (no fix), no cookies/cross-origin
POST /api/scan?full=1             ← free scan with full fixes — used by Hall of Fame ?url= param scans
POST /api/scan/pro                ← full scan (requires X-API-Key) — returns everything including cookies, cross-origin
POST /api/report/pdf              ← generate PDF (requires X-API-Key header)
GET  /api/get-payment-route       ← IP-based routing: returns {provider, key} or {provider, url}
POST /api/subscribe/razorpay      ← create Razorpay subscription (accepts plan=pro|agency), returns subscription_id
POST /api/webhook/razorpay        ← Razorpay webhook: generates Pro API key + sends email (skips agency)
POST /api/webhook/lemonsqueezy    ← LemonSqueezy webhook: generates Pro API key + sends email (skips agency variant)
GET  /api/verify-key              ← verify an API key is valid
POST /api/cancel-subscription     ← cancel Razorpay sub at cycle end (requires X-API-Key); LS users directed to billing portal
GET  /api/usage?key=xxx           ← returns {valid, email, plan, scans_used, scans_limit}
GET  /api/halloffame              ← returns cached scan results for top Indian sites
POST /api/share                   ← create shareable report link (requires X-API-Key), expires 7 days
GET  /api/share/<share_id>        ← fetch stored share result JSON (public, no key needed)
POST /api/admin/seed-test-key          ← admin endpoint (requires X-Admin-Secret header)
POST /api/admin/clear-hof-cache        ← clears HOF cache and triggers fresh rescan
POST /api/admin/refresh-world-index    ← triggers fresh World Security Index scan (Bearer CRON_SECRET)
GET  /health                           ← health check
POST /api/agency/setup            ← post-payment setup: verifies sub, stores agency record, sends welcome email
GET  /api/agency/dashboard        ← returns agency info, domains, history (?api_key=xxx)
POST /api/agency/scan-now         ← trigger immediate scan of all agency domains (?api_key=xxx)
POST /api/agency/update           ← update domains/schedule (?api_key=xxx)
POST /api/agency/run-scheduled    ← internal cron: scan all agencies due today (Bearer CRON_SECRET)
GET  /api/agency/pdf/<history_id> ← download stored PDF for a scan (?api_key=xxx)
```

---

## Railway Environment Variables
```
DB_PATH=/data/usage.db
RAZORPAY_KEY_ID=rzp_live_...
RAZORPAY_KEY_SECRET=...
RAZORPAY_WEBHOOK_SECRET=...
LEMONSQUEEZY_WEBHOOK_SECRET=...     ← set in Railway env, never commit
LEMONSQUEEZY_API_KEY=...            ← LS API key for subscription verification in /api/agency/setup
RESEND_API_KEY=...
ADMIN_SECRET=...                    ← set in Railway env, never commit
ENCRYPTION_KEY=...                  ← Fernet key for email encryption (generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
CRON_SECRET=...                     ← Secret for /api/agency/run-scheduled cron endpoint
AGENCY_PDF_DIR=/data/agency_pdfs    ← Directory to store agency scan PDFs (Railway persistent volume)
```
Note: ALLOWED_ORIGINS is no longer used — CORS is hardcoded to https://webaudit.in in app.py.

## Payment Details
- **Razorpay Pro plan ID:** `plan_Sk7gZpN95Nen1h` (₹499/mo, INR, monthly)
- **Razorpay Agency plan ID:** `plan_SmyiLgFmsJGgyy` (₹999/mo, INR, monthly)
- **LemonSqueezy Pro checkout:** `https://webaudit-in.lemonsqueezy.com/checkout/buy/d8ef46ee-530b-4134-898c-508b491927ab`
- **LemonSqueezy Agency checkout:** `https://webaudit-in.lemonsqueezy.com/checkout/buy/d8ef46ee-530b-4134-898c-508b491927ab`
- **LemonSqueezy Product ID:** 1039013 | Pro Variant: 1039013 | Agency Variant: 1629482 | OTS Variant: 1633832 | Compliance Variant: 1696995
- **LemonSqueezy OTS checkout:** `https://webaudit-in.lemonsqueezy.com/checkout/buy/ddfabc4b-a62f-42f1-adeb-d06f4ca877bd`
- **LemonSqueezy Compliance checkout:** `YOUR_COMPLIANCE_VARIANT_UUID` ← placeholder, update when LS product created
- **Routing logic:** `/api/get-payment-route` detects IP → India = Razorpay, else = LemonSqueezy

## Railway Cron Job (Agency scheduled scans)
Set up a Railway cron job to POST to the run-scheduled endpoint daily at 08:00 UTC:
- **URL:** `https://api.webaudit.in/api/agency/run-scheduled`
- **Method:** POST
- **Header:** `Authorization: Bearer {CRON_SECRET}`
- **Schedule:** `0 8 * * *` (daily at 08:00 UTC)
- Railway Dashboard → Project → Settings → Cron Jobs → Add Cron Job

---

## Database Schema (SQLite at /data/usage.db)
```sql
CREATE TABLE api_keys (
    email TEXT PRIMARY KEY,
    api_key TEXT UNIQUE,
    plan TEXT DEFAULT 'pro',
    created_at TEXT
);

CREATE TABLE scan_usage (
    api_key TEXT,
    month TEXT,
    count INTEGER DEFAULT 0,
    PRIMARY KEY (api_key, month)
);

CREATE TABLE halloffame_cache (
    domain TEXT PRIMARY KEY,
    grade TEXT,
    score INTEGER,
    last_scanned TEXT
);

CREATE TABLE shared_reports (
    id TEXT PRIMARY KEY,
    url TEXT,
    result JSON,
    created_at TEXT,
    expires_at TEXT
);
```

---

## Quota & Limits
- Free tier: scan on screen only, no PDF (headers + TLS + DNS shown; cookies + cross-origin are Pro only)
- Pro tier: 50 scans/month, PDF export, API access, cookies + cross-origin analysis
- Agency tier: 500 scans/month, 25 domains, weekly/monthly scheduled scans, email PDF delivery, agency dashboard

---

## Grading Logic
- Start at 100, deduct points per missing/misconfigured item
- A+ = 90–100, A = 80–89, B = 70–79, C = 60–69, D = 50–59, F = below 50
- Critical headers (CSP, HSTS): -20 each if missing
- CSP present but with unsafe-inline/unsafe-eval: -10 (warn, not missing)
- Important headers (X-Frame-Options, X-Content-Type-Options): -10 each
- X-Frame-Options missing but CSP frame-ancestors present: 0 pts (equivalent protection)
- Minor headers (Referrer-Policy, Permissions-Policy): -5 each
- TLS issues: -30 if expired, -20 expiring ≤14 days, -10 expiring ≤30 days, -5 expiring ≤60 days, -20 self-signed, -10 weak cipher/protocol
- DNS: -3 if no SPF, -3 if SPF weak, -5 if no DMARC, -3 if DMARC p=none, -5 if DMARC p= unknown/invalid, -2 DKIM undetected, -2 no CAA, -3 no DNSSEC
- Cookie issues: -5 per cookie missing Secure flag, -5 per cookie missing HttpOnly flag (flat, regardless of cookie type)
- Cross-origin isolation issues: -2 to -4 per missing header
- CORS wildcard (*): -5
- Server fingerprinting (version exposed): -3 per header
- Page analysis: -2 mixed content, -2 SRI missing, -2 base tag present
- Scanner uses Chrome/124 User-Agent to avoid CDN header stripping

---

## Scanner Modules (backend/scanner/)
- headers.py — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS policy check, server fingerprinting, security.txt detection
- tls.py — TLS protocol, cipher suite, cert expiry, issuer, self-signed check
- dns.py — SPF, DMARC, DKIM (12 common selectors), CAA records, DNSSEC (DS records)
- cookies.py — HttpOnly, Secure, SameSite per cookie, session-critical vs preference weighting
- page.py — mixed content, SRI (external scripts/links without integrity=), base tag hijacking, external deps count

---

## Chat 15 Completed (DO NOT REDO)
- DKIM, CAA, DNSSEC added to dns.py
- security.txt detection added to headers.py
- CORS policy check added to headers.py
- Server fingerprinting added to headers.py
- Page Analysis module created (page.py)
- Versus mode page (versus.html)
- Score Improvement Simulator added to scan.html
- Header generators: CSP, HSTS, Permissions-Policy, CORS (generators.html)
- security.txt Validator + Generator (security-txt.html)
- Navbar restructured: Tools dropdown (Versus, Generators, Security.txt) + More dropdown (Methodology, About)
- Hall of Fame cache fixed + admin clear endpoint added
- Pricing updated: ₹650/mo India, $7/mo international
- PDF alignment fixed (fixed column widths, page-break-inside: avoid)
- index.html feature cards updated (8 checks for headers, 7 for DNS, new Page Analysis card)

---

## Chat 16 Completed (DO NOT REDO)
- CSP Validator tab added to generators.html + POST /api/tools/validate-csp backend endpoint
- API documentation page: frontend/api-docs.html
- Learning Center: frontend/learn.html + 6 articles in frontend/learn/
- Shareable report links: POST /api/share, GET /api/share/<id>, frontend/report.html, "Share Report" button in scan.html

---

## Chat 17 Completed (DO NOT REDO)
- sitemap.xml created at frontend/sitemap.xml (18 URLs + securityheaders-alternative.html)
- robots.txt created at frontend/robots.txt
- Scan history added to scan.html — saves last 5 scans to localStorage (wa_scan_history), shows clickable pills below the form, clear history link
- WhatsApp share button added to scan.html results — mobile only (max-width: 768px), green #25D366, opens wa.me share URL
- SEO article: frontend/learn/securityheaders-alternative.html — targets "SecurityHeaders.com alternative" keyword, comparison table (WebAudit vs SiteSecurityScore vs ImmuniWeb), added to More dropdown across all nav instances
- Mobile overflow fixes across all 16 frontend HTML files: overflow-x:auto on section-body.open (scan.html, report.html), cmp-table wrapper (versus.html), all 5 score-tables (methodology.html), all 14 field-tables (api-docs.html)
- "SecurityHeaders Alternative" added to More dropdown in nav across all pages

---

## Chat 18 Completed (DO NOT REDO)
- TLS scoring fixed: expired -30, expiring ≤14d -20, ≤30d -10, ≤60d -5, self-signed -20 (backend/scanner/tls.py)
- Cookie scoring fixed: Secure missing -5 flat, HttpOnly missing -5 flat per cookie, removed session-critical/preference tiering (backend/scanner/cookies.py)
- methodology.html already had correct values; CLAUDE.md Grading Logic updated to match
- Fluid font scaling added to all 19 frontend HTML files: html { font-size: clamp(15px, 1.1vw + 0.5rem, 18px) }

## Chat 19 Completed (DO NOT REDO)
- ₹99 one-time scan via Razorpay Payment Link (https://rzp.io/rzp/7yhspnYg)
  - POST /api/verify-one-time: verifies payment_id via Razorpay API, issues 24hr single-use token
  - LemonSqueezy OTS: webhook handler creates token + emails scan link (one-time-scan.html?token=TOKEN)
  - one-time-scan.html: accepts ?token= (LS flow) or ?razorpay_payment_id= (Razorpay flow)
  - plans.html: OTS strip shows ₹99/Razorpay for India, ~$X/LemonSqueezy for international (live FX)
  - POST /api/scan: accepts one_time_token in body → full Pro-level result, token marked used
  - db.py: one_time_scans table (token, payment_id, used, created_at, expires_at)
  - frontend/one-time-scan.html: verify → scan form → full results page
  - plans.html: "One-Time Scan ₹99" strip below plans grid
  - sitemap.xml: one-time-scan.html added

## Chat 20 Completed (DO NOT REDO)
- Scan badge embed: GET /api/badge?url={domain} returns SVG badge (200×20px, grade-colored), 24hr in-memory cache
  - db.py: get_domain_grade(domain) queries halloffame_cache
  - app.py: _badge_cache dict, _BADGE_TTL=86400, _badge_svg(), _normalize_badge_domain(), GET /api/badge route
  - frontend/badge.html: live preview, embed code tabs (HTML/Markdown/URL), grade legend
  - sitemap.xml: badge.html added
  - All navbar Tools dropdowns: "Badge" link added to all 25 HTML files (root + learn/)
- securityheaders-alternative.html: ₹99 one-time scan mentioned in comparison table, INR pricing section, and Bottom Line

## Chat 21 Completed (DO NOT REDO)
- Agency tier full implementation:
  - DB: agency_subscriptions + agency_scan_history tables, all CRUD helpers
  - Fernet email encryption (ENCRYPTION_KEY env var)
  - POST /api/agency/setup — verifies Razorpay/LS subscription, encrypts email, generates wa_agency_ key, sends welcome email
  - GET /api/agency/dashboard — returns domains, schedule, scan count, history
  - POST /api/agency/scan-now — immediate scan of all domains, PDFs stored + history saved
  - POST /api/agency/update — update domains/schedule
  - POST /api/agency/run-scheduled — cron endpoint (Bearer CRON_SECRET), runs scheduled scans, emails PDFs
  - GET /api/agency/pdf/<id> — download stored PDF
  - frontend/agency-setup.html — post-payment setup page (Razorpay redirects here, LS redirects via checkout param)
  - frontend/agency-dashboard.html — domains, stats, history, scan now, update settings
  - plans.html Agency card: live, ₹999/mo India / ₹2,499/mo international, proper checkout (Razorpay → agency-setup.html, LS → LS checkout with redirect)
  - securityheaders-alternative.html: Agency tier mentioned in comparison table, INR pricing section, Bottom Line
  - sitemap.xml: agency-setup.html + agency-dashboard.html added
  - CLAUDE.md: Railway env vars (ENCRYPTION_KEY, CRON_SECRET, AGENCY_PDF_DIR), cron job instructions, all new API endpoints
  - Agency pricing fix: India → ₹999/mo (Razorpay plan_SmyiLgFmsJGgyy), International → ₹2,499/mo (LemonSqueezy); _routeCache pattern in plans.html
  - GitHub Actions workflow: .github/workflows/agency-scheduled-scans.yml — daily 08:00 UTC cron, calls /api/agency/run-scheduled with Bearer CRON_SECRET
  - CRON_SECRET added to GitHub repo secrets (G4h0ST98/webaudit.in)
  - navbar hover animation made consistent across all pages (removed a:hover underline rule)
  - More dropdown: SecurityHeaders Alternative link added to methodology.html and about.html (was missing)

## Chat 25 Completed (DO NOT REDO)
- Compliance PDF major rewrite (compliance_pdf.py):
  - Public API changed to `generate_compliance_pdf(scan_result: dict) -> bytes` (single-arg)
  - Teal section headers (#00c9a7), exec bg tints, footer teal border — branding upgrade
  - `evaluate_check()` now reads short-key format (e.g. `hr.get("csp", {}).get("present")`)
  - Assessment Summary section: dynamic paragraph + CWE mapping table per framework
  - Remediation grouped by (req_id, framework) → deduped, max ~22 rows; fix text HTML-escaped
  - `_normalize_scan_for_compliance()` bridge added to app.py: converts real scanner output → short-key format
  - Compliance endpoint updated to call `_normalize_scan_for_compliance(scan)` before generating PDF
  - Email filename: `{domain}_compliance_{date_str}.pdf`
  - Fixed HTML tag crash (reportlab `<script>`/`<link>` in A06 fix text) → `html.escape()` in _truncate_sentences()
- OG image switch: widelogo.png → og-image.jpg (1200×630 JPEG, 49KB vs 554KB PNG); all 34 HTML files updated
- newlogo.png: added to frontend/, schema.org Organization logo in index.html updated
- plans.html: Compliance Report product card added below OTS card; initPricing() sets India=₹249, intl=$3
- compliance-report.html: exec summary OWASP row "7 → 5 requirements"; ISO row NON-COMPLIANT → PARTIAL; framework card descriptions updated to mention CWE + Assessment Summary
- api-docs.html: sidebar + endpoint cards added for POST /api/verify-one-time, POST /api/compliance-report/pay, POST /api/compliance-report/generate
- status.html: new page created with live health checks (Scanner API, Payment providers, Frontend); auto-refreshes every 60s
  - 3 groups: Core API (health, free scan, payment route, badge), Payment & Delivery (Razorpay, LemonSqueezy, Resend), Frontend (main site, scan.html, api CDN)
  - Third-party services (Razorpay, LemonSqueezy, Resend) use `thirdParty: true` flag + `mode: 'no-cors'`; any response = Operational, only network-level fetch failure = red; instant rejection (< 50ms) = assumed operational with `—` latency and tooltip
  - Banner state (Service disruption / Partial degradation / All systems operational) driven only by WebAudit-owned endpoints (core + frontend groups); payment provider status shown in table but never triggers banner
  - Per-service `degradedMs` thresholds: Scanner API/Payment Route/API CDN = 2000ms, Badge API = 5000ms, Main Site/Scanner UI = 3000ms; exceeded threshold → yellow "Degraded"
  - Free Scan row hits GET /health (label "Scan engine operational") — not a live POST /api/scan; avoids burning quota and adding 1-3s latency on every 60s refresh
  - Colour-coded dots with latency ms; overall banner title updates dynamically
- All 31 HTML files with More dropdown: "Status" link added to nav, mobile nav, and footer; active-page hide JS added to each
- sitemap.xml: status.html added (lastmod 2026-05-25)

## Chat 24 Completed (DO NOT REDO)
- Razorpay checkout fixed: _headers COEP was `require-corp` (set in Chat 22), blocking checkout.js dynamic injection → changed back to `unsafe-none`
- LemonSqueezy Pro checkout fixed: was pointing to test variant (1633832, $650) → updated to production UUID `d8ef46ee-...` with `?checkout[variant_id]=1039013` for Pro, `&checkout[variant_id]=1629482` for Agency
- _LS_PRO_VARIANT_ID in app.py updated from 1629523 to 1039013
- Copy audit + 5 stale copy fixes: ₹650/mo → ₹499/mo (api-docs.html), ₹2,499/mo → ₹999/mo (plans.html meta), "50 free scans per month" → "50 scans/month" (plans.html), unqualified PDF claims → qualified "(Pro)" (index.html)
- Compliance report feature (full implementation):
  - backend/requirements.txt: added `reportlab`
  - backend/compliance_mapping.json: 4 frameworks (OWASP Top 10, PCI-DSS v4.0, GDPR Art. 32, ISO 27001:2022) — 22 requirements, 20 check keys
  - backend/compliance_pdf.py: ReportLab Platypus PDF — evaluate_check(), evaluate_compliance(), generate_compliance_pdf(). Cover + Executive Summary + 4 framework sections + Remediation Plan + Disclaimer.
  - backend/db.py: compliance_tokens table + compliance_payment_already_used(), create_compliance_token(), get_compliance_token(), mark_compliance_token_used()
  - backend/app.py: _LS_COMPLIANCE_VARIANT_ID=1696995, _RZP_COMPLIANCE_AMOUNT=24900 (₹249), email templates, POST /api/compliance-report/pay, POST /api/compliance-report/generate, LS webhook handles variant 1696995
  - frontend/compliance-report.html: landing page with Razorpay order flow + LS token redemption flow, framework cards, FAQ, IP-routed pricing
  - frontend/compliance/index.html: "What is Compliance?" overview — why it matters, risk cards, framework overview grid, CTA
  - frontend/compliance/owasp.html: OWASP Top 10 2021 — all 7 checkable categories (A01–A08) with check chips, fix guidance, coverage table
  - frontend/compliance/pci-dss.html: PCI-DSS v4.0 — 5 requirements (4.2.1, 6.4.1, 6.4.3, 8.3.6, 12.3.3) with warning box on non-compliance consequences
  - frontend/compliance/gdpr.html: GDPR Article 32 — 4 sub-clauses (a–d) with official text citation, fine warning, "appropriate measures" explanation
  - frontend/compliance/iso27001.html: ISO 27001:2022 Annex A — 6 controls (A.8.23–A.8.26, A.8.16, A.5.14), "New in 2022" badges, ISMS evidence guidance
  - frontend/sitemap.xml: compliance-report.html + compliance/ (6 URLs) added, lastmod 2026-05-24
- LS_COMPLIANCE_URL in compliance-report.html still has placeholder `YOUR_COMPLIANCE_VARIANT_UUID` — replace with real UUID when LS product is created for variant 1696995

## Chat 23 Completed (DO NOT REDO)
- LemonSqueezy pricing confirmed hardcoded USD: Pro $7/mo, Agency $28/mo, OTS $2
- LemonSqueezy OTS variant ID 1633832, checkout URL confirmed in Payment Details
- DNS updated: api.webaudit.in CNAME → r75lvhh6.up.railway.app
- World Security Index (world-security-index.html) auto-refreshes weekly via GitHub Actions cron + POST /api/admin/refresh-world-index (Bearer CRON_SECRET)
- IndexNow key a204882b3c65e7f5f1a7067007cb63f6 deployed; Bing Webmaster Tools connected
- Google Search Console verified, sitemap submitted (23 pages)
- Security hardening: 7 findings fixed (details in commit history)
- Tool correctness fixes: HSTS slider default (index 4 = 1 year), Permissions-Policy `(self)` syntax, security.txt paste validator checks both required fields (Contact + Expires)

## Chat 22 Completed (DO NOT REDO)
- Google Search Console verification meta tag added to index.html
- Agency keys now accepted in all Pro endpoints (/api/scan/pro, /api/report/pdf, /api/share, /api/verify-key, /api/usage)
- _resolve_key() helper in app.py: checks api_keys then agency_subscriptions, returns normalised dict
- db.check_quota() and db.increment_usage() now accept optional limit param (AGENCY_MONTHLY_LIMIT=500 for agency)
- cancel_pending status now accepted in scan/pro, pdf, share endpoints (was incorrectly rejecting it)
- _headers: COEP changed to require-corp; open.er-api.com removed from connect-src (FX fetch was removed)
- plans.html: USD as default price (no blank flash); INR override for India only after IP detection
- Agency CTA on plans.html is live (was already wired up, Coming Soon removed)
- plans.html "Want to cancel?" section added (IP-routed: Razorpay dashboard link vs LS billing portal)
- dashboard.html: API key input field on error screen (loadWithKey() + history.replaceState)
- Self-serve Razorpay cancellation: /api/cancel-subscription endpoint, cancel button in dashboard.html, cancel_pending status, razorpay_subscription_id stored in api_keys on webhook
- refund.html: one-time scan credits added to non-refundable section; cancellation portal links in section 1 as <dl> grid layout
- LemonSqueezy pricing changed from INR-converted to hardcoded USD: Pro $7/mo, Agency $28/mo, OTS $2

---

## Post-Launch TODO
### SEO content (priority — drives organic traffic)
- [ ] Article: "check website security headers" — targets high-volume search term
- [ ] Article: "HSTS checker" / "HTTP Strict Transport Security checker"
- [ ] Article: "CSP validator online" / "Content Security Policy tester"

### Distribution
- [ ] ProductHunt launch
- [ ] toolify.ai listing
- [ ] BetaList submission
- [ ] Hacker News Show HN post
- [ ] IndieHackers launch post
- [ ] Reddit: r/netsec, r/webdev, r/indiehackers
- [ ] GitHub awesome-security PR

### Tech debt (later, no rush)
- [ ] CSP unsafe-inline refactor: extract inline <script> blocks from 20 HTML files to external .js files, inline <style> blocks from 21 files to external .css files — required before unsafe-inline can be removed from _headers

---

## Pro Gating (scan.html)
- Free /api/scan: returns grade, header names+status+explanation (NO fix values), TLS, DNS (NO fix values), no cookies, no cross-origin
- Free /api/scan?full=1: returns everything including fix values — used ONLY for Hall of Fame ?url= param auto-scans
- Pro /api/scan/pro: requires X-API-Key, returns full results including cookies + cross-origin
- Unlock flow: user enters API key in scan.html → verifies via /api/verify-key → re-fetches /api/scan/pro → replaces results inline
- Key stored in sessionStorage so user doesn't re-enter for same session

---

## Hall of Fame
- 10 top Indian sites scanned weekly (background thread, 2s delay between each)
- Cache stored in halloffame_cache table, refreshed if >7 days old
- GET /api/halloffame returns cached results immediately + triggers rescan if stale
- If scan returns score 0 with all headers missing → site blocked scanner → skip caching
- "View full report" links to scan.html?url=domain which auto-triggers scan

---

## Developer Context
- Developer: Abhicharm (solo)
- OS: Fedora 43 Workstation
- GitHub: G4h0ST98 — repo: webaudit.in (main branch)
- Other project: SatarkScan (Android UPI fraud detector, separate repo)
- Preferred workflow: complete file replacements, not snippets
- Git push: uses PAT stored at ~/Desktop/2026/Githubtoken.txt

---

## Commands to Remember
```bash
# Run backend locally
cd backend && python app.py

# Git push — repo is G4h0ST98/securescanr, NOT the old webaudit.in repo
cd ~/Desktop/2026/Securescanr
git add .
git commit -m "message"
PAT=$(cat ~/Desktop/2026/Githubtoken.txt | tr -d '[:space:]')
git push "https://x-access-token:${PAT}@github.com/G4h0ST98/securescanr.git" main
```

---

## Notes on DEPLOY.md
- ALLOWED_ORIGINS is now hardcoded in app.py — ignore the env var section in DEPLOY.md
- API_BASE is hardcoded to https://api.webaudit.in in all frontend files
- pricing.html is deleted
- Railway URL is webauditin-production.up.railway.app
- DNS: `api.webaudit.in` CNAME → `r75lvhh6.up.railway.app` (Railway internal hostname)
- Everything else in DEPLOY.md (Railway setup, Cloudflare Pages setup, DNS records) is still accurate

## SEO & Indexing
- Google Search Console: verified, sitemap submitted (23 pages)
- Bing Webmaster Tools: connected
- IndexNow key: `a204882b3c65e7f5f1a7067007cb63f6` (file at webaudit.in/a204882b3c65e7f5f1a7067007cb63f6.txt)

## MCP Tools Available
- context7: use for library docs (Flask, WeasyPrint, dnspython, cryptography)
- sequential-thinking: use for planning complex multi-step features

## Instructions for Claude Code
- Always read this file at the start of every session
- Write complete files, not snippets
- Frontend files → Cloudflare Pages (auto-deploys from GitHub main)
- Backend files → Railway (auto-deploys from GitHub main)
- Never break existing endpoints — check app.py before adding new routes
- Keep scan results stateless — never store URLs or scan data, only API keys + quota
- Navbar has Tools dropdown (Versus, Generators, Security.txt, API Docs, Learn) and More dropdown (Methodology, About, SecurityHeaders Alternative)
