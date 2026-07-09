# WebAudit — Deployment Guide

Backend → Railway (free tier)
Frontend → Cloudflare Pages (free tier)
Domain → webaudit.in (managed in Cloudflare DNS)

---

## Prerequisites

| Account | URL | Cost |
|---------|-----|------|
| Railway | railway.app | Free — $5 credit/month |
| Cloudflare | cloudflare.com | Free |
| GitHub | github.com | Free — repo must be pushed |

All files in this guide are already present in the repo. No extra code changes needed before deploying.

---

## Part 1 — Deploy backend to Railway

### 1.1 Create a Railway account

1. Go to **railway.app** → click **Start a New Project**
2. Sign in with GitHub (authorise Railway to access your repos)

### 1.2 Create the project

1. Click **New Project → Deploy from GitHub repo**
2. Search for `webaudit.in` and select it
3. Railway will detect `backend/nixpacks.toml` and use it automatically

### 1.3 Set the root directory

Railway needs to know the Flask app lives in `backend/`, not the repo root.

1. After the project is created, click your service → **Settings**
2. Under **Source** → set **Root Directory** to `backend`
3. Railway will re-build from `backend/` — it will pick up `nixpacks.toml`,
   `requirements.txt`, and `Procfile` automatically

### 1.4 Set environment variables

In Railway: service → **Variables** → add each one:

| Variable | Value | Notes |
|----------|-------|-------|
| `FLASK_ENV` | `production` | Disables debug mode |
| `ALLOWED_ORIGINS` | `https://webaudit.in,https://www.webaudit.in` | CORS allowlist — add after domain is live; leave unset during initial test |
| `PORT` | *(leave unset)* | Railway injects this automatically |

### 1.5 Trigger a deploy

Railway auto-deploys on every push to `main`. To deploy manually:

1. Service → **Deployments** → **Deploy Now**
2. Watch the build log — the first build takes ~3 minutes (installing WeasyPrint deps)

### 1.6 Get your Railway URL

1. Service → **Settings** → **Domains**
2. Click **Generate Domain** — Railway assigns a URL like:
   `https://webaudit-backend-production.up.railway.app`
3. Test it:
   ```bash
   curl https://webaudit-backend-production.up.railway.app/health
   # → {"status":"ok"}
   ```
4. Test a scan:
   ```bash
   curl -s -X POST https://webaudit-backend-production.up.railway.app/api/scan \
     -H "Content-Type: application/json" \
     -d '{"url":"https://example.com"}' | python3 -m json.tool | head -10
   ```

### 1.7 WeasyPrint troubleshooting

If the build fails with a Pango/Cairo error, Railway's Nixpacks environment may need
a slightly different package set. Switch to the Docker approach:

1. Create `backend/Dockerfile`:
   ```dockerfile
   FROM python:3.12-slim

   RUN apt-get update && apt-get install -y --no-install-recommends \
       libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
       libgdk-pixbuf2.0-0 libffi8 shared-mime-info fonts-liberation \
       && rm -rf /var/lib/apt/lists/*

   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY . .

   EXPOSE 8080
   CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120 --preload
   ```
2. In Railway service → **Settings** → **Build** → set **Builder** to `Dockerfile`
3. Redeploy

---

## Part 2 — Deploy frontend to Cloudflare Pages

### 2.1 Open Cloudflare Pages

1. Log into **dash.cloudflare.com**
2. Left sidebar → **Workers & Pages** → **Create application** → **Pages**
3. Click **Connect to Git**

### 2.2 Connect your GitHub repo

1. Authorise Cloudflare to access your GitHub
2. Select the `webaudit.in` repository
3. Click **Begin setup**

### 2.3 Configure build settings

| Field | Value |
|-------|-------|
| Project name | `webaudit` |
| Production branch | `main` |
| Framework preset | *None* |
| Build command | *(leave blank)* |
| Build output directory | `frontend` |

The frontend is a single static HTML file — no build step needed.

### 2.4 Set the API_BASE environment variable

Before deploying, update `frontend/index.html` line ~620 to point to your Railway URL:

```js
// Change this:
const API_BASE = (
  location.hostname === 'localhost' || location.hostname === '127.0.0.1'
) ? 'http://localhost:5000' : '';

// To this (replace with your actual Railway URL):
const API_BASE = (
  location.hostname === 'localhost' || location.hostname === '127.0.0.1'
) ? 'http://localhost:5000'
  : 'https://webaudit-backend-production.up.railway.app';
```

Commit and push — Cloudflare Pages will auto-deploy.

### 2.5 Verify

Cloudflare Pages assigns a URL like `https://webaudit.pages.dev`.
Open it in a browser, scan `example.com`, and confirm results load.

---

## Part 3 — Environment variables reference

### Backend (Railway)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | Auto | 5000 | Injected by Railway — do not set manually |
| `FLASK_ENV` | Yes | `development` | Set to `production` to disable debug mode |
| `ALLOWED_ORIGINS` | Recommended | `*` (all) | Comma-separated list of allowed CORS origins |

### Frontend (Cloudflare Pages)

Cloudflare Pages does not run server-side code, so there are no runtime env vars.
The only configuration is the `API_BASE` constant inside `frontend/index.html`.

---

## Part 4 — Custom domain setup for webaudit.in

You need two subdomains:
- `webaudit.in` (or `www.webaudit.in`) → Cloudflare Pages (frontend)
- `api.webaudit.in` → Railway (backend)

### 4.1 Add webaudit.in to Cloudflare Pages

1. In Cloudflare Pages project → **Custom domains** → **Set up a custom domain**
2. Enter `webaudit.in` → click **Continue**
3. Cloudflare auto-adds the required DNS record since the domain is already on Cloudflare:
   ```
   CNAME   webaudit.in   webaudit.pages.dev   (proxied ✓)
   ```
4. Also add `www`:
   ```
   CNAME   www           webaudit.pages.dev   (proxied ✓)
   ```
5. Wait ~2 minutes → visit `https://webaudit.in` to confirm

### 4.2 Add api.webaudit.in to Railway

1. In Railway service → **Settings** → **Domains** → **Add Custom Domain**
2. Enter `api.webaudit.in` → Railway shows you a CNAME target like:
   `webaudit-backend-production.up.railway.app`
3. In Cloudflare DNS → **Add record**:
   ```
   Type:    CNAME
   Name:    api
   Target:  webaudit-backend-production.up.railway.app
   Proxy:   DNS only (grey cloud) ← Railway handles TLS; do NOT proxy
   ```
4. Wait up to 5 minutes → test:
   ```bash
   curl https://api.webaudit.in/health
   # → {"status":"ok"}
   ```

### 4.3 Update ALLOWED_ORIGINS on Railway

Now that the domain is live, lock down CORS:

Railway → service → **Variables** → update:
```
ALLOWED_ORIGINS = https://webaudit.in,https://www.webaudit.in
```

Redeploy (or Railway applies it immediately without redeploy).

### 4.4 Update API_BASE in the frontend

Update `frontend/index.html`:
```js
const API_BASE = (
  location.hostname === 'localhost' || location.hostname === '127.0.0.1'
) ? 'http://localhost:5000'
  : 'https://api.webaudit.in';
```

Commit and push → Cloudflare Pages auto-deploys in ~30 seconds.

### 4.5 DNS records summary

| Type | Name | Value | Proxy |
|------|------|-------|-------|
| CNAME | `webaudit.in` | `webaudit.pages.dev` | Proxied ✓ |
| CNAME | `www` | `webaudit.pages.dev` | Proxied ✓ |
| CNAME | `api` | `<railway-generated-hostname>` | DNS only ✗ |

---

## Part 5 — Post-deployment checklist

Run through these after both services are live on the custom domain.

- [ ] `curl https://api.webaudit.in/health` returns `{"status":"ok"}`
- [ ] Scan `https://example.com` via the UI — all four module sections appear
- [ ] TLS section shows a valid certificate (not an error)
- [ ] DNS section shows SPF/DMARC results
- [ ] "Download PDF Report" modal opens and shows API key input
- [ ] PDF download works with a valid API key (use any key ≥ 8 chars for now)
- [ ] Open browser DevTools → Network — verify no CORS errors on scan request
- [ ] Open `https://webaudit.in` on mobile — check 2-column card layout
- [ ] Check Railway logs for any 500 errors after a few test scans

---

## Part 6 — Redeployment workflow

After any code change:

```bash
# From repo root
git add .
git commit -m "describe change"
PAT=$(cat ~/Desktop/2026/Githubtoken.txt | tr -d '[:space:]')
git push "https://x-access-token:${PAT}@github.com/G4h0ST98/webaudit.in.git" main
```

- **Railway** detects the push and redeploys the backend automatically (~1 min)
- **Cloudflare Pages** detects the push and redeploys the frontend automatically (~30 sec)

No manual steps needed after the initial setup.
