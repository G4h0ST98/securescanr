#!/usr/bin/env bash
# WebAudit pre-deployment readiness check.
# Run from the repo root before pushing to Railway + Cloudflare Pages.

set -euo pipefail

# ── Colour codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

PASS="${GREEN}✓${RESET}"
FAIL="${RED}✗${RESET}"
WARN="${YELLOW}⚠${RESET}"

# ── State ─────────────────────────────────────────────────────────────────────
errors=0
warnings=0

ok()   { printf "  ${PASS} %s\n" "$1"; }
fail() { printf "  ${FAIL} ${RED}%s${RESET}\n" "$1"; (( errors++ )) || true; }
warn() { printf "  ${WARN} ${YELLOW}%s${RESET}\n" "$1"; (( warnings++ )) || true; }

# ── Resolve repo root (script may be called from any directory) ───────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="${REPO_ROOT}/backend"
FRONTEND="${REPO_ROOT}/frontend"

printf "\n${BOLD}WebAudit — deployment readiness check${RESET}\n"
printf "Repo root: %s\n\n" "${REPO_ROOT}"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Required files
# ─────────────────────────────────────────────────────────────────────────────
printf "${BOLD}[1/5] Required files${RESET}\n"

declare -A REQUIRED_FILES=(
  ["backend/app.py"]="${BACKEND}/app.py"
  ["backend/requirements.txt"]="${BACKEND}/requirements.txt"
  ["backend/Procfile"]="${BACKEND}/Procfile"
  ["backend/nixpacks.toml"]="${BACKEND}/nixpacks.toml"
  ["backend/scanner/headers.py"]="${BACKEND}/scanner/headers.py"
  ["backend/scanner/tls.py"]="${BACKEND}/scanner/tls.py"
  ["backend/scanner/dns.py"]="${BACKEND}/scanner/dns.py"
  ["backend/scanner/cookies.py"]="${BACKEND}/scanner/cookies.py"
  ["backend/report/pdf.py"]="${BACKEND}/report/pdf.py"
  ["frontend/index.html"]="${FRONTEND}/index.html"
  ["DEPLOY.md"]="${REPO_ROOT}/DEPLOY.md"
  [".gitignore"]="${REPO_ROOT}/.gitignore"
)

for label in "${!REQUIRED_FILES[@]}"; do
  path="${REQUIRED_FILES[$label]}"
  if [[ -f "$path" ]]; then
    ok "$label"
  else
    fail "$label  ← file missing"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# 2. requirements.txt — gunicorn present
# ─────────────────────────────────────────────────────────────────────────────
printf "\n${BOLD}[2/5] requirements.txt${RESET}\n"

REQ="${BACKEND}/requirements.txt"
if [[ -f "$REQ" ]]; then
  declare -a REQUIRED_PKGS=(flask flask-cors requests dnspython weasyprint cryptography gunicorn)
  for pkg in "${REQUIRED_PKGS[@]}"; do
    if grep -qi "^${pkg}" "$REQ"; then
      ok "${pkg}"
    else
      fail "${pkg} not found in requirements.txt"
    fi
  done
else
  fail "requirements.txt missing — cannot check packages"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. Procfile — correct gunicorn command
# ─────────────────────────────────────────────────────────────────────────────
printf "\n${BOLD}[3/5] Procfile${RESET}\n"

PROCFILE="${BACKEND}/Procfile"
if [[ -f "$PROCFILE" ]]; then
  if grep -q "^web:" "$PROCFILE"; then
    ok "web: process type declared"
  else
    fail "Procfile has no 'web:' process type"
  fi

  if grep -q "gunicorn" "$PROCFILE"; then
    ok "gunicorn used as server"
  else
    fail "Procfile does not use gunicorn — Flask's dev server must not run in production"
  fi

  if grep -q '\$PORT' "$PROCFILE"; then
    ok "\$PORT used in gunicorn bind address"
  else
    fail "Procfile does not bind to \$PORT — Railway will not be able to route traffic"
  fi
else
  fail "Procfile missing"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. app.py — production-ready configuration
# ─────────────────────────────────────────────────────────────────────────────
printf "\n${BOLD}[4/5] app.py${RESET}\n"

APP="${BACKEND}/app.py"
if [[ -f "$APP" ]]; then
  if grep -q 'os.environ.get.*PORT' "$APP" || grep -q 'os\.environ\[.PORT.\]' "$APP"; then
    ok "PORT read from environment variable"
  else
    fail "PORT is hardcoded — app.py must read PORT from os.environ for Railway"
  fi

  if grep -q 'host.*0\.0\.0\.0' "$APP"; then
    ok "Flask binds to 0.0.0.0 (all interfaces)"
  else
    fail "Flask does not bind to 0.0.0.0 — Railway cannot reach the app"
  fi

  if grep -q 'debug=True' "$APP"; then
    warn "debug=True found — ensure FLASK_ENV=production is set in Railway to override this"
  else
    ok "debug mode not hardcoded to True"
  fi

  if grep -qi 'ALLOWED_ORIGINS\|flask_cors\|CORS' "$APP"; then
    ok "CORS configured"
  else
    warn "No CORS configuration found — browser requests from webaudit.in may be blocked"
  fi

  if grep -q 'import os' "$APP"; then
    ok "import os present"
  else
    fail "'import os' missing — required to read environment variables"
  fi
else
  fail "app.py missing"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. frontend/index.html — API_BASE configured
# ─────────────────────────────────────────────────────────────────────────────
printf "\n${BOLD}[5/5] frontend/index.html${RESET}\n"

HTML="${FRONTEND}/index.html"
if [[ -f "$HTML" ]]; then
  ok "index.html present"

  if grep -q 'const API_BASE' "$HTML"; then
    ok "API_BASE constant present"
  else
    fail "API_BASE constant not found in index.html"
  fi

  # Warn if API_BASE still falls back to empty string for production
  # (means prod traffic hits same-origin — fine only behind a proxy, otherwise broken)
  if grep -q "API_BASE.*=.*''" "$HTML" || grep -q 'API_BASE.*""' "$HTML"; then
    warn "API_BASE production value is empty string — update it to your Railway URL before going live (see DEPLOY.md § 2.4)"
  elif grep -q 'railway\.app\|webaudit\.in' "$HTML"; then
    ok "API_BASE points to a production host"
  else
    warn "API_BASE production value is not yet set to a Railway URL — update before launch (see DEPLOY.md § 2.4)"
  fi

  if grep -q 'application/pdf\|/api/report/pdf' "$HTML"; then
    ok "PDF download endpoint wired up"
  else
    warn "PDF download endpoint reference not found in index.html"
  fi
else
  fail "frontend/index.html missing"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Result
# ─────────────────────────────────────────────────────────────────────────────
printf "\n%s\n" "────────────────────────────────────────"

if (( errors == 0 )); then
  printf "${GREEN}${BOLD}  READY TO DEPLOY${RESET}"
  if (( warnings > 0 )); then
    printf "  ${YELLOW}(${warnings} warning%s — review above)${RESET}" \
      "$([ "$warnings" -eq 1 ] && echo '' || echo 's')"
  fi
  printf "\n\n"
  printf "  Next steps:\n"
  printf "  1. Push to GitHub (see DEPLOY.md § Part 6)\n"
  printf "  2. Follow Railway setup   → DEPLOY.md § Part 1\n"
  printf "  3. Follow Cloudflare setup → DEPLOY.md § Part 2\n"
  printf "  4. Configure webaudit.in  → DEPLOY.md § Part 4\n\n"
  exit 0
else
  printf "${RED}${BOLD}  NOT READY — %d error%s must be fixed before deploying${RESET}\n\n" \
    "$errors" "$([ "$errors" -eq 1 ] && echo '' || echo 's')"
  exit 1
fi
