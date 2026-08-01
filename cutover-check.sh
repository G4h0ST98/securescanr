#!/usr/bin/env bash
#
# cutover-check.sh — is securescanr.com actually live yet?
#
# Companion to deploy-check.sh: that one validates the repo BEFORE you push,
# this one checks the live estate AFTER.
#
# Checks the five steps of the webaudit.in → securescanr.com cutover, in the
# order they have to happen, and names the one that is still wrong. Written
# because the failure modes look identical from a browser: "the site is broken"
# is equally true when DNS is unset, when Pages is building the wrong repo, and
# when the backend is up but refusing the origin.
#
#   ./cutover-check.sh              # check production
#   ./cutover-check.sh --local      # check a local dev pair instead
#   SITE=staging.securescanr.com ./cutover-check.sh
#
# Exit status is the number of failed checks, so CI can gate on it.

set -uo pipefail

SITE="${SITE:-securescanr.com}"
API="${API:-api.securescanr.com}"
OLD="${OLD:-webaudit.in}"
RAILWAY="${RAILWAY:-r75lvhh6.up.railway.app}"
# A string that exists only in the redesigned build. If Pages is serving the
# old WebAudit repo the page still returns 200, so status codes prove nothing.
MARKER="${MARKER:-ways to lose a point}"
TIMEOUT="${TIMEOUT:-15}"

if [ "${1:-}" = "--local" ]; then
  SITE="localhost:8899"; API="localhost:5000"; SCHEME="http"
else
  SCHEME="https"
fi

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[2m'; N=$'\e[0m'; BOLD=$'\e[1m'
else
  R=""; G=""; Y=""; B=""; N=""; BOLD=""
fi

PASS=0; FAIL=0; WARN=0
step()  { printf '\n%s── %s %s\n' "$BOLD" "$*" "$N"; }
ok()    { PASS=$((PASS+1)); printf '  %sPASS%s  %s\n' "$G" "$N" "$1"; }
bad()   { FAIL=$((FAIL+1)); printf '  %sFAIL%s  %s\n' "$R" "$N" "$1"; [ -n "${2:-}" ] && printf '        %sfix: %s%s\n' "$B" "$2" "$N"; return 0; }
warn()  { WARN=$((WARN+1)); printf '  %sWARN%s  %s\n' "$Y" "$N" "$1"; [ -n "${2:-}" ] && printf '        %s%s%s\n' "$B" "$2" "$N"; return 0; }
note()  { printf '        %s%s%s\n' "$B" "$1" "$N"; }

# Resolve a hostname to a space-separated list, whatever tools exist.
resolve() {
  if command -v dig >/dev/null 2>&1; then
    dig +short "$1" 2>/dev/null | tr '\n' ' '
  elif command -v host >/dev/null 2>&1; then
    host "$1" 2>/dev/null | awk '/address|alias/ {print $NF}' | tr '\n' ' '
  else
    getent hosts "$1" 2>/dev/null | awk '{print $1}' | tr '\n' ' '
  fi
}

# `printf ... | grep -q` is NOT safe under `set -o pipefail`: grep exits on the
# first match, printf takes SIGPIPE, and the pipeline reports failure even
# though the match succeeded. It only shows up once the body is big enough that
# printf is still writing — i.e. on every real page. Substring tests below use
# bash pattern matching instead, which involves no pipe at all.
has()  { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
hasi() { local h="${1,,}" n="${2,,}"; case "$h" in *"$n"*) return 0 ;; *) return 1 ;; esac; }

# Strip any :port so DNS lookups get a bare hostname.
hostonly() { printf '%s' "${1%%:*}"; }

# curl that never hangs and never dies on a bad cert (we test the cert
# separately — a TLS failure should read as "no certificate", not as a timeout).
fetch() { curl -sS -m "$TIMEOUT" "$@" 2>/dev/null; }
code()  { curl -s -o /dev/null -m "$TIMEOUT" -w '%{http_code}' "$@" 2>/dev/null; }

printf '%sSecureScanr cutover check%s  %s → %s\n' "$BOLD" "$N" "$SCHEME://$SITE" "$SCHEME://$API"
printf '%s%s%s\n' "$B" "$(date -u '+%Y-%m-%d %H:%MZ')" "$N"

# ── 1 · Frontend is served, and it is the RIGHT build ─────────────────────────
step "1 · Frontend  ($SITE)"

site_code=$(code "$SCHEME://$SITE/")
if [ "$site_code" = "000" ]; then
  bad "no HTTPS response from $SITE" \
      "connect a Cloudflare Pages project to G4h0ST98/securescanr (output dir: frontend/), then point the domain at it"
  ips=$(resolve "$(hostonly "$SITE")")
  [ -n "$ips" ] && note "resolves to: $ips"
  case "$ips" in
    *porkbun*|*207.207.210*) note "those are Porkbun parking records — the domain has never been pointed anywhere" ;;
  esac
elif [ "$site_code" -ge 500 ] 2>/dev/null; then
  bad "$SITE returned HTTP $site_code" "the domain resolves but nothing is serving it"
else
  ok "$SITE responds (HTTP $site_code)"

  body=$(fetch "$SCHEME://$SITE/methodology.html")
  if [ -z "$body" ]; then
    bad "could not read /methodology.html" "check the Pages build actually published"
  elif hasi "$body" "$MARKER"; then
    ok "serving the redesigned build (found \"$MARKER\")"
  elif hasi "$body" 'WebAudit'; then
    bad "serving the OLD WebAudit build" \
        "Pages is building the wrong repo — repoint it at G4h0ST98/securescanr"
  else
    warn "could not confirm which build is live" \
         "marker \"$MARKER\" not found; set MARKER= to a string unique to the current build"
  fi
fi

# ── 2 · TLS ───────────────────────────────────────────────────────────────────
if [ "$SCHEME" = "https" ]; then
  step "2 · TLS  ($SITE)"
  if ! command -v openssl >/dev/null 2>&1; then
    warn "openssl not installed — skipping certificate check"
  else
    cert=$(timeout "$TIMEOUT" openssl s_client -connect "$SITE:443" -servername "$SITE" </dev/null 2>&1)
    if has "$cert" 'no peer certificate'; then
      bad "no certificate presented on :443" \
          "nothing is terminating TLS — the host is not on Cloudflare/Pages yet"
    else
      issuer=$(printf '%s' "$cert" | sed -n 's/^issuer=//p' | head -1)
      vfy=$(printf '%s' "$cert" | sed -n 's/^ *Verify return code: //p' | tail -1)
      case "$vfy" in
        0*) ok "certificate valid  ${issuer:-(issuer unknown)}" ;;
        "") warn "certificate present, verification result unknown" ;;
        *)  bad "certificate does not verify — $vfy" "wait for issuance, or re-add the custom domain" ;;
      esac
    fi
  fi
else
  step "2 · TLS"
  note "skipped for --local"
fi

# ── 3 · API host exists and answers ───────────────────────────────────────────
step "3 · API host  ($API)"

if [ "$SCHEME" = "http" ]; then
  api_ips="(local)"
else
  api_ips=$(resolve "$(hostonly "$API")")
fi
case "$api_ips" in
  "(local)")    note "DNS check skipped for --local" ;;
  "")           bad "$API does not resolve" "add a CNAME: $API → $RAILWAY" ;;
  *porkbun*|*207.207.210*)
                bad "$API points at Porkbun parking, not Railway" \
                    "replace the parking record with a CNAME: $API → $RAILWAY" ;;
  *)            ok "$API resolves  ($api_ips)" ;;
esac

API_UP=0
health=$(fetch "$SCHEME://$API/health")
if has "$health" '"ok"'; then
  ok "/health returns ok"; API_UP=1
else
  hcode=$(code "$SCHEME://$API/health")
  if [ "$hcode" = "404" ]; then
    bad "Railway returned 404 for /health" \
        "the CNAME exists but the domain is not registered on the Railway service — add it as a custom domain"
  else
    bad "no healthy response from $API/health (HTTP $hcode)" \
        "check the Railway deployment is running"
  fi
fi

# ── 4 · Backend accepts the new origin (the step people skip) ─────────────────
step "4 · CORS  (does the API accept $SITE?)"

# preflight_acao <api-origin> <request-origin>
preflight_acao() {
  curl -s -o /dev/null -m "$TIMEOUT" -D - -X OPTIONS "$1/api/scan" \
    -H "Origin: $2" \
    -H 'Access-Control-Request-Method: POST' \
    -H 'Access-Control-Request-Headers: content-type' 2>/dev/null \
  | tr -d '\r' | awk 'tolower($1)=="access-control-allow-origin:" {print $2}'
}

want_origin="$SCHEME://$SITE"

# If the new API host is not up yet, fall back to the backend that IS live so we
# can still answer the independent question: has the redeploy happened? This is
# the step that gets skipped, because fixing DNS makes people assume they are
# done — the browser still blocks everything until the new build ships.
if [ "$API_UP" -eq 1 ]; then
  CORS_HOST="$SCHEME://$API"; CORS_WHICH="the new API host"
else
  CORS_HOST="https://api.$OLD"; CORS_WHICH="the currently deployed backend (api.$OLD)"
  note "$API is not reachable — testing $CORS_WHICH instead"
fi

acao=$(preflight_acao "$CORS_HOST" "$want_origin")
if [ -n "$acao" ]; then
  ok "$CORS_WHICH accepts $want_origin  (ACAO: $acao)"
else
  old_acao=$(preflight_acao "$CORS_HOST" "https://$OLD")
  if [ -n "$old_acao" ]; then
    bad "$CORS_WHICH allows https://$OLD but NOT $want_origin — stale build" \
        "redeploy the backend from G4h0ST98/securescanr; backend/app.py already lists the new origins"
  elif [ "$API_UP" -eq 0 ]; then
    warn "could not test CORS — no backend reachable" "fix check 3 first"
  else
    bad "no Access-Control-Allow-Origin for $want_origin" \
        "add the origin to the CORS list in backend/app.py and redeploy"
  fi
  note "without this the browser blocks every call, even once DNS is correct"
fi

# ── 5 · End to end: a real scan through the real host ─────────────────────────
step "5 · End to end  (POST /api/scan)"

scan=$(curl -sS -m 45 -X POST "$SCHEME://$API/api/scan" \
        -H 'Content-Type: application/json' \
        -H "Origin: $want_origin" \
        -d '{"url":"https://example.com"}' 2>/dev/null)
if has "$scan" '"score"'; then
  score=$(printf '%s' "$scan" | tr ',' '\n' | sed -n 's/.*"score":[ ]*\([0-9]*\).*/\1/p' | head -1)
  grade=$(printf '%s' "$scan" | tr ',' '\n' | sed -n 's/.*"grade":[ ]*"\([^"]*\)".*/\1/p' | head -1)
  ok "scan succeeded — example.com scored ${score:-?}/100 ${grade:+($grade)}"
else
  bad "scan did not return a score" "fix the checks above first; this one depends on all of them"
  [ -n "$scan" ] && note "response: $(printf '%s' "$scan" | head -c 160)"
fi

# ── 6 · Old domain redirects (SEO) ────────────────────────────────────────────
if [ "$SCHEME" = "https" ]; then
  step "6 · Redirects  ($OLD → $SITE)"
  # follow the chain — Pages emits its own clean-URL hop first, so the first
  # Location header is not the answer
  loc=$(curl -s -L -o /dev/null -m "$TIMEOUT" -w '%{url_effective}' "https://$OLD/methodology.html" 2>/dev/null)
  ocode=$(code "https://$OLD/methodology.html")
  case "$loc" in
    *"$SITE"*) ok "$OLD redirects to $SITE  ($ocode → $loc)" ;;
    *"$OLD"*)  warn "$OLD still serves its own content (HTTP $ocode)" \
                    "Search Console is verified and a sitemap is submitted against $OLD — 301 it to $SITE or lose that indexing" ;;
    "")        warn "could not resolve where $OLD leads" ;;
    *)         warn "$OLD leads somewhere unexpected: $loc" ;;
  esac
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n%s─────────────────────────────%s\n' "$BOLD" "$N"
printf '  %s%d passed%s   %s%d failed%s   %s%d warnings%s\n' \
  "$G" "$PASS" "$N" "$R" "$FAIL" "$N" "$Y" "$WARN" "$N"
if [ "$FAIL" -eq 0 ]; then
  printf '  %sCutover looks complete.%s\n\n' "$G" "$N"
else
  printf '  %sFix the first FAIL above — the later checks depend on the earlier ones.%s\n\n' "$Y" "$N"
fi
exit "$FAIL"
