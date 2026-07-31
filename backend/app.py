import base64
import hashlib
import hmac
import json
import logging
import os
import random
import re
import socket
import string
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import razorpay
import requests as req_lib
import resend
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request, Response, send_file
from flask_cors import CORS

from scanner.headers import analyze_headers, fetch_url
from scanner.tls import scan_tls
from scanner.dns import scan_dns
from scanner.cookies import scan_cookies
from scanner.cross_origin import scan_cross_origin
from scanner.page import scan_page
from report.pdf import generate_pdf
from compliance_pdf import evaluate_compliance, generate_compliance_pdf
import db

# Load backend/.env before any os.environ.get() below runs. Optional import so
# the app still boots where the package isn't installed (Railway injects real
# env vars and has no .env file).
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

app = Flask(__name__)

CORS(app,
     # Production origins, plus local dev on any port. The frontend is served
     # separately (Cloudflare Pages in prod, a static server locally), so a
     # localhost frontend calling a localhost Flask is still cross-origin.
     origins=[
         "https://securescanr.com",
         "https://www.securescanr.com",
         re.compile(r"^http://localhost:\d+$"),
         re.compile(r"^http://127\.0\.0\.1:\d+$"),
     ],
     allow_headers=["Content-Type", "X-API-Key", "Authorization"],
     methods=["GET", "POST", "OPTIONS"],
     supports_credentials=False,
     always_send=False)

db.init_db()


# ── Config constants ──────────────────────────────────────────────────────────
_RZP_KEY_ID            = os.environ.get("RAZORPAY_KEY_ID", "")
_RZP_KEY_SECRET        = os.environ.get("RAZORPAY_KEY_SECRET", "")
_RZP_PLAN_ID           = os.environ.get("RAZORPAY_PLAN_ID", "plan_Sk7gZpN95Nen1h")
_RZP_AGENCY_PLAN_ID    = "plan_SmyiLgFmsJGgyy"
_RZP_WEBHOOK_SECRET    = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
_LS_WEBHOOK_SECRET     = os.environ.get("LEMONSQUEEZY_WEBHOOK_SECRET", "")
_LS_API_KEY            = os.environ.get("LEMONSQUEEZY_API_KEY", "")
_LS_PRO_VARIANT_ID          = 1039013
_LS_AGENCY_VARIANT_ID       = 1629482
_LS_OTS_VARIANT_ID          = 1633832
_LS_COMPLIANCE_VARIANT_ID   = 1696995
_RZP_COMPLIANCE_AMOUNT      = 24900  # ₹249 in paise
_RESEND_API_KEY        = os.environ.get("RESEND_API_KEY", "")
_ADMIN_SECRET          = os.environ.get("ADMIN_SECRET", "")
_CRON_SECRET           = os.environ.get("CRON_SECRET", "")
_ENCRYPTION_KEY        = os.environ.get("ENCRYPTION_KEY", "")

# Owner-only scan-limit override. Keys listed here (comma-separated Railway env var)
# get _OWNER_SCAN_LIMIT/month instead of the normal plan limit. Lets the owner's
# own agency key run high-volume outreach without changing any paying customer's
# quota. Remove the env var to revert the key to its normal 500/mo agency limit.
_OWNER_SCAN_KEYS: set[str] = {
    k.strip() for k in os.environ.get("OWNER_SCAN_KEYS", "").split(",") if k.strip()
}
_OWNER_SCAN_LIMIT = int(os.environ.get("OWNER_SCAN_LIMIT", "10000"))

# IPs that bypass rate-limiting and all quota checks (comma-separated Railway env var)
_WHITELISTED_IPS: set[str] = {
    ip.strip() for ip in os.environ.get("WHITELISTED_IPS", "").split(",") if ip.strip()
}

# PDF storage directory for scheduled agency scans
_AGENCY_PDF_DIR = os.environ.get("AGENCY_PDF_DIR", "/data/agency_pdfs")
try:
    os.makedirs(_AGENCY_PDF_DIR, exist_ok=True)
except OSError:
    _AGENCY_PDF_DIR = "/tmp/agency_pdfs"
    os.makedirs(_AGENCY_PDF_DIR, exist_ok=True)

_badge_cache: dict = {}   # {domain: (svg_str, expire_epoch)}
_BADGE_TTL = 86400        # 24 hours

_BADGE_COLORS = {
    "A+": ("#2ed573", "#0a0b0d"),
    "A":  ("#2ed573", "#0a0b0d"),
    "B":  ("#00d4aa", "#0a0b0d"),
    "C":  ("#ffa502", "#0a0b0d"),
    "D":  ("#ff6b35", "#ffffff"),
    "F":  ("#ff4757", "#ffffff"),
}


# ── Fernet encryption ─────────────────────────────────────────────────────────

def _get_fernet() -> Fernet | None:
    if not _ENCRYPTION_KEY:
        return None
    try:
        return Fernet(_ENCRYPTION_KEY.encode())
    except Exception:
        return None


def _encrypt_email(email: str) -> str:
    f = _get_fernet()
    if not f:
        return email  # unencrypted fallback (dev only)
    return f.encrypt(email.encode()).decode()


def _decrypt_email(encrypted: str) -> str:
    f = _get_fernet()
    if not f:
        return encrypted
    try:
        return f.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        return ""


# ── Badge helpers ─────────────────────────────────────────────────────────────

def _badge_svg(grade: str | None, score: int | None) -> bytes:
    if not grade or grade not in _BADGE_COLORS:
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="20" role="img"'
            ' aria-label="SecureScanr: unscanned">'
            "<title>SecureScanr: not yet scanned</title>"
            "<defs><clipPath id=\"r\"><rect width=\"200\" height=\"20\" rx=\"3\"/></clipPath></defs>"
            '<g clip-path="url(#r)">'
            '<rect width="86" height="20" fill="#111318"/>'
            '<rect x="86" width="114" height="20" fill="#374151"/>'
            "</g>"
            '<g font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="10">'
            '<text x="43" y="14" text-anchor="middle" fill="#e8eaf0">SecureScanr</text>'
            '<text x="143" y="14" text-anchor="middle" fill="#9ca3af">unscanned</text>'
            "</g></svg>"
        )
        return svg.encode("utf-8")
    bg, fg = _BADGE_COLORS[grade]
    score_str = str(score) if score is not None else "?"
    label = f"{grade} {score_str}/100"
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="20" role="img"'
        f' aria-label="SecureScanr: {label}">'
        f"<title>SecureScanr security grade: {label}</title>"
        f"<defs><clipPath id=\"r\"><rect width=\"200\" height=\"20\" rx=\"3\"/></clipPath></defs>"
        f'<g clip-path="url(#r)">'
        f'<rect width="86" height="20" fill="#111318"/>'
        f'<rect x="86" width="114" height="20" fill="{bg}"/>'
        f"</g>"
        f'<g font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="10">'
        f'<text x="43" y="14" text-anchor="middle" fill="#e8eaf0">SecureScanr</text>'
        f'<text x="143" y="14" text-anchor="middle" fill="{fg}" font-weight="bold">{label}</text>'
        f"</g></svg>"
    )
    return svg.encode("utf-8")


def _normalize_badge_domain(raw: str) -> str:
    raw = raw.strip()
    for scheme in ("https://", "http://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme):]
            break
    if raw.startswith("www."):
        raw = raw[4:]
    for sep in ("/", "?", "#"):
        raw = raw.split(sep)[0]
    return raw.lower()


# ── Hall of Fame domains ──────────────────────────────────────────────────────

_HOF_DOMAINS = [
    "sbi.co.in",
    "hdfc.com",
    "irctc.co.in",
    "flipkart.com",
    "zomato.com",
    "swiggy.com",
    "paytm.com",
    "myntra.com",
    "makemytrip.com",
    "ola.com",
]
_hof_scanning = False


def _sync_hof_domains() -> None:
    rows   = db.get_halloffame()
    cached = {r["domain"] for r in rows}
    stale  = cached - set(_HOF_DOMAINS)
    if stale:
        db.clear_halloffame()
        logging.info("HOF: cache cleared — removed stale domains: %s", stale)

_sync_hof_domains()


# ── World Security Index seed data ────────────────────────────────────────────

_WORLD_INDEX_SEED = [
    # Scores are placeholder estimates — overwritten by the weekly refresh scan.
    # Country codes are the source-of-truth used by _run_world_index_refresh().
    {"rank":  1, "domain": "google.com",         "score": 84, "grade": "A",  "headers": 78, "tls": 95, "dns": 82, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  2, "domain": "youtube.com",        "score": 80, "grade": "A",  "headers": 74, "tls": 92, "dns": 78, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  3, "domain": "facebook.com",       "score": 76, "grade": "B",  "headers": 71, "tls": 88, "dns": 74, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  4, "domain": "instagram.com",      "score": 75, "grade": "B",  "headers": 70, "tls": 87, "dns": 73, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  5, "domain": "twitter.com",        "score": 72, "grade": "B",  "headers": 67, "tls": 85, "dns": 70, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  6, "domain": "whatsapp.com",       "score": 74, "grade": "B",  "headers": 69, "tls": 86, "dns": 72, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  7, "domain": "wikipedia.org",      "score": 66, "grade": "C",  "headers": 61, "tls": 78, "dns": 64, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  8, "domain": "yahoo.com",          "score": 65, "grade": "C",  "headers": 60, "tls": 77, "dns": 63, "country": "US", "last_scanned": "2026-05-26"},
    {"rank":  9, "domain": "amazon.com",         "score": 79, "grade": "B",  "headers": 73, "tls": 90, "dns": 77, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 10, "domain": "tiktok.com",         "score": 63, "grade": "C",  "headers": 57, "tls": 75, "dns": 61, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 11, "domain": "reddit.com",         "score": 68, "grade": "C",  "headers": 63, "tls": 80, "dns": 66, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 12, "domain": "linkedin.com",       "score": 81, "grade": "A",  "headers": 76, "tls": 92, "dns": 79, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 13, "domain": "netflix.com",        "score": 77, "grade": "B",  "headers": 72, "tls": 88, "dns": 75, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 14, "domain": "microsoft.com",      "score": 87, "grade": "A",  "headers": 82, "tls": 94, "dns": 85, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 15, "domain": "bing.com",           "score": 82, "grade": "A",  "headers": 77, "tls": 93, "dns": 80, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 16, "domain": "pinterest.com",      "score": 65, "grade": "C",  "headers": 60, "tls": 77, "dns": 63, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 17, "domain": "twitch.tv",          "score": 67, "grade": "C",  "headers": 62, "tls": 79, "dns": 65, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 18, "domain": "discord.com",        "score": 78, "grade": "B",  "headers": 73, "tls": 89, "dns": 76, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 19, "domain": "telegram.org",       "score": 71, "grade": "B",  "headers": 66, "tls": 83, "dns": 69, "country": "AE", "last_scanned": "2026-05-26"},
    {"rank": 20, "domain": "snapchat.com",       "score": 64, "grade": "C",  "headers": 59, "tls": 76, "dns": 62, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 21, "domain": "github.com",         "score": 94, "grade": "A+", "headers": 91, "tls": 98, "dns": 92, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 22, "domain": "stackoverflow.com",  "score": 69, "grade": "C",  "headers": 64, "tls": 81, "dns": 67, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 23, "domain": "apple.com",          "score": 83, "grade": "A",  "headers": 78, "tls": 94, "dns": 81, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 24, "domain": "adobe.com",          "score": 73, "grade": "B",  "headers": 68, "tls": 85, "dns": 71, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 25, "domain": "dropbox.com",        "score": 78, "grade": "B",  "headers": 73, "tls": 89, "dns": 76, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 26, "domain": "zoom.us",            "score": 76, "grade": "B",  "headers": 71, "tls": 87, "dns": 74, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 27, "domain": "spotify.com",        "score": 74, "grade": "B",  "headers": 69, "tls": 86, "dns": 72, "country": "SE", "last_scanned": "2026-05-26"},
    {"rank": 28, "domain": "paypal.com",         "score": 79, "grade": "B",  "headers": 74, "tls": 90, "dns": 77, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 29, "domain": "ebay.com",           "score": 71, "grade": "B",  "headers": 66, "tls": 83, "dns": 69, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 30, "domain": "walmart.com",        "score": 72, "grade": "B",  "headers": 67, "tls": 84, "dns": 70, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 31, "domain": "nytimes.com",        "score": 69, "grade": "C",  "headers": 64, "tls": 81, "dns": 67, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 32, "domain": "bbc.com",            "score": 69, "grade": "C",  "headers": 64, "tls": 81, "dns": 67, "country": "GB", "last_scanned": "2026-05-26"},
    {"rank": 33, "domain": "cnn.com",            "score": 64, "grade": "C",  "headers": 59, "tls": 76, "dns": 62, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 34, "domain": "theguardian.com",    "score": 67, "grade": "C",  "headers": 62, "tls": 79, "dns": 65, "country": "GB", "last_scanned": "2026-05-26"},
    {"rank": 35, "domain": "reuters.com",        "score": 66, "grade": "C",  "headers": 61, "tls": 78, "dns": 64, "country": "GB", "last_scanned": "2026-05-26"},
    {"rank": 36, "domain": "bloomberg.com",      "score": 71, "grade": "B",  "headers": 66, "tls": 83, "dns": 69, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 37, "domain": "forbes.com",         "score": 64, "grade": "C",  "headers": 59, "tls": 76, "dns": 62, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 38, "domain": "medium.com",         "score": 67, "grade": "C",  "headers": 62, "tls": 79, "dns": 65, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 39, "domain": "quora.com",          "score": 64, "grade": "C",  "headers": 59, "tls": 76, "dns": 62, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 40, "domain": "wordpress.com",      "score": 73, "grade": "B",  "headers": 68, "tls": 85, "dns": 71, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 41, "domain": "shopify.com",        "score": 78, "grade": "B",  "headers": 73, "tls": 89, "dns": 76, "country": "CA", "last_scanned": "2026-05-26"},
    {"rank": 42, "domain": "stripe.com",         "score": 93, "grade": "A+", "headers": 90, "tls": 97, "dns": 91, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 43, "domain": "cloudflare.com",     "score": 97, "grade": "A+", "headers": 95, "tls": 99, "dns": 96, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 44, "domain": "canva.com",          "score": 75, "grade": "B",  "headers": 70, "tls": 87, "dns": 73, "country": "AU", "last_scanned": "2026-05-26"},
    {"rank": 45, "domain": "figma.com",          "score": 80, "grade": "A",  "headers": 75, "tls": 91, "dns": 78, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 46, "domain": "notion.so",          "score": 73, "grade": "B",  "headers": 68, "tls": 85, "dns": 71, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 47, "domain": "slack.com",          "score": 79, "grade": "B",  "headers": 74, "tls": 90, "dns": 77, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 48, "domain": "atlassian.com",      "score": 75, "grade": "B",  "headers": 70, "tls": 87, "dns": 73, "country": "AU", "last_scanned": "2026-05-26"},
    {"rank": 49, "domain": "salesforce.com",     "score": 77, "grade": "B",  "headers": 72, "tls": 88, "dns": 75, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 50, "domain": "hubspot.com",        "score": 76, "grade": "B",  "headers": 71, "tls": 87, "dns": 74, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 51, "domain": "airbnb.com",         "score": 74, "grade": "B",  "headers": 69, "tls": 86, "dns": 72, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 52, "domain": "uber.com",           "score": 73, "grade": "B",  "headers": 68, "tls": 85, "dns": 71, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 53, "domain": "booking.com",        "score": 59, "grade": "D",  "headers": 53, "tls": 71, "dns": 57, "country": "NL", "last_scanned": "2026-05-26"},
    {"rank": 54, "domain": "tripadvisor.com",    "score": 56, "grade": "D",  "headers": 50, "tls": 68, "dns": 54, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 55, "domain": "espn.com",           "score": 63, "grade": "C",  "headers": 58, "tls": 75, "dns": 61, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 56, "domain": "imdb.com",           "score": 65, "grade": "C",  "headers": 60, "tls": 77, "dns": 63, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 57, "domain": "nasa.gov",           "score": 82, "grade": "A",  "headers": 77, "tls": 93, "dns": 80, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 58, "domain": "who.int",            "score": 74, "grade": "B",  "headers": 69, "tls": 86, "dns": 72, "country": "CH", "last_scanned": "2026-05-26"},
    {"rank": 59, "domain": "un.org",             "score": 72, "grade": "B",  "headers": 67, "tls": 84, "dns": 70, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 60, "domain": "worldbank.org",      "score": 76, "grade": "B",  "headers": 71, "tls": 87, "dns": 74, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 61, "domain": "europa.eu",          "score": 78, "grade": "B",  "headers": 73, "tls": 89, "dns": 76, "country": "BE", "last_scanned": "2026-05-26"},
    {"rank": 62, "domain": "baidu.com",          "score": 61, "grade": "C",  "headers": 55, "tls": 73, "dns": 59, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 63, "domain": "alibaba.com",        "score": 62, "grade": "C",  "headers": 56, "tls": 74, "dns": 60, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 64, "domain": "tencent.com",        "score": 63, "grade": "C",  "headers": 57, "tls": 75, "dns": 61, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 65, "domain": "weibo.com",          "score": 55, "grade": "D",  "headers": 49, "tls": 67, "dns": 53, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 66, "domain": "qq.com",             "score": 59, "grade": "D",  "headers": 53, "tls": 71, "dns": 57, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 67, "domain": "jd.com",             "score": 64, "grade": "C",  "headers": 58, "tls": 76, "dns": 62, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 68, "domain": "taobao.com",         "score": 58, "grade": "D",  "headers": 52, "tls": 70, "dns": 56, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 69, "domain": "naver.com",          "score": 71, "grade": "B",  "headers": 66, "tls": 83, "dns": 69, "country": "KR", "last_scanned": "2026-05-26"},
    {"rank": 70, "domain": "kakao.com",          "score": 69, "grade": "C",  "headers": 64, "tls": 81, "dns": 67, "country": "KR", "last_scanned": "2026-05-26"},
    {"rank": 71, "domain": "line.me",            "score": 73, "grade": "B",  "headers": 68, "tls": 85, "dns": 71, "country": "JP", "last_scanned": "2026-05-26"},
    {"rank": 72, "domain": "rakuten.com",        "score": 68, "grade": "C",  "headers": 63, "tls": 80, "dns": 66, "country": "JP", "last_scanned": "2026-05-26"},
    {"rank": 73, "domain": "mercadolibre.com",   "score": 64, "grade": "C",  "headers": 58, "tls": 76, "dns": 62, "country": "AR", "last_scanned": "2026-05-26"},
    {"rank": 74, "domain": "flipkart.com",       "score": 75, "grade": "B",  "headers": 70, "tls": 87, "dns": 73, "country": "IN", "last_scanned": "2026-05-26"},
    {"rank": 75, "domain": "indiatoday.in",      "score": 50, "grade": "D",  "headers": 44, "tls": 62, "dns": 48, "country": "IN", "last_scanned": "2026-05-26"},
    {"rank": 76, "domain": "timesofindia.com",   "score": 47, "grade": "F",  "headers": 41, "tls": 59, "dns": 45, "country": "IN", "last_scanned": "2026-05-26"},
    {"rank": 77, "domain": "ndtv.com",           "score": 44, "grade": "F",  "headers": 38, "tls": 56, "dns": 42, "country": "IN", "last_scanned": "2026-05-26"},
    {"rank": 78, "domain": "bbc.co.uk",          "score": 70, "grade": "B",  "headers": 65, "tls": 82, "dns": 68, "country": "GB", "last_scanned": "2026-05-26"},
    {"rank": 79, "domain": "mail.ru",            "score": 52, "grade": "D",  "headers": 46, "tls": 64, "dns": 50, "country": "RU", "last_scanned": "2026-05-26"},
    {"rank": 80, "domain": "vk.com",             "score": 54, "grade": "D",  "headers": 48, "tls": 66, "dns": 52, "country": "RU", "last_scanned": "2026-05-26"},
    {"rank": 81, "domain": "yandex.ru",          "score": 63, "grade": "C",  "headers": 57, "tls": 75, "dns": 61, "country": "RU", "last_scanned": "2026-05-26"},
    {"rank": 82, "domain": "ok.ru",              "score": 48, "grade": "F",  "headers": 42, "tls": 60, "dns": 46, "country": "RU", "last_scanned": "2026-05-26"},
    {"rank": 83, "domain": "globo.com",          "score": 60, "grade": "C",  "headers": 54, "tls": 72, "dns": 58, "country": "BR", "last_scanned": "2026-05-26"},
    {"rank": 84, "domain": "uol.com.br",         "score": 55, "grade": "D",  "headers": 49, "tls": 67, "dns": 53, "country": "BR", "last_scanned": "2026-05-26"},
    {"rank": 85, "domain": "samsung.com",        "score": 78, "grade": "B",  "headers": 73, "tls": 89, "dns": 76, "country": "KR", "last_scanned": "2026-05-26"},
    {"rank": 86, "domain": "sony.com",           "score": 74, "grade": "B",  "headers": 69, "tls": 86, "dns": 72, "country": "JP", "last_scanned": "2026-05-26"},
    {"rank": 87, "domain": "lg.com",             "score": 72, "grade": "B",  "headers": 67, "tls": 84, "dns": 70, "country": "KR", "last_scanned": "2026-05-26"},
    {"rank": 88, "domain": "intel.com",          "score": 80, "grade": "A",  "headers": 75, "tls": 91, "dns": 78, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 89, "domain": "nvidia.com",         "score": 78, "grade": "B",  "headers": 73, "tls": 89, "dns": 76, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 90, "domain": "amd.com",            "score": 75, "grade": "B",  "headers": 70, "tls": 87, "dns": 73, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 91, "domain": "oracle.com",         "score": 82, "grade": "A",  "headers": 77, "tls": 93, "dns": 80, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 92, "domain": "ibm.com",            "score": 80, "grade": "A",  "headers": 75, "tls": 91, "dns": 78, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 93, "domain": "cisco.com",          "score": 83, "grade": "A",  "headers": 78, "tls": 94, "dns": 81, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 94, "domain": "dell.com",           "score": 76, "grade": "B",  "headers": 71, "tls": 87, "dns": 74, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 95, "domain": "hp.com",             "score": 74, "grade": "B",  "headers": 69, "tls": 86, "dns": 72, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 96, "domain": "lenovo.com",         "score": 68, "grade": "C",  "headers": 63, "tls": 80, "dns": 66, "country": "CN", "last_scanned": "2026-05-26"},
    {"rank": 97, "domain": "asus.com",           "score": 70, "grade": "B",  "headers": 65, "tls": 82, "dns": 68, "country": "TW", "last_scanned": "2026-05-26"},
    {"rank": 98, "domain": "bandcamp.com",       "score": 64, "grade": "C",  "headers": 59, "tls": 76, "dns": 62, "country": "US", "last_scanned": "2026-05-26"},
    {"rank": 99, "domain": "soundcloud.com",     "score": 67, "grade": "C",  "headers": 62, "tls": 79, "dns": 65, "country": "DE", "last_scanned": "2026-05-26"},
]
_world_index_refreshing = False


def _seed_world_index() -> None:
    if db.world_index_count() == 0:
        for entry in _WORLD_INDEX_SEED:
            db.upsert_world_index_entry(
                entry["domain"], entry["rank"], entry["score"], entry["grade"],
                entry["headers"], entry["tls"], entry["dns"],
                entry["country"], entry["last_scanned"],
            )
        logging.info("World Index: seeded %d entries from static data", len(_WORLD_INDEX_SEED))

_seed_world_index()


# ── Email templates ───────────────────────────────────────────────────────────

_EMAIL_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',system-ui,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#111827;border-radius:12px;border:1px solid #1e2a3a;overflow:hidden;">
        <tr>
          <td style="padding:32px 40px 24px;border-bottom:1px solid #1e2a3a;">
            <span style="font-size:20px;font-weight:700;color:#94a3b8;letter-spacing:-.3px;">
              Web<span style="color:#06B6D4;">Audit</span>
            </span>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px 32px;">
            <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:#f1f5f9;letter-spacing:-.4px;">
              Your API key is ready
            </h1>
            <p style="margin:0 0 28px;font-size:15px;color:#94a3b8;line-height:1.6;">
              Thank you for subscribing to SecureScanr Pro. Here is your API key — keep it safe and do not share it publicly.
            </p>
            <div style="background:#0a0f1e;border:1px solid #06B6D4;border-radius:8px;padding:20px 24px;margin-bottom:28px;">
              <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#06B6D4;">
                Your API Key
              </p>
              <code style="font-family:'Courier New',Courier,monospace;font-size:15px;color:#f1f5f9;letter-spacing:.5px;word-break:break-all;">
                {api_key}
              </code>
            </div>
            <h2 style="margin:0 0 12px;font-size:16px;font-weight:700;color:#f1f5f9;">How to use it</h2>
            <p style="margin:0 0 12px;font-size:14px;color:#94a3b8;line-height:1.6;">
              Add this key as the <code style="background:#1e2a3a;color:#06B6D4;padding:2px 6px;border-radius:4px;font-size:13px;">X-API-Key</code> header in your requests to <strong style="color:#f1f5f9;">api.securescanr.com</strong>:
            </p>
            <div style="background:#0a0f1e;border:1px solid #1e2a3a;border-radius:8px;padding:16px 20px;margin-bottom:28px;">
              <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:#94a3b8;line-height:1.8;display:block;">
                POST /api/scan/pro<br>
                X-API-Key: {api_key}<br>
                Content-Type: application/json<br><br>
                &#123; "url": "https://yourclient.com" &#125;
              </code>
            </div>
            <p style="margin:0 0 32px;font-size:14px;color:#94a3b8;line-height:1.6;">
              PDF exports are available at <code style="background:#1e2a3a;color:#06B6D4;padding:2px 6px;border-radius:4px;font-size:13px;">POST /api/report/pdf</code> with the same header.
              Your plan includes 50 scans per month, resetting on the 1st.
            </p>
            <a href="https://securescanr.com/dashboard.html?key={api_key}" style="display:inline-block;background:#06B6D4;color:#0a0f1e;font-size:14px;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;margin-bottom:16px;">
              Access your dashboard →
            </a>
            <p style="margin:12px 0 0;font-size:13px;color:#4b5563;">
              Or <a href="https://securescanr.com" style="color:#06B6D4;text-decoration:none;">go to securescanr.com</a> to run a scan directly.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 40px 28px;border-top:1px solid #1e2a3a;">
            <p style="margin:0;font-size:13px;color:#4b5563;line-height:1.6;">
              Questions? Reply to this email — I read every message.<br>
              <a href="https://securescanr.com" style="color:#06B6D4;text-decoration:none;">securescanr.com</a>
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""

_AGENCY_WELCOME_EMAIL = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',system-ui,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#111827;border-radius:12px;border:1px solid #1e2a3a;overflow:hidden;">
        <tr>
          <td style="padding:32px 40px 24px;border-bottom:1px solid #1e2a3a;">
            <span style="font-size:20px;font-weight:700;color:#94a3b8;letter-spacing:-.3px;">
              Web<span style="color:#06B6D4;">Audit</span>
            </span>
            <span style="margin-left:10px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#06B6D4;vertical-align:middle;">Agency</span>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px 32px;">
            <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:#f1f5f9;letter-spacing:-.4px;">
              Your Agency account is active
            </h1>
            <p style="margin:0 0 28px;font-size:15px;color:#94a3b8;line-height:1.6;">
              {intro}
            </p>
            <div style="background:#0a0f1e;border:1px solid #06B6D4;border-radius:8px;padding:20px 24px;margin-bottom:28px;">
              <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#06B6D4;">
                Your Agency API Key
              </p>
              <code style="font-family:'Courier New',Courier,monospace;font-size:15px;color:#f1f5f9;letter-spacing:.5px;word-break:break-all;">
                {api_key}
              </code>
            </div>
            <h2 style="margin:0 0 12px;font-size:16px;font-weight:700;color:#f1f5f9;">Monitored domains</h2>
            <div style="background:#0a0f1e;border:1px solid #1e2a3a;border-radius:8px;padding:16px 20px;margin-bottom:28px;">
              <p style="margin:0;font-family:'Courier New',Courier,monospace;font-size:13px;color:#94a3b8;line-height:1.8;">
                {domains_list}
              </p>
            </div>
            <h2 style="margin:0 0 12px;font-size:16px;font-weight:700;color:#f1f5f9;">Schedule</h2>
            <p style="margin:0 0 28px;font-size:14px;color:#94a3b8;line-height:1.6;">
              {schedule_desc}. You will receive a PDF security report for each domain by email on schedule. You can also trigger an immediate scan from your agency dashboard.
            </p>
            <a href="https://securescanr.com/agency-dashboard.html?api_key={api_key}" style="display:inline-block;background:#06B6D4;color:#0a0f1e;font-size:14px;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;margin-bottom:16px;">
              Open Agency Dashboard →
            </a>
            <p style="margin:12px 0 0;font-size:13px;color:#4b5563;">
              Bookmark the dashboard URL above — it uses your API key for access. Keep this key private.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 40px 28px;border-top:1px solid #1e2a3a;">
            <p style="margin:0;font-size:13px;color:#4b5563;line-height:1.6;">
              Questions? Reply to this email — I read every message.<br>
              <a href="https://securescanr.com" style="color:#06B6D4;text-decoration:none;">securescanr.com</a>
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""

_AGENCY_REPORT_EMAIL = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',system-ui,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#111827;border-radius:12px;border:1px solid #1e2a3a;overflow:hidden;">
        <tr>
          <td style="padding:32px 40px 24px;border-bottom:1px solid #1e2a3a;">
            <span style="font-size:20px;font-weight:700;color:#94a3b8;letter-spacing:-.3px;">
              Web<span style="color:#06B6D4;">Audit</span>
            </span>
            <span style="margin-left:10px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#06B6D4;vertical-align:middle;">Scheduled Report</span>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px 32px;">
            <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#f1f5f9;letter-spacing:-.4px;">
              Security report: {domain}
            </h1>
            <p style="margin:0 0 24px;font-size:15px;color:#94a3b8;line-height:1.6;">
              Your scheduled scan for <strong style="color:#f1f5f9;">{domain}</strong> is complete. The PDF report is attached.
            </p>
            <div style="background:#0a0f1e;border:1px solid #1e2a3a;border-radius:8px;padding:20px 24px;margin-bottom:28px;display:flex;gap:24px;">
              <div>
                <p style="margin:0 0 4px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#94a3b8;">Grade</p>
                <p style="margin:0;font-size:32px;font-weight:700;color:{grade_color};">{grade}</p>
              </div>
              <div>
                <p style="margin:0 0 4px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#94a3b8;">Score</p>
                <p style="margin:0;font-size:32px;font-weight:700;color:#f1f5f9;">{score}/100</p>
              </div>
            </div>
            <p style="margin:0 0 28px;font-size:14px;color:#94a3b8;line-height:1.6;">
              Scanned on {scanned_at}. The full PDF report with findings and fix recommendations is attached to this email.
            </p>
            <a href="https://securescanr.com/agency-dashboard.html?api_key={api_key}" style="display:inline-block;background:#06B6D4;color:#0a0f1e;font-size:14px;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;">
              View Dashboard →
            </a>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 40px 28px;border-top:1px solid #1e2a3a;">
            <p style="margin:0;font-size:13px;color:#4b5563;line-height:1.6;">
              <a href="https://securescanr.com" style="color:#06B6D4;text-decoration:none;">securescanr.com</a>
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""

_GRADE_COLORS = {
    "A+": "#2ed573", "A": "#2ed573", "B": "#00d4aa",
    "C": "#ffa502",  "D": "#ff6b35", "F": "#ff4757",
}

_OTS_EMAIL_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',system-ui,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#111827;border-radius:12px;border:1px solid #1e2a3a;overflow:hidden;">
        <tr>
          <td style="padding:32px 40px 24px;border-bottom:1px solid #1e2a3a;">
            <span style="font-size:20px;font-weight:700;color:#94a3b8;letter-spacing:-.3px;">
              Web<span style="color:#06B6D4;">Audit</span>
            </span>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px 32px;">
            <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:#f1f5f9;letter-spacing:-.4px;">
              Your one-time scan is ready
            </h1>
            <p style="margin:0 0 28px;font-size:15px;color:#94a3b8;line-height:1.6;">
              Thank you for your purchase. Your full Pro-level security scan is ready — all headers, TLS, DNS, cookies, cross-origin, and fix recommendations. No account needed.
            </p>
            <p style="margin:0 0 16px;font-size:14px;color:#94a3b8;">
              Click the button below to run your scan. The link expires in <strong style="color:#f1f5f9;">24 hours</strong>.
            </p>
            <a href="{scan_url}" style="display:inline-block;background:#06B6D4;color:#0a0f1e;font-size:14px;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;margin-bottom:24px;">
              Start your scan →
            </a>
            <p style="margin:0;font-size:13px;color:#4b5563;word-break:break-all;">
              Or copy this link: <a href="{scan_url}" style="color:#06B6D4;text-decoration:none;">{scan_url}</a>
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 40px 28px;border-top:1px solid #1e2a3a;">
            <p style="margin:0;font-size:13px;color:#4b5563;line-height:1.6;">
              Questions? Reply to this email.<br>
              <a href="https://securescanr.com" style="color:#06B6D4;text-decoration:none;">securescanr.com</a>
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""


_COMPLIANCE_TOKEN_EMAIL = """\
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:32px 16px;">
      <table width="560" cellpadding="0" cellspacing="0"
             style="background:#fff;border-radius:8px;border:1px solid #e2e8f0;max-width:560px;">
        <tr>
          <td style="padding:28px 40px 20px;">
            <p style="margin:0 0 4px;font-size:22px;font-weight:700;color:#111318;
                      font-family:sans-serif;">SecureScanr</p>
            <p style="margin:0;font-size:13px;color:#64748b;font-family:sans-serif;">
              Security Compliance Assessment
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:0 40px 24px;">
            <p style="margin:0 0 12px;font-size:15px;color:#1e293b;font-family:sans-serif;line-height:1.6;">
              Your compliance report token is ready. Enter it on the compliance report page
              along with your target domain to generate your PDF report.
            </p>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;font-family:sans-serif;">
              This token is valid for <strong>48 hours</strong> and can be used once.
            </p>
            <a href="{redeem_url}"
               style="display:inline-block;padding:12px 28px;background:#00d4aa;
                      color:#0a0b0d;font-weight:700;font-size:14px;border-radius:6px;
                      text-decoration:none;font-family:sans-serif;">
              Generate my compliance report →
            </a>
            <p style="margin:16px 0 0;font-size:12px;color:#94a3b8;font-family:sans-serif;
                      word-break:break-all;">
              Or copy: {redeem_url}
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 40px 24px;border-top:1px solid #e2e8f0;">
            <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.6;font-family:sans-serif;">
              Your report covers OWASP Top 10, PCI-DSS v4.0, GDPR Article 32, and ISO 27001 Annex A.<br>
              Questions? Reply to this email &nbsp;·&nbsp;
              <a href="https://securescanr.com" style="color:#00d4aa;text-decoration:none;">securescanr.com</a>
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""

_COMPLIANCE_REPORT_EMAIL = """\
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:32px 16px;">
      <table width="560" cellpadding="0" cellspacing="0"
             style="background:#fff;border-radius:8px;border:1px solid #e2e8f0;max-width:560px;">
        <tr>
          <td style="padding:28px 40px 20px;">
            <p style="margin:0 0 4px;font-size:22px;font-weight:700;color:#111318;
                      font-family:sans-serif;">SecureScanr</p>
            <p style="margin:0;font-size:13px;color:#64748b;font-family:sans-serif;">
              Security Compliance Assessment
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:0 40px 8px;">
            <p style="margin:0 0 6px;font-size:20px;font-weight:700;color:#111318;
                      font-family:sans-serif;">{domain}</p>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;font-family:sans-serif;">
              Scanned on {scanned_at}
            </p>
            <p style="margin:0 0 12px;font-size:15px;color:#1e293b;font-family:sans-serif;line-height:1.6;">
              Your compliance report is attached. It covers:
            </p>
            <ul style="margin:0 0 16px;padding-left:20px;font-size:14px;color:#374151;
                       font-family:sans-serif;line-height:1.8;">
              <li>OWASP Top 10 2021</li>
              <li>PCI-DSS v4.0 (web application requirements)</li>
              <li>GDPR Article 32 (technical measures)</li>
              <li>ISO 27001:2022 Annex A</li>
            </ul>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;font-family:sans-serif;">
              Overall result: <strong>{passed_total}</strong> requirements passed,
              <strong>{failed_total}</strong> failed across all frameworks.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 40px 24px;border-top:1px solid #e2e8f0;">
            <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.6;font-family:sans-serif;">
              Questions? Reply to this email &nbsp;·&nbsp;
              <a href="https://securescanr.com" style="color:#00d4aa;text-decoration:none;">securescanr.com</a>
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _send_api_key_email(email: str, api_key: str) -> None:
    if not _RESEND_API_KEY or not email:
        return
    try:
        resend.api_key = _RESEND_API_KEY
        resend.Emails.send({
            "from":    "hello@securescanr.com",
            "to":      [email],
            "subject": "Your SecureScanr Pro API Key",
            "html":    _EMAIL_HTML_TEMPLATE.format(api_key=api_key),
        })
    except Exception as exc:
        logging.error("Resend email failed for %s: %s", email, exc)


def _send_agency_welcome_email(email: str, api_key: str, domains: list, schedule_type: str, schedule_day: int) -> None:
    if not _RESEND_API_KEY or not email:
        return
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    if schedule_type == "weekly":
        schedule_desc = f"Weekly on {day_names[schedule_day % 7]}"
    else:
        schedule_desc = f"Monthly on the {schedule_day}th"
    if domains:
        intro        = f"Welcome to SecureScanr Agency. Your account is set up with {len(domains)} domain(s) on a {schedule_type} scan schedule. Here is your agency API key:"
        domains_list = "<br>".join(domains)
    else:
        intro        = "Welcome to SecureScanr Agency. Your account is active. Add your domains and configure your scan schedule from the dashboard below. Here is your agency API key:"
        domains_list = "<em style=\"color:#4b5563;\">None yet — add domains from your dashboard to enable scheduled scanning.</em>"
    try:
        resend.api_key = _RESEND_API_KEY
        resend.Emails.send({
            "from":    "hello@securescanr.com",
            "to":      [email],
            "subject": "SecureScanr Agency — Your account is active",
            "html":    _AGENCY_WELCOME_EMAIL.format(
                api_key=api_key,
                intro=intro,
                schedule_desc=schedule_desc,
                domains_list=domains_list,
            ),
        })
    except Exception as exc:
        logging.error("Agency welcome email failed for %s: %s", email, exc)


def _send_agency_report_email(
    email: str,
    api_key: str,
    domain: str,
    grade: str,
    score: int,
    pdf_bytes: bytes,
) -> None:
    if not _RESEND_API_KEY or not email:
        return
    grade_color = _GRADE_COLORS.get(grade, "#94a3b8")
    scanned_at  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    safe_domain = domain.replace(".", "_")
    try:
        resend.api_key = _RESEND_API_KEY
        resend.Emails.send({
            "from":    "hello@securescanr.com",
            "to":      [email],
            "subject": f"SecureScanr Agency report: {domain} — Grade {grade}",
            "html":    _AGENCY_REPORT_EMAIL.format(
                domain=domain,
                grade=grade,
                score=score,
                grade_color=grade_color,
                scanned_at=scanned_at,
                api_key=api_key,
            ),
            "attachments": [{
                "filename": f"securescanr_{safe_domain}.pdf",
                "content":  base64.b64encode(pdf_bytes).decode(),
            }],
        })
    except Exception as exc:
        logging.error("Agency report email failed for %s / %s: %s", email, domain, exc)


def _send_one_time_scan_email(email: str, token: str) -> None:
    if not _RESEND_API_KEY or not email:
        return
    scan_url = f"https://securescanr.com/one-time-scan.html?token={token}"
    try:
        resend.api_key = _RESEND_API_KEY
        resend.Emails.send({
            "from":    "hello@securescanr.com",
            "to":      [email],
            "subject": "Your SecureScanr one-time scan link",
            "html":    _OTS_EMAIL_HTML.format(scan_url=scan_url),
        })
    except Exception as exc:
        logging.error("OTS email failed for %s: %s", email, exc)


def _send_compliance_token_email(email: str, token: str) -> None:
    if not _RESEND_API_KEY or not email:
        return
    redeem_url = f"https://securescanr.com/compliance-report.html?token={token}"
    try:
        resend.api_key = _RESEND_API_KEY
        resend.Emails.send({
            "from":    "hello@securescanr.com",
            "to":      [email],
            "subject": "Your SecureScanr Compliance Report token",
            "html":    _COMPLIANCE_TOKEN_EMAIL.format(redeem_url=redeem_url),
        })
    except Exception as exc:
        logging.error("Compliance token email failed for %s: %s", email, exc)


def _send_compliance_report_email(
    email: str,
    domain: str,
    pdf_bytes: bytes,
    passed_total: int = 0,
    failed_total: int = 0,
) -> None:
    if not _RESEND_API_KEY or not email:
        return
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    date_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        resend.api_key = _RESEND_API_KEY
        resend.Emails.send({
            "from":    "hello@securescanr.com",
            "to":      [email],
            "subject": f"SecureScanr Compliance Report — {domain}",
            "html":    _COMPLIANCE_REPORT_EMAIL.format(
                domain=domain,
                scanned_at=scanned_at,
                passed_total=passed_total,
                failed_total=failed_total,
            ),
            "attachments": [{
                "filename": f"{domain}_compliance_{date_str}.pdf",
                "content":  base64.b64encode(pdf_bytes).decode(),
            }],
        })
    except Exception as exc:
        logging.error("Compliance report email failed for %s / %s: %s", email, domain, exc)


def _normalise_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    return raw


def _validate_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "URL must use http or https."
    if not parsed.netloc:
        return "URL is missing a host."
    host = parsed.hostname or ""
    blocked = ("localhost", "127.", "10.", "192.168.", "172.")
    if any(host.startswith(p) for p in blocked) or host == "::1":
        return "Scanning private/loopback addresses is not allowed."
    return None


def _detect_cdn(response_headers: dict) -> str:
    """Detect CDN/proxy from HTTP response headers."""
    h = {k.lower(): v for k, v in response_headers.items()}
    server = h.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in h:
        return "Cloudflare"
    if "fastly" in server or "x-served-by" in h or "fastly-restarts" in h:
        return "Fastly"
    if "x-amz-cf-id" in h or "cloudfront" in h.get("via", "").lower():
        return "AWS CloudFront"
    if "akamai" in server or "akamai-grn" in h:
        return "Akamai"
    if "x-azure-ref" in h:
        return "Azure Front Door"
    if "google" in h.get("via", "").lower():
        return "Google Cloud CDN"
    if "x-varnish" in h or "varnish" in server:
        return "Varnish"
    if "sucuri" in server:
        return "Sucuri"
    if "litespeed" in server:
        return "LiteSpeed"
    return "Not detected"


def _resolve_ip(hostname: str) -> str:
    """Resolve hostname to an IPv4 address. Returns '—' on failure."""
    if not hostname:
        return "—"
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return info[0][4][0] if info else "—"
    except Exception:
        return "—"


def _normalize_scan_for_compliance(scan: dict) -> dict:
    """
    Convert raw _run_scan_modules() output to the short-key format that
    compliance_pdf.evaluate_check() expects.
    """
    hr   = scan.get("headers_result") or {}
    raw  = hr.get("headers") or {}        # keyed by full header name
    cors = hr.get("cors") or {}
    fp   = hr.get("server_fingerprint") or {}
    tls  = scan.get("tls_result") or {}
    dns  = scan.get("dns_result") or {}
    page = scan.get("page_result") or {}

    def _h(name: str) -> dict:
        return raw.get(name) or {}

    csp_h  = _h("Content-Security-Policy")
    hsts_h = _h("Strict-Transport-Security")
    xfo_h  = _h("X-Frame-Options")
    xcto_h = _h("X-Content-Type-Options")
    ref_h  = _h("Referrer-Policy")
    perm_h = _h("Permissions-Policy")

    # SPF / DMARC / CAA — scanner returns sub-dicts
    spf_d   = dns.get("spf") or {}
    dmarc_d = dns.get("dmarc") or {}
    caa_d   = dns.get("caa") or {}
    dkim_d  = dns.get("dkim") or {}
    dnssec_d= dns.get("dnssec") or {}

    spf_ok           = isinstance(spf_d, dict) and spf_d.get("status") not in ("missing", "none", "", None)
    dmarc_ok         = isinstance(dmarc_d, dict) and dmarc_d.get("status") not in ("missing", "none", "", None)
    dmarc_enforced   = dmarc_ok and (dmarc_d.get("policy") in ("quarantine", "reject"))
    caa_ok           = isinstance(caa_d, dict) and bool(caa_d.get("records"))
    dkim_ok          = isinstance(dkim_d, dict) and dkim_d.get("present", False)
    dnssec_ok        = isinstance(dnssec_d, dict) and dnssec_d.get("enabled", False)

    # CSP is "warn" when unsafe-inline/unsafe-eval are present
    csp_unsafe = csp_h.get("status") == "warn"

    # CORS wildcard — scanner sets status "bad" for HTML pages with wildcard
    cors_wildcard = cors.get("status") == "bad"

    # Server fingerprint — any non-zero deduction means version info exposed
    fp_exposed = bool(fp.get("fingerprints")) or fp.get("total_deduction", 0) > 0

    # TLS valid — supported and no severe deductions (< 30 pts)
    tls_valid = tls.get("supported", False) and tls.get("total_deduction", 0) < 30

    return {
        "domain": scan.get("domain", ""),
        "headers_result": {
            "csp": {
                "present":      csp_h.get("present", False),
                "unsafe_inline": csp_unsafe,
                "unsafe_eval":   csp_unsafe,
            },
            "hsts":        {"present": hsts_h.get("present", False)},
            "xfo":         {"present": xfo_h.get("present",  False) or xfo_h.get("status") == "good"},
            "xcto":        {"present": xcto_h.get("present", False)},
            "referrer":    {"present": ref_h.get("present",  False)},
            "permissions": {"present": perm_h.get("present", False)},
            "cors":        {"wildcard": cors_wildcard},
            "server_fingerprint": fp_exposed,
        },
        "tls_result":     {"valid": tls_valid},
        "dns_result": {
            "spf":            spf_ok,
            "dmarc":          dmarc_ok,
            "dmarc_enforced": dmarc_enforced,
            "caa":            caa_ok,
            "dkim":           dkim_ok,
            "dnssec":         dnssec_ok,
        },
        "cookies_result": scan.get("cookies_result") or {"cookies": []},
        "page_result": {
            "sri_missing":   (page.get("sri") or {}).get("missing_count", 0) > 0,
            "mixed_content": (page.get("mixed_content") or {}).get("count", 0) > 0,
        },
    }


def _run_scan_modules(url: str) -> dict:
    hostname = urlparse(url).hostname or ""
    is_https = url.startswith("https://")

    futures = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures["http"] = pool.submit(fetch_url, url)
        futures["dns"]  = pool.submit(scan_dns, hostname)
        if is_https:
            futures["tls"] = pool.submit(scan_tls, hostname)

        results = {}
        errors  = {}
        for k, fut in futures.items():
            try:
                results[k] = fut.result()
            except (req_lib.RequestException, ValueError) as exc:
                errors[k] = str(exc)

    if "http" in errors:
        raise req_lib.RequestException(errors["http"])

    response            = results["http"]
    headers_result      = analyze_headers(response)
    cookies_result      = scan_cookies(response)
    cross_origin_result = scan_cross_origin(response)
    page_result         = scan_page(response)
    dns_result = results.get("dns", {
        "spf": None, "dmarc": None, "dkim": None, "caa": None, "dnssec": None,
        "total_deduction": 0, "summary": "DNS scan failed.",
    })
    tls_result = results.get("tls") if is_https else {
        "supported": False,
        "error": "Site uses HTTP — no TLS.",
        "certificate": None,
        "connection": None,
        "deductions": [{"reason": "Site does not use HTTPS", "points": 20}],
        "total_deduction": 20,
        "summary": "Site does not use HTTPS.",
    }

    total_deduction = (
        headers_result["total_deduction"]
        + ((tls_result or {}).get("total_deduction", 0))
        + dns_result["total_deduction"]
        + cookies_result["total_deduction"]
        + cross_origin_result["total_deduction"]
        + page_result["total_deduction"]
    )
    score = max(0, 100 - total_deduction)
    grade = _score_to_grade(score)

    module_summaries = [
        headers_result["summary"],
        (tls_result or {}).get("summary", ""),
        dns_result["summary"],
        cookies_result["summary"],
        cross_origin_result["summary"],
    ]
    combined_summary = " | ".join(s for s in module_summaries if s)

    return {
        "response":            response,
        "headers_result":      headers_result,
        "tls_result":          tls_result,
        "dns_result":          dns_result,
        "cookies_result":      cookies_result,
        "cross_origin_result": cross_origin_result,
        "page_result":         page_result,
        "score":               score,
        "grade":               grade,
        "summary":             combined_summary,
    }


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def _client_ip() -> str:
    """Return the real client IP — use rightmost X-Forwarded-For entry (proxy-appended)
    so clients cannot spoof it by injecting a fake leading IP."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Rightmost entry is appended by Railway's proxy and cannot be forged
        return forwarded.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def _quota_key() -> str:
    key = request.headers.get("X-API-Key", "").strip()
    if key:
        return key
    return f"ip:{_client_ip()}"


# ── Short-term rate limiter (5 req/min per IP, in-memory) ─────────────────────
_rate_limit_lock                   = threading.Lock()
_rate_limit_window: dict[str, list] = {}  # ip → [timestamp, ...]
_RATE_LIMIT_MAX    = 5
_RATE_LIMIT_WINDOW = 60  # seconds


def _is_whitelisted() -> bool:
    """Return True if the caller's IP is in WHITELISTED_IPS (bypasses quota + rate limit)."""
    return bool(_WHITELISTED_IPS) and _client_ip() in _WHITELISTED_IPS


def _is_owner_key() -> bool:
    """Return True if the request carries a valid owner key (X-API-Key in OWNER_SCAN_KEYS).
    Owner keys bypass the per-IP rate limit, same as a whitelisted IP."""
    api_key = request.headers.get("X-API-Key", "").strip()
    return bool(api_key) and api_key in _OWNER_SCAN_KEYS


def _is_rate_limited() -> bool:
    """Return True if the caller has exceeded 5 scan requests in the last 60 s."""
    ip  = _client_ip()
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW
    with _rate_limit_lock:
        timestamps = _rate_limit_window.get(ip, [])
        timestamps = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= _RATE_LIMIT_MAX:
            _rate_limit_window[ip] = timestamps
            return True
        timestamps.append(now)
        _rate_limit_window[ip] = timestamps
    return False


def _resolve_key(api_key: str) -> dict | None:
    """Return a normalised key record from api_keys or agency_subscriptions."""
    record = db.get_api_key(api_key)
    if record:
        record["is_agency"] = False
        return record
    agency = db.get_agency_by_api_key(api_key)
    if agency:
        return {
            "api_key":   api_key,
            "email":     _decrypt_email(agency["encrypted_email"]),
            "plan":      "agency",
            "status":    "active",
            "is_agency": True,
        }
    return None


def _scan_limit_for(record: dict, api_key: str) -> int:
    """Monthly scan limit for a key: owner override first, then plan default."""
    if api_key in _OWNER_SCAN_KEYS:
        return _OWNER_SCAN_LIMIT
    return db.AGENCY_MONTHLY_LIMIT if record.get("is_agency") else db.MONTHLY_LIMIT


def _verified_api_key() -> dict | None:
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return None
    return _resolve_key(api_key)


def _verify_razorpay_webhook(payload: bytes, signature: str) -> bool:
    if not _RZP_WEBHOOK_SECRET:
        return False
    expected = hmac.new(
        _RZP_WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _verify_razorpay_subscription(sub_id: str) -> dict | None:
    """Fetch a Razorpay subscription and return it if active, else None."""
    if not _RZP_KEY_ID or not _RZP_KEY_SECRET:
        return None
    try:
        client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))
        sub = client.subscription.fetch(sub_id)
        if sub.get("status") in ("active", "created", "authenticated"):
            return sub
        return None
    except Exception as exc:
        logging.error("Razorpay subscription.fetch failed for %s: %s", sub_id, exc)
        return None


def _verify_ls_subscription(sub_id: str) -> dict | None:
    """Verify a LemonSqueezy subscription via LS API. Returns the attributes dict or None."""
    if not _LS_API_KEY:
        return None
    try:
        resp = req_lib.get(
            f"https://api.lemonsqueezy.com/v1/subscriptions/{sub_id}",
            headers={
                "Authorization": f"Bearer {_LS_API_KEY}",
                "Accept": "application/vnd.api+json",
            },
            timeout=10,
        )
        if not resp.ok:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
        if attrs.get("status") in ("active", "on_trial"):
            return attrs
        return None
    except Exception as exc:
        logging.error("LS subscription verify failed for %s: %s", sub_id, exc)
        return None


def _schedule_matches_today(schedule_type: str, schedule_day: int) -> bool:
    today = datetime.now(timezone.utc)
    if schedule_type == "weekly":
        return today.weekday() == (schedule_day % 7)
    else:  # monthly
        return today.day == schedule_day


def _run_agency_domain_scan(agency: dict, domain: str) -> dict | None:
    """Scan one domain for an agency. Returns {score, grade, pdf_bytes} or None on error."""
    url = f"https://{domain}"
    try:
        scan = _run_scan_modules(url)
    except Exception as exc:
        # Catch all exceptions (not just RequestException) so one failing domain
        # does not crash the caller's loop and skip all remaining domains.
        logging.error("Agency scan failed for %s / %s: %s", agency["id"], domain, exc)
        return None

    response = scan["response"]
    scan_result = {
        "url":               url,
        "final_url":         response.url,
        "status_code":       response.status_code,
        "grade":             scan["grade"],
        "score":             scan["score"],
        "headers":           scan["headers_result"]["headers"],
        "tls":               scan["tls_result"],
        "dns":               scan["dns_result"],
        "cookies":           scan["cookies_result"],
        "cross_origin":      scan["cross_origin_result"],
        "page_analysis":     scan["page_result"],
        "cors":              scan["headers_result"].get("cors"),
        "server_fingerprint": scan["headers_result"].get("server_fingerprint"),
        "cdn":               _detect_cdn(dict(response.headers)),
        "redirect_chain":    [r.url for r in response.history] + [response.url],
        "ip":                _resolve_ip(urlparse(url).hostname or ""),
        "summary":           scan["summary"],
    }
    try:
        pdf_bytes = generate_pdf(scan_result, "")
    except Exception as exc:
        logging.error("Agency PDF generation failed for %s: %s", domain, exc)
        pdf_bytes = b""

    return {"score": scan["score"], "grade": scan["grade"], "pdf_bytes": pdf_bytes}


# ── Hall of Fame background scanner ──────────────────────────────────────────

_HOF_SECURITY_HEADERS = {
    "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
}


def _count_present_security_headers(http_resp) -> int:
    if http_resp is None:
        return 0
    resp_headers = {k.lower() for k in (http_resp.headers or {})}
    return sum(1 for h in _HOF_SECURITY_HEADERS if h in resp_headers)


def _fetch_best_hof_url(domain: str):
    """
    Try https://www.{domain} then https://{domain}.
    Return (url, http_resp) for whichever serves more security headers.
    Prefers www on a tie so CDN-gated sites like cloudflare.com score correctly.
    """
    www_resp  = None
    apex_resp = None
    try:
        www_resp  = fetch_url(f"https://www.{domain}")
    except Exception:
        pass
    try:
        apex_resp = fetch_url(f"https://{domain}")
    except Exception:
        pass

    if www_resp is None and apex_resp is None:
        raise RuntimeError(f"Both www and apex fetch failed for {domain}")
    if www_resp is None:
        return f"https://{domain}", apex_resp
    if apex_resp is None:
        return f"https://www.{domain}", www_resp

    if _count_present_security_headers(www_resp) >= _count_present_security_headers(apex_resp):
        return f"https://www.{domain}", www_resp
    return f"https://{domain}", apex_resp


def _run_hof_scan() -> None:
    global _hof_scanning
    logging.info("HOF: starting background scan of %d domains", len(_HOF_DOMAINS))
    try:
        for domain in _HOF_DOMAINS:
            try:
                with ThreadPoolExecutor(max_workers=3) as pool:
                    f_http = pool.submit(_fetch_best_hof_url, domain)
                    f_dns  = pool.submit(scan_dns, domain)
                    f_tls  = pool.submit(scan_tls, domain)
                    try:
                        url, http_resp = f_http.result(timeout=60)
                        logging.info("HOF: fetching %s (selected over apex/www)", url)
                    except Exception as exc:
                        logging.warning("HOF: HTTP fetch failed for %s: %s — skipping", domain, exc)
                        time.sleep(2)
                        continue
                    try:
                        dns_result = f_dns.result(timeout=10)
                    except Exception:
                        dns_result = {"spf": None, "dmarc": None, "dkim": None, "caa": None, "dnssec": None, "total_deduction": 0, "summary": ""}
                    try:
                        tls_result = f_tls.result(timeout=10)
                    except Exception:
                        tls_result = {
                            "supported": False, "error": "TLS scan failed.",
                            "certificate": None, "connection": None,
                            "deductions": [], "total_deduction": 0, "summary": "",
                        }

                headers_result      = analyze_headers(http_resp)
                cookies_result      = scan_cookies(http_resp)
                cross_origin_result = scan_cross_origin(http_resp)
                page_result         = scan_page(http_resp)

                total_deduction = (
                    headers_result["total_deduction"]
                    + tls_result["total_deduction"]
                    + dns_result["total_deduction"]
                    + cookies_result["total_deduction"]
                    + cross_origin_result["total_deduction"]
                    + page_result["total_deduction"]
                )
                score = max(0, 100 - total_deduction)
                grade = _score_to_grade(score)

                if score == 0:
                    headers = headers_result.get("headers") or {}
                    all_missing = bool(headers) and all(
                        h.get("status") == "missing" for h in headers.values()
                    )
                    if all_missing:
                        logging.warning(
                            "HOF: %s → score=0 with all headers missing (likely bot-blocked) — skipping",
                            domain,
                        )
                        time.sleep(2)
                        continue

                db.upsert_halloffame(domain, grade, score)
                logging.info("HOF: %s → %s (%d)", domain, grade, score)

            except Exception as exc:
                logging.error("HOF: unexpected error for %s: %s — skipping", domain, exc)
            time.sleep(2)
    finally:
        _hof_scanning = False
        logging.info("HOF: background scan complete")


def _update_hof_background(domain: str) -> None:
    """Non-blocking HOF cache update using www-vs-apex normalization.
    Called from user-triggered scan routes so the HOF always reflects the best URL."""
    def _worker():
        try:
            _, http_resp = _fetch_best_hof_url(domain)
            with ThreadPoolExecutor(max_workers=2) as pool:
                f_dns = pool.submit(scan_dns, domain)
                f_tls = pool.submit(scan_tls, domain)
                headers_result      = analyze_headers(http_resp)
                cookies_result      = scan_cookies(http_resp)
                cross_origin_result = scan_cross_origin(http_resp)
                page_result         = scan_page(http_resp)
                try:
                    dns_result = f_dns.result(timeout=10)
                except Exception:
                    dns_result = {"spf": None, "dmarc": None, "dkim": None, "caa": None, "dnssec": None, "total_deduction": 0, "summary": ""}
                try:
                    tls_result = f_tls.result(timeout=10)
                except Exception:
                    tls_result = {"supported": False, "error": "TLS scan failed.", "certificate": None, "connection": None, "deductions": [], "total_deduction": 0, "summary": ""}
            total_deduction = (
                headers_result["total_deduction"] + tls_result["total_deduction"]
                + dns_result["total_deduction"] + cookies_result["total_deduction"]
                + cross_origin_result["total_deduction"] + page_result["total_deduction"]
            )
            score = max(0, 100 - total_deduction)
            grade = _score_to_grade(score)
            db.upsert_halloffame(domain, grade, score)
            logging.info("HOF update: %s → %s (%d)", domain, grade, score)
        except Exception as exc:
            logging.warning("HOF update failed for %s: %s", domain, exc)
    threading.Thread(target=_worker, daemon=True).start()


def _run_world_index_refresh() -> None:
    global _world_index_refreshing
    today      = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    country_map = {e["domain"]: e["country"] for e in _WORLD_INDEX_SEED}
    logging.info("World Index: starting refresh of %d domains", len(_WORLD_INDEX_SEED))
    try:
        for entry in _WORLD_INDEX_SEED:
            domain = entry["domain"]
            try:
                _, http_resp = _fetch_best_hof_url(domain)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    f_dns = pool.submit(scan_dns, domain)
                    f_tls = pool.submit(scan_tls, domain)
                    headers_result      = analyze_headers(http_resp)
                    cookies_result      = scan_cookies(http_resp)
                    cross_origin_result = scan_cross_origin(http_resp)
                    page_result         = scan_page(http_resp)
                    try:
                        dns_result = f_dns.result(timeout=10)
                    except Exception:
                        dns_result = {"spf": None, "dmarc": None, "dkim": None, "caa": None, "dnssec": None, "total_deduction": 0, "summary": ""}
                    try:
                        tls_result = f_tls.result(timeout=10)
                    except Exception:
                        tls_result = {"supported": False, "error": "TLS scan failed.", "certificate": None, "connection": None, "deductions": [], "total_deduction": 0, "summary": ""}

                headers_score = max(0, 100 - headers_result["total_deduction"])
                tls_score     = max(0, 100 - tls_result["total_deduction"])
                dns_score     = max(0, 100 - dns_result["total_deduction"])
                total_deduction = (
                    headers_result["total_deduction"] + tls_result["total_deduction"]
                    + dns_result["total_deduction"] + cookies_result["total_deduction"]
                    + cross_origin_result["total_deduction"] + page_result["total_deduction"]
                )
                score = max(0, 100 - total_deduction)
                grade = _score_to_grade(score)
                db.upsert_world_index_entry(
                    domain, entry["rank"], score, grade,
                    headers_score, tls_score, dns_score,
                    country_map.get(domain, "US"), today,
                )
                logging.info("World Index: %s → %s (%d)", domain, grade, score)
            except Exception as exc:
                logging.error("World Index: error scanning %s: %s — skipping", domain, exc)
            time.sleep(1)
        db.rerank_world_index()
        logging.info("World Index: refresh complete, re-ranked %d domains", len(_WORLD_INDEX_SEED))
    finally:
        _world_index_refreshing = False


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/ping")
def ping():
    return "ok", 200


@app.get("/api/badge")
def api_badge():
    raw = request.args.get("url", "").strip()
    if not raw:
        r = Response(_badge_svg(None, None), content_type="image/svg+xml")
        r.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        return r

    domain = _normalize_badge_domain(raw)
    now = time.time()

    cached = _badge_cache.get(domain)
    if cached and now < cached[1]:
        svg_bytes = cached[0]
    else:
        try:
            record = db.get_domain_grade(domain)
        except Exception:
            record = None
        svg_bytes = _badge_svg(
            record["grade"] if record else None,
            record["score"] if record else None,
        )
        _badge_cache[domain] = (svg_bytes, now + _BADGE_TTL)

    resp = Response(svg_bytes, content_type="image/svg+xml")
    resp.headers["Cache-Control"] = "public, max-age=3600"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    return resp


@app.get("/api/get-payment-route")
def api_get_payment_route():
    forwarded = request.headers.get("X-Forwarded-For", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "")

    provider = "razorpay"
    currency = "INR"

    if ip:
        try:
            geo = req_lib.get(
                f"http://ip-api.com/json/{ip}?fields=countryCode",
                timeout=3,
            )
            if geo.ok and geo.json().get("countryCode") != "IN":
                provider = "lemonsqueezy"
                currency = "USD"
        except Exception:
            pass

    payload: dict = {"provider": provider, "currency": currency}
    if provider == "razorpay":
        payload["key"] = _RZP_KEY_ID
    return jsonify(payload)


@app.post("/api/subscribe/razorpay")
def api_subscribe_razorpay():
    if not _RZP_KEY_ID or not _RZP_KEY_SECRET:
        return jsonify({"error": "Payment not configured."}), 503

    body = request.get_json(silent=True) or {}
    plan = body.get("plan", "pro")
    plan_id = _RZP_AGENCY_PLAN_ID if plan == "agency" else _RZP_PLAN_ID

    try:
        client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))
        subscription = client.subscription.create({
            "plan_id":         plan_id,
            "customer_notify": 1,
            "total_count":     12,
            "quantity":        1,
        })
    except Exception as exc:
        return jsonify({"error": f"Could not create subscription: {exc}"}), 502

    return jsonify({
        "subscription_id": subscription["id"],
        "short_url":       subscription.get("short_url", ""),
    })


@app.post("/api/webhook/razorpay")
def api_webhook_razorpay():
    payload_body = request.get_data()
    signature    = request.headers.get("X-Razorpay-Signature", "")

    if not _verify_razorpay_webhook(payload_body, signature):
        return jsonify({"error": "Invalid signature."}), 400

    event_data = request.get_json(silent=True) or {}
    event      = event_data.get("event", "")

    # ── subscription.charged ──────────────────────────────────────────────────
    # Preferred handler for subscription payments: plan_id is in the payload
    # itself, so no extra Razorpay API call is needed and there is no ambiguity.
    if event == "subscription.charged":
        payload    = event_data.get("payload", {})
        sub_entity = payload.get("subscription", {}).get("entity", {})
        pay_entity = payload.get("payment",      {}).get("entity", {})
        plan_id    = sub_entity.get("plan_id", "")
        sub_id     = sub_entity.get("id", "")
        email      = pay_entity.get("email", "")

        if email and plan_id:
            if plan_id == _RZP_AGENCY_PLAN_ID:
                existing = db.get_agency_by_subscription_id(sub_id, None)
                if not existing:
                    agency_id  = uuid.uuid4().hex
                    agency_key = "wa_agency_" + uuid.uuid4().hex
                    db.create_agency_subscription(
                        agency_id, sub_id, None,
                        _encrypt_email(email), agency_key, [],
                        "weekly", 1,
                    )
                    _send_agency_welcome_email(email, agency_key, [], "weekly", 1)
            elif plan_id == _RZP_PLAN_ID:
                api_key = uuid.uuid4().hex
                db.store_api_key(api_key, email, "pro", razorpay_sub_id=sub_id)
                _send_api_key_email(email, api_key)

        return "", 200

    # ── payment.captured ──────────────────────────────────────────────────────
    # Fallback for non-subscription payments. Subscription payments are handled
    # above via subscription.charged; when subscription_id is present we attempt
    # the same plan check but NEVER fall through to Pro activation on failure —
    # that was the bug that issued Pro keys to Agency subscribers.
    if event == "payment.captured":
        payment         = event_data.get("payload", {}).get("payment", {}).get("entity", {})
        email           = payment.get("email", "")
        subscription_id = payment.get("subscription_id", "")

        if subscription_id:
            try:
                rzp_client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))
                sub = rzp_client.subscription.fetch(subscription_id)
                if sub.get("plan_id") == _RZP_AGENCY_PLAN_ID:
                    existing = db.get_agency_by_subscription_id(subscription_id, None)
                    if not existing and email:
                        agency_id  = uuid.uuid4().hex
                        agency_key = "wa_agency_" + uuid.uuid4().hex
                        db.create_agency_subscription(
                            agency_id, subscription_id, None,
                            _encrypt_email(email), agency_key, [],
                            "weekly", 1,
                        )
                        _send_agency_welcome_email(email, agency_key, [], "weekly", 1)
                    return "", 200
            except Exception as exc:
                logging.warning("Webhook payment.captured: sub fetch failed %s: %s — no key issued", subscription_id, exc)
            # Whether agency, pro, or unknown — subscription.charged covers this.
            # Never fall through to Pro key creation for subscription payments.
            return "", 200

        if not email:
            return "", 200

        # Non-subscription payment — issue Pro key.
        api_key = uuid.uuid4().hex
        db.store_api_key(api_key, email, "pro")
        _send_api_key_email(email, api_key)

    # ── subscription.cancelled / subscription.halted / subscription.completed ─
    # Downgrade the user's Pro key (or deactivate their agency) to free tier.
    if event in ("subscription.cancelled", "subscription.halted", "subscription.completed"):
        sub_entity = event_data.get("payload", {}).get("subscription", {}).get("entity", {})
        sub_id     = sub_entity.get("id", "")
        if sub_id:
            # Pro key downgrade
            key_rec = db.get_api_key_by_rzp_sub_id(sub_id)
            if key_rec:
                db.downgrade_subscription(key_rec["api_key"])
                logging.info("RZP %s: downgraded Pro key for sub %s", event, sub_id)
            # Agency deactivation
            agency = db.get_agency_by_subscription_id(rzp_sub_id=sub_id)
            if agency:
                db.deactivate_agency(agency["id"])
                logging.info("RZP %s: deactivated agency for sub %s", event, sub_id)
        return "", 200

    return "", 200


@app.post("/api/webhook/lemonsqueezy")
def api_webhook_lemonsqueezy():
    payload_body = request.get_data()
    signature    = request.headers.get("X-Signature", "")

    if not _LS_WEBHOOK_SECRET:
        return jsonify({"error": "Webhook not configured."}), 400

    expected = hmac.new(
        _LS_WEBHOOK_SECRET.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify({"error": "Invalid signature."}), 400

    event_data = request.get_json(silent=True) or {}
    event      = (event_data.get("meta") or {}).get("event_name", "")

    if event == "order_created":
        attrs      = (event_data.get("data", {}).get("attributes", {}))
        variant_id = (
            (attrs.get("first_order_item") or {}).get("variant_id")
            or (event_data.get("meta", {}).get("custom_data") or {}).get("variant_id")
        )
        # Skip agency (handled via /api/agency/setup)
        if variant_id and int(variant_id) == _LS_AGENCY_VARIANT_ID:
            return "", 200

        # One-time scan purchase: create token and email the scan link
        if variant_id and int(variant_id) == _LS_OTS_VARIANT_ID:
            order_id  = str(event_data.get("data", {}).get("id", ""))
            ls_pay_id = f"ls_ots_{order_id}"
            if order_id and not db.payment_id_already_used(ls_pay_id):
                email = attrs.get("user_email", "")
                token = db.create_one_time_token(ls_pay_id)
                _send_one_time_scan_email(email, token)
            return "", 200

        # Compliance report purchase: create token and email redemption link
        if variant_id and int(variant_id) == _LS_COMPLIANCE_VARIANT_ID:
            order_id  = str(event_data.get("data", {}).get("id", ""))
            ls_pay_id = f"ls_compliance_{order_id}"
            if order_id and not db.compliance_payment_already_used(ls_pay_id):
                email = attrs.get("user_email", "")
                token = db.create_compliance_token(ls_pay_id, email)
                _send_compliance_token_email(email, token)
            return "", 200

        email   = attrs.get("user_email", "")
        api_key = uuid.uuid4().hex
        db.store_api_key(api_key, email, "pro")
        _send_api_key_email(email, api_key)

    # ── subscription_created: link LS subscription ID to the api_key row ──────
    # Fires after order_created for subscription purchases. We use this to store
    # the LS subscription ID so we can look it up on cancellation events later.
    if event == "subscription_created":
        attrs      = (event_data.get("data", {}).get("attributes", {}))
        ls_sub_id  = str(event_data.get("data", {}).get("id", ""))
        email      = attrs.get("user_email", "")
        variant_id = attrs.get("variant_id")
        # Skip agency (managed via /api/agency/setup, not api_keys table)
        if variant_id and int(variant_id) == _LS_AGENCY_VARIANT_ID:
            return "", 200
        # Skip one-time and compliance variants (not subscriptions)
        if variant_id and int(variant_id) in (_LS_OTS_VARIANT_ID, _LS_COMPLIANCE_VARIANT_ID):
            return "", 200
        if ls_sub_id and email:
            db.update_ls_sub_id(email, ls_sub_id)
            logging.info("LS subscription_created: linked sub %s to email %s", ls_sub_id, email)
        return "", 200

    # ── subscription_cancelled / subscription_expired / subscription_paused ───
    # Downgrade the user's Pro key (or deactivate their agency) to free tier.
    if event in ("subscription_cancelled", "subscription_expired", "subscription_paused"):
        attrs      = (event_data.get("data", {}).get("attributes", {}))
        ls_sub_id  = str(event_data.get("data", {}).get("id", ""))
        variant_id = attrs.get("variant_id")
        # Guard: skip one-time and compliance purchases (shouldn't fire these events, but be safe)
        if variant_id and int(variant_id) in (_LS_OTS_VARIANT_ID, _LS_COMPLIANCE_VARIANT_ID):
            return "", 200
        if ls_sub_id:
            # Pro key downgrade
            key_rec = db.get_api_key_by_ls_sub_id(ls_sub_id)
            if key_rec:
                db.downgrade_subscription(key_rec["api_key"])
                logging.info("LS %s: downgraded Pro key for sub %s", event, ls_sub_id)
            # Agency deactivation
            agency = db.get_agency_by_subscription_id(ls_sub_id=ls_sub_id)
            if agency:
                db.deactivate_agency(agency["id"])
                logging.info("LS %s: deactivated agency for sub %s", event, ls_sub_id)
        return "", 200

    return "", 200


# ── Agency routes ─────────────────────────────────────────────────────────────

@app.post("/api/agency/setup")
def api_agency_setup():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required."}), 400

    rzp_sub_id = str(body.get("razorpay_subscription_id", "")).strip() or None
    ls_sub_id  = str(body.get("lemonsqueezy_subscription_id", "")).strip() or None
    email      = str(body.get("email", "")).strip()
    domains    = body.get("domains", [])
    sched_type = str(body.get("schedule_type", "weekly")).strip().lower()
    sched_day  = int(body.get("schedule_day", 1))

    if not rzp_sub_id and not ls_sub_id:
        return jsonify({"error": "razorpay_subscription_id or lemonsqueezy_subscription_id required."}), 400
    if not email or "@" not in email:
        return jsonify({"error": "Valid email required."}), 400
    if not isinstance(domains, list) or len(domains) == 0:
        return jsonify({"error": "At least one domain required."}), 400
    if len(domains) > 25:
        return jsonify({"error": "Maximum 25 domains allowed."}), 400
    if sched_type not in ("weekly", "monthly"):
        return jsonify({"error": "schedule_type must be weekly or monthly."}), 400
    if sched_type == "weekly" and not (0 <= sched_day <= 6):
        return jsonify({"error": "For weekly schedule, schedule_day must be 0–6 (0=Mon)."}), 400
    if sched_type == "monthly" and not (1 <= sched_day <= 31):
        return jsonify({"error": "For monthly schedule, schedule_day must be 1–31."}), 400

    # Clean domain list
    clean_domains = []
    for d in domains:
        d = str(d).strip().lower()
        d = d.removeprefix("https://").removeprefix("http://")
        d = d.removeprefix("www.")
        if d:
            clean_domains.append(d)
    if not clean_domains:
        return jsonify({"error": "No valid domains provided."}), 400

    # Check for duplicate registration
    existing = db.get_agency_by_subscription_id(rzp_sub_id, ls_sub_id)
    if existing:
        return jsonify({"error": "This subscription is already registered."}), 409

    # Verify subscription
    if rzp_sub_id:
        sub = _verify_razorpay_subscription(rzp_sub_id)
        if sub is None and _RZP_KEY_ID:
            return jsonify({"error": "Razorpay subscription not found or not active."}), 402
    elif ls_sub_id:
        attrs = _verify_ls_subscription(ls_sub_id)
        if attrs is None and _LS_API_KEY:
            return jsonify({"error": "LemonSqueezy subscription not found or not active."}), 402
        if attrs and int(attrs.get("variant_id", 0)) != _LS_AGENCY_VARIANT_ID:
            return jsonify({"error": "This subscription is not an Agency plan."}), 400

    agency_id      = uuid.uuid4().hex
    api_key        = "wa_agency_" + uuid.uuid4().hex
    encrypted_email = _encrypt_email(email)

    db.create_agency_subscription(
        agency_id, rzp_sub_id, ls_sub_id,
        encrypted_email, api_key, clean_domains,
        sched_type, sched_day,
    )
    _send_agency_welcome_email(email, api_key, clean_domains, sched_type, sched_day)

    return jsonify({
        "api_key":       api_key,
        "dashboard_url": f"https://securescanr.com/agency-dashboard.html?api_key={api_key}",
        "domains":       clean_domains,
        "schedule_type": sched_type,
        "schedule_day":  sched_day,
    }), 201


@app.get("/api/agency/dashboard")
def api_agency_dashboard():
    api_key = request.args.get("api_key", "").strip()
    if not api_key:
        return jsonify({"error": "api_key parameter required."}), 401

    agency = db.get_agency_by_api_key(api_key)
    if not agency:
        return jsonify({"error": "Invalid or inactive agency API key."}), 403

    scan_count = db.get_agency_scan_count(agency["id"])
    history    = db.get_agency_history(agency["id"], limit=150)

    return jsonify({
        "api_key":          api_key,
        "domains":          agency["domains"],
        "domain_pdf_prefs": agency.get("domain_pdf_prefs", {}),
        "schedule_type":    agency["schedule_type"],
        "schedule_day":     agency["schedule_day"],
        "scan_count":       scan_count,
        "scan_limit":       db.AGENCY_MONTHLY_LIMIT,
        "created_at":       agency["created_at"],
        "history":          history,
    })


@app.post("/api/agency/scan-now")
def api_agency_scan_now():
    api_key = request.args.get("api_key", "") or (request.get_json(silent=True) or {}).get("api_key", "")
    api_key = str(api_key).strip()
    if not api_key:
        return jsonify({"error": "api_key required."}), 401

    agency = db.get_agency_by_api_key(api_key)
    if not agency:
        return jsonify({"error": "Invalid or inactive agency API key."}), 403

    scan_count = db.get_agency_scan_count(agency["id"])
    domains    = agency["domains"]
    scans_needed = len(domains)
    if scan_count + scans_needed > db.AGENCY_MONTHLY_LIMIT:
        remaining = db.AGENCY_MONTHLY_LIMIT - scan_count
        return jsonify({
            "error": f"Monthly scan limit would be exceeded. {remaining} scans remaining this month.",
        }), 429

    email     = _decrypt_email(agency["encrypted_email"])
    pdf_prefs = agency.get("domain_pdf_prefs", {})
    results   = []

    for domain in domains:
        try:
            result = _run_agency_domain_scan(agency, domain)
            if result is None:
                results.append({"domain": domain, "error": "Scan failed"})
                continue

            history_id = uuid.uuid4().hex
            pdf_path = ""
            if result["pdf_bytes"]:
                pdf_path = os.path.join(_AGENCY_PDF_DIR, f"{history_id}.pdf")
                try:
                    with open(pdf_path, "wb") as f:
                        f.write(result["pdf_bytes"])
                except OSError:
                    pdf_path = ""

            db.save_agency_scan(agency["id"], domain, result["score"], result["grade"], pdf_path)
            db.update_agency_scan_count(agency["id"])

            # Only email PDF if the per-domain toggle is on (default: True)
            if pdf_prefs.get(domain, True):
                _send_agency_report_email(
                    email, agency["api_key"], domain,
                    result["grade"], result["score"], result["pdf_bytes"] or b"",
                )
            results.append({"domain": domain, "score": result["score"], "grade": result["grade"]})
        except Exception as exc:
            logging.error("Unexpected error scanning %s for agency %s: %s", domain, agency["id"], exc)
            results.append({"domain": domain, "error": "Unexpected error"})
            continue
        time.sleep(1)

    return jsonify({"scanned": len([r for r in results if "grade" in r]), "results": results})


@app.post("/api/agency/update")
def api_agency_update():
    api_key = request.args.get("api_key", "") or (request.get_json(silent=True) or {}).get("api_key", "")
    api_key = str(api_key).strip()
    if not api_key:
        return jsonify({"error": "api_key required."}), 401

    agency = db.get_agency_by_api_key(api_key)
    if not agency:
        return jsonify({"error": "Invalid or inactive agency API key."}), 403

    body = request.get_json(silent=True) or {}
    domains          = body.get("domains", agency["domains"])
    sched_type       = str(body.get("schedule_type", agency["schedule_type"])).strip().lower()
    sched_day        = int(body.get("schedule_day", agency["schedule_day"]))
    raw_pdf_prefs    = body.get("domain_pdf_prefs", agency.get("domain_pdf_prefs", {}))
    domain_pdf_prefs = raw_pdf_prefs if isinstance(raw_pdf_prefs, dict) else {}

    if not isinstance(domains, list) or len(domains) == 0:
        return jsonify({"error": "At least one domain required."}), 400
    if len(domains) > 25:
        return jsonify({"error": "Maximum 25 domains allowed."}), 400
    if sched_type not in ("weekly", "monthly"):
        return jsonify({"error": "schedule_type must be weekly or monthly."}), 400

    clean_domains = []
    for d in domains:
        d = str(d).strip().lower()
        d = d.removeprefix("https://").removeprefix("http://")
        d = d.removeprefix("www.")
        if d:
            clean_domains.append(d)

    # Remap prefs to only include cleaned domain names actually in the list
    clean_prefs = {d: bool(domain_pdf_prefs.get(d, True)) for d in clean_domains}

    db.update_agency_settings(agency["id"], clean_domains, sched_type, sched_day, clean_prefs)
    return jsonify({
        "domains":          clean_domains,
        "domain_pdf_prefs": clean_prefs,
        "schedule_type":    sched_type,
        "schedule_day":     sched_day,
    })


@app.post("/api/agency/run-scheduled")
def api_agency_run_scheduled():
    """Internal cron endpoint — runs scheduled scans for all agencies due today."""
    auth = request.headers.get("Authorization", "")
    if not _CRON_SECRET or auth != f"Bearer {_CRON_SECRET}":
        return jsonify({"error": "Unauthorized."}), 401

    agencies = db.get_all_active_agencies()
    summary  = {"checked": len(agencies), "ran": 0, "skipped": 0, "details": []}

    for agency in agencies:
        if not _schedule_matches_today(agency["schedule_type"], agency["schedule_day"]):
            summary["skipped"] += 1
            continue

        scan_count = db.get_agency_scan_count(agency["id"])
        domains    = agency["domains"]
        email      = _decrypt_email(agency["encrypted_email"])
        pdf_prefs  = agency.get("domain_pdf_prefs", {})

        for domain in domains:
            if scan_count >= db.AGENCY_MONTHLY_LIMIT:
                logging.warning("Agency %s hit monthly limit — skipping %s", agency["id"], domain)
                break

            try:
                result = _run_agency_domain_scan(agency, domain)
                if result is None:
                    summary["details"].append({"agency": agency["id"], "domain": domain, "status": "error"})
                    continue

                history_id = uuid.uuid4().hex
                pdf_path   = ""
                if result["pdf_bytes"]:
                    pdf_path = os.path.join(_AGENCY_PDF_DIR, f"{history_id}.pdf")
                    try:
                        with open(pdf_path, "wb") as f:
                            f.write(result["pdf_bytes"])
                    except OSError:
                        pdf_path = ""

                db.save_agency_scan(agency["id"], domain, result["score"], result["grade"], pdf_path)
                db.update_agency_scan_count(agency["id"])
                scan_count += 1

                # Only email PDF if the per-domain toggle is on (default: True)
                if pdf_prefs.get(domain, True):
                    _send_agency_report_email(
                        email, agency["api_key"], domain,
                        result["grade"], result["score"], result["pdf_bytes"],
                    )
                summary["details"].append({
                    "agency": agency["id"], "domain": domain,
                    "grade": result["grade"], "score": result["score"], "status": "ok",
                })
            except Exception as exc:
                logging.error("Unexpected error scanning %s for agency %s: %s", domain, agency["id"], exc)
                summary["details"].append({"agency": agency["id"], "domain": domain, "status": "error"})
            time.sleep(2)

        summary["ran"] += 1

    return jsonify(summary)


@app.get("/api/agency/pdf/<history_id>")
def api_agency_pdf(history_id: str):
    api_key = request.args.get("api_key", "").strip()
    if not api_key:
        return jsonify({"error": "api_key parameter required."}), 401

    agency = db.get_agency_by_api_key(api_key)
    if not agency:
        return jsonify({"error": "Invalid or inactive agency API key."}), 403

    record = db.get_agency_scan_by_id(history_id)
    if not record or record["agency_id"] != agency["id"]:
        return jsonify({"error": "Report not found."}), 404

    pdf_path = record.get("pdf_path", "")
    if not pdf_path or not os.path.exists(pdf_path):
        return jsonify({"error": "PDF not available. It may have expired."}), 404

    safe_domain = record["domain"].replace(".", "_")
    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"securescanr_{safe_domain}.pdf",
    )


# ── Existing routes ───────────────────────────────────────────────────────────

@app.get("/api/halloffame")
def api_halloffame():
    global _hof_scanning
    results = db.get_halloffame()
    if db.halloffame_needs_refresh(n_expected=1) and not _hof_scanning:
        _hof_scanning = True
        threading.Thread(target=_run_hof_scan, daemon=True).start()
    last_scanned = max((r["last_scanned"] for r in results), default=None)
    return jsonify({
        "results":      results,
        "last_scanned": last_scanned,
        "scanning":     _hof_scanning,
    })


@app.get("/api/usage")
def api_usage():
    key = request.args.get("key", "").strip()
    if not key:
        return jsonify({"valid": False}), 400

    record = _resolve_key(key)
    if not record or record["status"] not in ("active", "cancel_pending"):
        return jsonify({"valid": False}), 404

    scan_limit = _scan_limit_for(record, key)
    _, remaining = db.check_quota(key, limit=scan_limit)
    scans_used = scan_limit - remaining

    return jsonify({
        "valid":               True,
        "email":               record["email"],
        "plan":                record["plan"],
        "scans_used":          scans_used,
        "scans_limit":         scan_limit,
        "subscription_status": record["status"],
    })


@app.get("/api/verify-key")
def api_verify_key():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return jsonify({"error": "X-API-Key header required."}), 401

    record = _resolve_key(api_key)
    if not record or record["status"] not in ("active", "cancel_pending"):
        return jsonify({"valid": False}), 401

    return jsonify({"valid": True, "plan": record["plan"]})


@app.post("/api/cancel-subscription")
def api_cancel_subscription():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return jsonify({"error": "X-API-Key header required."}), 401

    _LS_CANCEL_MSG = (
        "No Razorpay subscription found for this key. "
        "International (LemonSqueezy) subscribers can cancel at "
        "webaudit-in.lemonsqueezy.com/billing"
    )

    # ── Pro key (api_keys table) ──────────────────────────────────────────────
    key_record = db.get_api_key(api_key)
    if key_record:
        if key_record["status"] == "cancel_pending":
            return jsonify({"error": "Cancellation is already scheduled for end of billing period."}), 400
        if key_record["status"] != "active":
            return jsonify({"error": "Subscription is not active."}), 400
        rzp_sub_id = key_record.get("razorpay_subscription_id", "").strip()
        if not rzp_sub_id:
            return jsonify({"error": _LS_CANCEL_MSG}), 400
        try:
            client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))
            client.subscription.cancel(rzp_sub_id, {"cancel_at_cycle_end": 1})
            db.update_subscription_status(api_key, "cancel_pending")
            return jsonify({
                "ok":      True,
                "message": "Subscription will cancel at the end of the current billing period.",
            })
        except Exception as exc:
            logging.error("cancel-subscription (pro) failed for sub %s: %s", rzp_sub_id, exc)
            return jsonify({"error": "Failed to cancel with Razorpay. Please email hello@securescanr.com."}), 500

    # ── Agency key (agency_subscriptions table) ───────────────────────────────
    agency = db.get_agency_by_api_key(api_key)
    if agency:
        rzp_sub_id = (agency.get("razorpay_subscription_id") or "").strip()
        if not rzp_sub_id:
            return jsonify({"error": _LS_CANCEL_MSG}), 400
        try:
            client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))
            client.subscription.cancel(rzp_sub_id, {"cancel_at_cycle_end": 1})
            return jsonify({
                "ok":      True,
                "message": "Agency subscription will cancel at the end of the current billing period.",
            })
        except Exception as exc:
            logging.error("cancel-subscription (agency) failed for sub %s: %s", rzp_sub_id, exc)
            return jsonify({"error": "Failed to cancel with Razorpay. Please email hello@securescanr.com."}), 500

    return jsonify({"error": "Invalid or missing API key."}), 401


@app.post("/api/verify-one-time")
def api_verify_one_time():
    body = request.get_json(silent=True)
    if not body or "razorpay_payment_id" not in body:
        return jsonify({"error": "razorpay_payment_id required."}), 400

    payment_id = str(body["razorpay_payment_id"]).strip()
    if not payment_id:
        return jsonify({"error": "razorpay_payment_id cannot be empty."}), 400

    if db.payment_id_already_used(payment_id):
        return jsonify({"error": "This payment has already been used for a scan."}), 409

    if not _RZP_KEY_ID or not _RZP_KEY_SECRET:
        return jsonify({"error": "Payment verification not configured."}), 503

    try:
        rzp_client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))
        payment = rzp_client.payment.fetch(payment_id)
    except Exception as exc:
        return jsonify({"error": f"Could not verify payment: {exc}"}), 502

    if payment.get("status") != "captured":
        return jsonify({"error": "Payment not completed. Please complete your payment first."}), 402

    if payment.get("amount") != 9900:
        return jsonify({"error": "Invalid payment amount for one-time scan."}), 400

    token = db.create_one_time_token(payment_id)
    return jsonify({"token": token, "expires_in": "24 hours"})


# ── Compliance report routes ───────────────────────────────────────────────────

@app.post("/api/compliance-report/pay")
def api_compliance_report_pay():
    """Create a Razorpay order for ₹249 compliance report purchase."""
    if not _RZP_KEY_ID or not _RZP_KEY_SECRET:
        return jsonify({"error": "Payment not configured."}), 503
    try:
        client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))
        order = client.order.create({
            "amount":   _RZP_COMPLIANCE_AMOUNT,
            "currency": "INR",
            "payment_capture": 1,
            "notes": {"product": "compliance_report"},
        })
    except Exception as exc:
        return jsonify({"error": f"Could not create order: {exc}"}), 502

    return jsonify({
        "order_id": order["id"],
        "amount":   _RZP_COMPLIANCE_AMOUNT,
        "currency": "INR",
        "key":      _RZP_KEY_ID,
    })


@app.post("/api/compliance-report/generate")
def api_compliance_report_generate():
    """
    Verify payment, run scan, generate compliance PDF and email it.

    Accepts:
      Razorpay: { url, email, razorpay_payment_id, razorpay_order_id, razorpay_signature }
      LemonSqueezy: { url, compliance_token }   (email is stored on the token)
    """
    body = request.get_json(silent=True) or {}

    url   = _normalise_url(str(body.get("url", "")).strip())
    email = str(body.get("email", "")).strip()

    err = _validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    # ── Auth: Razorpay order signature ────────────────────────────────────────
    rzp_payment_id = str(body.get("razorpay_payment_id", "")).strip()
    rzp_order_id   = str(body.get("razorpay_order_id", "")).strip()
    rzp_signature  = str(body.get("razorpay_signature", "")).strip()

    if rzp_payment_id and rzp_order_id and rzp_signature:
        if not _RZP_KEY_SECRET:
            return jsonify({"error": "Payment verification not configured."}), 503
        # Verify Razorpay payment signature
        sig_payload = f"{rzp_order_id}|{rzp_payment_id}"
        expected = hmac.new(
            _RZP_KEY_SECRET.encode("utf-8"),
            sig_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, rzp_signature):
            return jsonify({"error": "Invalid payment signature."}), 400

        # Prevent replay
        pay_key = f"rzp_compliance_{rzp_payment_id}"
        if db.compliance_payment_already_used(pay_key):
            return jsonify({"error": "This payment has already been used."}), 409
        if not email or "@" not in email:
            return jsonify({"error": "Valid email required."}), 400

    # ── Auth: LemonSqueezy compliance token ───────────────────────────────────
    elif compliance_token := str(body.get("compliance_token", "")).strip():
        token_record = db.get_compliance_token(compliance_token)
        if not token_record:
            return jsonify({"error": "Invalid or expired compliance token."}), 403
        email = token_record["email"] or email

    else:
        return jsonify({"error": "Payment credentials or compliance token required."}), 400

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required."}), 400

    # ── Run scan ──────────────────────────────────────────────────────────────
    try:
        scan = _run_scan_modules(url)
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {exc}"}), 502

    # Normalise raw scanner output to short-key format compliance_pdf expects
    from urllib.parse import urlparse as _up
    domain = _up(url).hostname or url

    scan["domain"] = domain
    scan_result = _normalize_scan_for_compliance(scan)

    # ── Evaluate compliance (for email totals) ────────────────────────────────
    compliance_data = evaluate_compliance(scan_result)

    # ── Generate PDF ──────────────────────────────────────────────────────────
    try:
        pdf_bytes = generate_compliance_pdf(scan_result)
    except Exception as exc:
        logging.error("Compliance PDF generation failed for %s: %s", domain, exc)
        return jsonify({"error": "Report generation failed. Please try again."}), 500

    # Totals for email
    passed_total = sum(fw["passed"] for fw in compliance_data.values())
    failed_total = sum(fw["failed"] for fw in compliance_data.values())

    # ── Email report ──────────────────────────────────────────────────────────
    _send_compliance_report_email(email, domain, pdf_bytes, passed_total, failed_total)

    # ── Mark payment used ─────────────────────────────────────────────────────
    if rzp_payment_id:
        db.create_compliance_token(f"rzp_compliance_{rzp_payment_id}", email)
    elif compliance_token:
        db.mark_compliance_token_used(compliance_token)

    return jsonify({
        "success": True,
        "message": f"Compliance report emailed to {email}.",
        "domain":  domain,
        "passed":  passed_total,
        "failed":  failed_total,
    })


@app.post("/api/scan")
def api_scan():
    # Short-term rate limit: 5 requests/min per IP (applies to unauthenticated callers).
    # Whitelisted IPs and owner keys bypass it entirely.
    if not request.headers.get("X-API-Key", "").strip() and not _is_whitelisted() and not _is_owner_key() and _is_rate_limited():
        return jsonify({"error": "Too many requests. Please wait a minute and try again."}), 429

    body = request.get_json(silent=True)
    if not body or "url" not in body:
        return jsonify({"error": "Request body must be JSON with a 'url' field."}), 400

    url = _normalise_url(str(body["url"]))
    err = _validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    one_time_token = str(body.get("one_time_token", "")).strip()
    token_record   = None
    if one_time_token:
        token_record = db.get_one_time_token(one_time_token)
        if not token_record:
            return jsonify({"error": "Invalid or expired one-time scan token."}), 403

    if not token_record and not _is_whitelisted():
        quota_key = _quota_key()
        allowed, _ = db.check_quota(quota_key)
        if not allowed:
            return jsonify({"error": "Monthly scan limit reached. Resets on the 1st."}), 429

    try:
        scan = _run_scan_modules(url)
    except req_lib.RequestException as exc:
        return jsonify({"error": str(exc)}), 502

    response       = scan["response"]
    headers_result = scan["headers_result"]
    tls_result     = scan["tls_result"]
    dns_result     = scan["dns_result"]

    if token_record:
        result = {
            "url":                url,
            "final_url":          response.url,
            "status_code":        response.status_code,
            "grade":              scan["grade"],
            "score":              scan["score"],
            "pro_locked":         False,
            "summary":            scan["summary"],
            "headers":            headers_result["headers"],
            "tls":                tls_result,
            "dns":                dns_result,
            "cookies":            scan["cookies_result"],
            "cross_origin":       scan["cross_origin_result"],
            "security_txt":       headers_result.get("security_txt"),
            "cors":               headers_result.get("cors"),
            "server_fingerprint": headers_result.get("server_fingerprint"),
            "page_analysis":      scan["page_result"],
        }
        db.mark_one_time_token_used(one_time_token)
        return jsonify(result), 200

    issue_counts = {"critical": 0, "important": 0, "minor": 0}
    for info in (headers_result["headers"] or {}).values():
        if info["status"] in ("missing", "weak", "warn"):
            sev = info.get("severity", "minor")
            issue_counts[sev] = issue_counts.get(sev, 0) + 1
    if (tls_result or {}).get("total_deduction", 0) > 0:
        issue_counts["important"] += 1
    if dns_result.get("total_deduction", 0) > 0:
        issue_counts["important"] += 1
    issue_counts["total"] = sum(issue_counts.values())

    # full=1 only takes effect when the caller supplies a valid API key —
    # prevents unauthenticated callers from bypassing the fix-value Pro gate.
    full_mode = (
        request.args.get("full") == "1"
        and bool(_verified_api_key())
    )

    if full_mode:
        out_headers = headers_result["headers"]
        out_dns     = dns_result
    else:
        import copy
        out_headers = {
            name: {k: v for k, v in info.items() if k != "fix"}
            for name, info in (headers_result["headers"] or {}).items()
        }
        out_dns = copy.deepcopy(dns_result)
        for _key in ("spf", "dmarc", "dkim", "caa", "dnssec"):
            rec = (out_dns or {}).get(_key)
            if isinstance(rec, dict):
                rec.pop("fix", None)

    result = {
        "url":                url,
        "final_url":          response.url,
        "status_code":        response.status_code,
        "grade":              scan["grade"],
        "score":              scan["score"],
        "pro_locked":         True,
        "issue_counts":       issue_counts,
        "summary":            scan["summary"],
        "headers":            out_headers,
        "tls":                tls_result,
        "dns":                out_dns,
        "security_txt":       headers_result.get("security_txt"),
        "cors":               headers_result.get("cors"),
        "server_fingerprint": headers_result.get("server_fingerprint"),
        "page_analysis":      scan["page_result"],
    }

    domain = urlparse(url).hostname or ""
    if domain.startswith("www."):
        domain = domain[4:]
    if domain:
        _update_hof_background(domain)

    if not _is_whitelisted():
        remaining_after = db.increment_usage(quota_key)
    else:
        remaining_after = 9999
    resp = jsonify(result)
    resp.headers["X-Scans-Remaining"] = str(remaining_after)
    return resp, 200


@app.post("/api/scan/pro")
def api_scan_pro():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return jsonify({"error": "X-API-Key header is required for Pro scans."}), 401

    key_record = _resolve_key(api_key)
    if not key_record or key_record["status"] not in ("active", "cancel_pending"):
        return jsonify({"error": "Invalid or inactive API key."}), 403

    scan_limit = _scan_limit_for(key_record, api_key)
    if not _is_whitelisted():
        allowed, _ = db.check_quota(api_key, limit=scan_limit)
        if not allowed:
            return jsonify({"error": "Monthly scan limit reached. Resets on the 1st."}), 429

    body = request.get_json(silent=True)
    if not body or "url" not in body:
        return jsonify({"error": "Request body must be JSON with a 'url' field."}), 400

    url = _normalise_url(str(body["url"]))
    err = _validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    try:
        scan = _run_scan_modules(url)
    except req_lib.RequestException as exc:
        return jsonify({"error": str(exc)}), 502

    response = scan["response"]

    result = {
        "url":                url,
        "final_url":          response.url,
        "status_code":        response.status_code,
        "grade":              scan["grade"],
        "score":              scan["score"],
        "pro_locked":         False,
        "headers":            scan["headers_result"]["headers"],
        "tls":                scan["tls_result"],
        "dns":                scan["dns_result"],
        "cookies":            scan["cookies_result"],
        "cross_origin":       scan["cross_origin_result"],
        "security_txt":       scan["headers_result"].get("security_txt"),
        "cors":               scan["headers_result"].get("cors"),
        "server_fingerprint": scan["headers_result"].get("server_fingerprint"),
        "page_analysis":      scan["page_result"],
        "summary":            scan["summary"],
    }

    domain = urlparse(url).hostname or ""
    if domain.startswith("www."):
        domain = domain[4:]
    if domain:
        _update_hof_background(domain)

    if not _is_whitelisted():
        remaining_after = db.increment_usage(api_key, limit=scan_limit)
    else:
        remaining_after = 9999
    resp = jsonify(result)
    resp.headers["X-Scans-Remaining"] = str(remaining_after)
    return resp, 200


@app.post("/api/report/pdf")
def api_report_pdf():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return jsonify({"error": "X-API-Key header is required for PDF export."}), 401

    key_record = _resolve_key(api_key)
    if not key_record or key_record["status"] not in ("active", "cancel_pending"):
        return jsonify({"error": "Invalid or inactive API key."}), 403

    scan_limit = _scan_limit_for(key_record, api_key)
    if not _is_whitelisted():
        allowed, _ = db.check_quota(api_key, limit=scan_limit)
        if not allowed:
            return jsonify({"error": "Monthly scan limit reached. Resets on the 1st."}), 429

    body = request.get_json(silent=True)
    if not body or "url" not in body:
        return jsonify({"error": "Request body must be JSON with a 'url' field."}), 400

    url = _normalise_url(str(body["url"]))
    err = _validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    buyer_name = str(body.get("name", "")).strip()[:80]

    hostname = urlparse(url).hostname or ""
    is_https = url.startswith("https://")

    futures = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures["http"] = pool.submit(fetch_url, url)
        futures["dns"]  = pool.submit(scan_dns, hostname)
        if is_https:
            futures["tls"] = pool.submit(scan_tls, hostname)

        results = {}
        errors  = {}
        for key, fut in futures.items():
            try:
                results[key] = fut.result()
            except (req_lib.RequestException, ValueError) as exc:
                errors[key] = str(exc)

    if "http" in errors:
        return jsonify({"error": errors["http"]}), 502

    response            = results["http"]
    headers_result      = analyze_headers(response)
    cookies_result      = scan_cookies(response)
    cross_origin_result = scan_cross_origin(response)
    page_result         = scan_page(response)
    dns_result          = results.get("dns", {"spf": None, "dmarc": None, "dkim": None, "caa": None, "dnssec": None, "total_deduction": 0, "summary": ""})
    tls_result          = results.get("tls") if is_https else {
        "supported": False,
        "error": "Site uses HTTP — no TLS.",
        "certificate": None,
        "connection": None,
        "deductions": [{"reason": "Site does not use HTTPS", "points": 20}],
        "total_deduction": 20,
        "summary": "Site does not use HTTPS.",
    }

    total_deduction = (
        headers_result["total_deduction"]
        + (tls_result["total_deduction"] if tls_result else 0)
        + dns_result["total_deduction"]
        + cookies_result["total_deduction"]
        + cross_origin_result["total_deduction"]
        + page_result["total_deduction"]
    )
    score = max(0, 100 - total_deduction)
    grade = _score_to_grade(score)

    scan_result = {
        "url":               url,
        "final_url":         response.url,
        "status_code":       response.status_code,
        "grade":             grade,
        "score":             score,
        "headers":           headers_result["headers"],
        "tls":               tls_result,
        "dns":               dns_result,
        "cookies":           cookies_result,
        "cross_origin":      cross_origin_result,
        "page_analysis":     page_result,
        "cors":              headers_result.get("cors"),
        "server_fingerprint": headers_result.get("server_fingerprint"),
        "cdn":               _detect_cdn(dict(response.headers)),
        "redirect_chain":    [r.url for r in response.history] + [response.url],
        "ip":                _resolve_ip(hostname),
        "summary":           "",
    }

    try:
        pdf_bytes = generate_pdf(scan_result, buyer_name)
    except Exception as exc:
        return jsonify({"error": f"PDF generation failed: {exc}"}), 500

    remaining_after = db.increment_usage(api_key, limit=scan_limit) if not _is_whitelisted() else 9999

    safe_host = (urlparse(url).hostname or "report").replace(".", "_")
    filename  = f"securescanr_{safe_host}.pdf"

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Scans-Remaining":   str(remaining_after),
        },
    )


@app.post("/api/admin/seed-test-key")
def api_admin_seed_test_key():
    secret = request.headers.get("X-Admin-Secret", "")
    if not _ADMIN_SECRET or secret != _ADMIN_SECRET:
        return jsonify({"error": "Forbidden."}), 403

    test_key   = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    with db._connect() as con:
        con.execute(
            "INSERT OR REPLACE INTO api_keys (email, api_key, plan, created_at, status) "
            "VALUES (?, ?, ?, ?, ?)",
            ("admin@securescanr.com", test_key, "pro", created_at, "active"),
        )

    return jsonify({"status": "done", "api_key": test_key})


@app.post("/api/admin/fix-agency-account")
def api_admin_fix_agency_account():
    """One-shot repair: converts a wrongly-issued Pro key to an Agency account."""
    secret = request.headers.get("X-Admin-Secret", "")
    if not _ADMIN_SECRET or secret != _ADMIN_SECRET:
        return jsonify({"error": "Forbidden."}), 403

    body       = request.get_json(silent=True) or {}
    rzp_sub_id = str(body.get("razorpay_subscription_id", "")).strip()
    if not rzp_sub_id:
        return jsonify({"error": "razorpay_subscription_id required."}), 400
    if not _RZP_KEY_ID or not _RZP_KEY_SECRET:
        return jsonify({"error": "Razorpay not configured."}), 503

    rzp_client = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_KEY_SECRET))

    try:
        sub = rzp_client.subscription.fetch(rzp_sub_id)
    except Exception as exc:
        return jsonify({"error": f"Could not fetch subscription: {exc}"}), 502

    if sub.get("plan_id") != _RZP_AGENCY_PLAN_ID:
        return jsonify({"error": f"Not an agency subscription (plan_id: {sub.get('plan_id')})."}), 400

    # Resolve email: explicit body override OR first payment on the subscription
    email = str(body.get("email", "")).strip()
    if not email:
        try:
            payments = rzp_client.payment.all({"subscription_id": rzp_sub_id, "count": 1})
            items = (payments or {}).get("items", [])
            if items:
                email = items[0].get("email", "")
        except Exception as exc:
            logging.warning("fix-agency: payment fetch failed for %s: %s", rzp_sub_id, exc)

    if not email:
        return jsonify({"error": "Could not resolve email — pass 'email' in body."}), 400

    # Already correctly registered as Agency?
    existing = db.get_agency_by_subscription_id(rzp_sub_id, None)
    if existing:
        return jsonify({
            "status":  "already_agency",
            "email":   _decrypt_email(existing["encrypted_email"]),
            "api_key": existing["api_key"],
        }), 200

    # Delete the incorrectly created Pro key for this email
    pro_key_deleted = False
    with db._connect() as con:
        row = con.execute("SELECT api_key FROM api_keys WHERE email=?", (email,)).fetchone()
        if row:
            con.execute("DELETE FROM api_keys WHERE email=?", (email,))
            pro_key_deleted = True

    # Create the correct Agency record and send welcome email
    agency_id  = uuid.uuid4().hex
    agency_key = "wa_agency_" + uuid.uuid4().hex
    db.create_agency_subscription(
        agency_id, rzp_sub_id, None,
        _encrypt_email(email), agency_key, [],
        "weekly", 1,
    )
    _send_agency_welcome_email(email, agency_key, [], "weekly", 1)
    logging.info("fix-agency: repaired account for %s sub=%s pro_deleted=%s", email, rzp_sub_id, pro_key_deleted)

    return jsonify({
        "status":          "fixed",
        "email":           email,
        "pro_key_deleted": pro_key_deleted,
        "agency_api_key":  agency_key,
        "dashboard_url":   f"https://securescanr.com/agency-dashboard.html?api_key={agency_key}",
    }), 201


@app.post("/api/admin/clear-hof-cache")
def api_admin_clear_hof_cache():
    secret = request.headers.get("X-Admin-Secret", "")
    if not _ADMIN_SECRET or secret != _ADMIN_SECRET:
        return jsonify({"error": "Forbidden."}), 403

    global _hof_scanning
    db.clear_halloffame()
    logging.info("HOF: cache cleared via admin endpoint")
    if not _hof_scanning:
        _hof_scanning = True
        threading.Thread(target=_run_hof_scan, daemon=True).start()
        logging.info("HOF: background rescan triggered via admin endpoint")

    return jsonify({"status": "cache cleared", "scanning": True})


@app.get("/api/world-index")
def api_world_index():
    sites = db.get_world_index()
    updated = max((s["last_scanned"] for s in sites), default="") if sites else ""
    return jsonify({
        "updated":    updated,
        "sites":      sites,
        "refreshing": _world_index_refreshing,
    })


@app.post("/api/admin/refresh-world-index")
def api_admin_refresh_world_index():
    secret = request.headers.get("X-Admin-Secret", "")
    if not _ADMIN_SECRET or not hmac.compare_digest(secret, _ADMIN_SECRET):
        return jsonify({"error": "Forbidden."}), 403

    global _world_index_refreshing
    if _world_index_refreshing:
        return jsonify({"message": "Refresh already in progress."}), 409
    _world_index_refreshing = True
    threading.Thread(target=_run_world_index_refresh, daemon=True).start()
    logging.info("World Index: refresh triggered via admin endpoint")
    return jsonify({"message": "World Index refresh started.", "domains": len(_WORLD_INDEX_SEED)})


@app.get("/api/admin/stats")
def api_admin_stats():
    _ADMIN_KEY = "securescanr_admin_2026"
    provided = request.headers.get("X-Admin-Key", "")
    if not hmac.compare_digest(provided, _ADMIN_KEY):
        return jsonify({"error": "Forbidden."}), 403
    return jsonify(db.get_admin_stats(whitelisted_ips=_WHITELISTED_IPS))


@app.post("/api/tools/validate-csp")
def api_validate_csp():
    body = request.get_json(silent=True)
    if not body or "csp" not in body:
        return jsonify({"error": "Request body must be JSON with a 'csp' field."}), 400

    csp_value = str(body["csp"]).strip()
    if not csp_value:
        return jsonify({"error": "CSP value cannot be empty."}), 400

    directives: dict = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

    issues = []

    script_sources = directives.get("script-src") or directives.get("default-src", [])

    if "'unsafe-inline'" in script_sources:
        issues.append({
            "directive": "script-src",
            "issue": "'unsafe-inline' allows inline scripts to execute, completely bypassing XSS protection",
            "severity": "critical",
            "fix": "Remove 'unsafe-inline'. Use nonces ('nonce-xxx') or hashes ('sha256-xxx') for inline scripts.",
        })

    if "'unsafe-eval'" in script_sources:
        issues.append({
            "directive": "script-src",
            "issue": "'unsafe-eval' permits eval() and similar dynamic code execution functions",
            "severity": "critical",
            "fix": "Remove 'unsafe-eval'. Refactor code to avoid eval(), setTimeout(string), and new Function().",
        })

    if "*" in script_sources:
        issues.append({
            "directive": "script-src",
            "issue": "Wildcard (*) allows scripts from any origin — provides no XSS protection",
            "severity": "critical",
            "fix": "Replace * with explicit trusted domains (e.g. cdn.example.com) or 'self'.",
        })

    if "data:" in script_sources:
        issues.append({
            "directive": "script-src",
            "issue": "data: URIs in script-src can be exploited to inject and execute arbitrary scripts",
            "severity": "warning",
            "fix": "Remove 'data:' from script-src. This URI scheme is rarely needed for scripts and creates an injection vector.",
        })

    for directive, sources in directives.items():
        if "http:" in sources:
            issues.append({
                "directive": directive,
                "issue": "http: source allows loading resources over unencrypted HTTP, enabling content injection",
                "severity": "warning",
                "fix": f"Replace 'http:' with 'https:' in {directive} to enforce encrypted connections.",
            })

    if "default-src" not in directives:
        issues.append({
            "directive": "default-src",
            "issue": "No default-src fallback — fetch directives not explicitly listed have no restriction",
            "severity": "warning",
            "fix": "Add default-src 'self'; as a safe baseline fallback for all unspecified fetch directives.",
        })

    if "object-src" not in directives:
        default_sources = directives.get("default-src", [])
        if "'none'" not in default_sources:
            issues.append({
                "directive": "object-src",
                "issue": "Missing object-src — <object>, <embed>, and <applet> tags can load plugins including Flash",
                "severity": "warning",
                "fix": "Add object-src 'none'; to block all plugin content.",
            })

    if "base-uri" not in directives:
        issues.append({
            "directive": "base-uri",
            "issue": "Missing base-uri — an injected <base> tag can redirect all relative URLs to an attacker-controlled domain",
            "severity": "info",
            "fix": "Add base-uri 'self'; to restrict <base> tag URLs to the same origin.",
        })

    has_critical = any(i["severity"] == "critical" for i in issues)
    has_warning  = any(i["severity"] == "warning"  for i in issues)
    quality = "dangerous" if has_critical else ("weak" if has_warning else "good")

    return jsonify({
        "quality":         quality,
        "issues":          issues,
        "directive_count": len(directives),
    })


def _generate_share_id(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


@app.post("/api/share")
def api_share():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return jsonify({"error": "X-API-Key header is required."}), 401

    key_record = _resolve_key(api_key)
    if not key_record or key_record["status"] not in ("active", "cancel_pending"):
        return jsonify({"error": "Invalid or inactive API key."}), 403

    scan_limit = _scan_limit_for(key_record, api_key)
    if not _is_whitelisted():
        allowed, _ = db.check_quota(api_key, limit=scan_limit)
        if not allowed:
            return jsonify({"error": "Monthly scan limit reached. Resets on the 1st."}), 429

    body = request.get_json(silent=True)
    if not body or "url" not in body:
        return jsonify({"error": "Request body must be JSON with a 'url' field."}), 400

    url = _normalise_url(str(body["url"]))
    err = _validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    try:
        scan = _run_scan_modules(url)
    except req_lib.RequestException as exc:
        return jsonify({"error": str(exc)}), 502

    response = scan["response"]
    result = {
        "url":                url,
        "final_url":          response.url,
        "status_code":        response.status_code,
        "grade":              scan["grade"],
        "score":              scan["score"],
        "pro_locked":         False,
        "headers":            scan["headers_result"]["headers"],
        "tls":                scan["tls_result"],
        "dns":                scan["dns_result"],
        "cookies":            scan["cookies_result"],
        "cross_origin":       scan["cross_origin_result"],
        "security_txt":       scan["headers_result"].get("security_txt"),
        "cors":               scan["headers_result"].get("cors"),
        "server_fingerprint": scan["headers_result"].get("server_fingerprint"),
        "page_analysis":      scan["page_result"],
        "summary":            scan["summary"],
    }

    try:
        result_json = json.dumps(result)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"Could not serialise result: {exc}"}), 500

    share_id   = _generate_share_id()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    db.save_shared_report(share_id, url, result_json)
    if not _is_whitelisted():
        db.increment_usage(api_key, limit=scan_limit)

    return jsonify({
        "share_id":   share_id,
        "share_url":  f"https://securescanr.com/report.html?id={share_id}",
        "expires_at": expires_at,
    })


@app.get("/api/share/<share_id>")
def api_get_share(share_id: str):
    db.cleanup_expired_reports()
    record = db.get_shared_report(share_id)
    if not record:
        return jsonify({"error": "Report not found or has expired."}), 404

    try:
        result = json.loads(record["result"])
    except (json.JSONDecodeError, ValueError):
        return jsonify({"error": "Stored report could not be parsed."}), 500

    result["share_id"]   = share_id
    result["expires_at"] = record["expires_at"]
    result["created_at"] = record["created_at"]
    return jsonify(result)


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
