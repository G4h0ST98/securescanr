"""
Persistence layer — SQLite-backed.
- scan_usage            : monthly quota tracking per key/IP
- api_keys              : paid subscriber keys issued after successful payment
- one_time_scans        : single-use scan tokens issued after ₹99 payment
- agency_subscriptions  : agency tier subscription records
- agency_scan_history   : per-domain scan results for agency accounts
"""

import json
import os
import uuid
import sqlite3
from datetime import datetime, timezone, timedelta

_DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(__file__), "usage.db"),
)
MONTHLY_LIMIT = 50
AGENCY_MONTHLY_LIMIT = 500


def init_db() -> None:
    with _connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scan_usage (
                api_key    TEXT NOT NULL,
                month      TEXT NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (api_key, month)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key                      TEXT PRIMARY KEY,
                email                        TEXT NOT NULL DEFAULT '',
                plan                         TEXT NOT NULL DEFAULT 'pro',
                created_at                   TEXT NOT NULL,
                status                       TEXT NOT NULL DEFAULT 'active',
                razorpay_subscription_id     TEXT NOT NULL DEFAULT '',
                lemonsqueezy_subscription_id TEXT NOT NULL DEFAULT ''
            )
        """)
        # Migrations: add columns for existing databases that predate these fields
        try:
            con.execute("ALTER TABLE api_keys ADD COLUMN razorpay_subscription_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        try:
            con.execute("ALTER TABLE api_keys ADD COLUMN lemonsqueezy_subscription_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        con.execute("""
            CREATE TABLE IF NOT EXISTS halloffame_cache (
                domain       TEXT PRIMARY KEY,
                grade        TEXT NOT NULL,
                score        INTEGER NOT NULL,
                last_scanned TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS shared_reports (
                id         TEXT PRIMARY KEY,
                url        TEXT NOT NULL,
                result     TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS one_time_scans (
                token      TEXT PRIMARY KEY,
                payment_id TEXT NOT NULL UNIQUE,
                used       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS compliance_tokens (
                token      TEXT PRIMARY KEY,
                payment_id TEXT NOT NULL UNIQUE,
                email      TEXT NOT NULL DEFAULT '',
                used       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS agency_subscriptions (
                id                           TEXT PRIMARY KEY,
                razorpay_subscription_id     TEXT UNIQUE,
                lemonsqueezy_subscription_id TEXT UNIQUE,
                encrypted_email              TEXT NOT NULL,
                api_key                      TEXT NOT NULL UNIQUE,
                domains                      TEXT NOT NULL DEFAULT '[]',
                schedule_type                TEXT NOT NULL DEFAULT 'weekly',
                schedule_day                 INTEGER NOT NULL DEFAULT 1,
                scan_count_month             INTEGER NOT NULL DEFAULT 0,
                scan_month                   TEXT NOT NULL DEFAULT '',
                created_at                   TEXT NOT NULL,
                active                       INTEGER NOT NULL DEFAULT 1,
                domain_pdf_prefs             TEXT NOT NULL DEFAULT '{}'
            )
        """)
        # Migration: add domain_pdf_prefs for existing databases
        try:
            con.execute("ALTER TABLE agency_subscriptions ADD COLUMN domain_pdf_prefs TEXT NOT NULL DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass
        con.execute("""
            CREATE TABLE IF NOT EXISTS agency_scan_history (
                id         TEXT PRIMARY KEY,
                agency_id  TEXT NOT NULL,
                domain     TEXT NOT NULL,
                score      INTEGER NOT NULL,
                grade      TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                pdf_path   TEXT NOT NULL DEFAULT ''
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS world_index_cache (
                domain        TEXT PRIMARY KEY,
                rank          INTEGER NOT NULL DEFAULT 0,
                score         INTEGER NOT NULL DEFAULT 0,
                grade         TEXT NOT NULL DEFAULT '',
                headers_score INTEGER NOT NULL DEFAULT 0,
                tls_score     INTEGER NOT NULL DEFAULT 0,
                dns_score     INTEGER NOT NULL DEFAULT 0,
                country       TEXT NOT NULL DEFAULT '',
                last_scanned  TEXT NOT NULL DEFAULT ''
            )
        """)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, timeout=10, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    return con


def _month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


# ── Quota ─────────────────────────────────────────────────────────────────────

def check_quota(key: str, limit: int = MONTHLY_LIMIT) -> tuple[bool, int]:
    """Return (allowed, remaining). Read-only — does not modify usage."""
    month = _month()
    with _connect() as con:
        row = con.execute(
            "SELECT scan_count FROM scan_usage WHERE api_key=? AND month=?",
            (key, month),
        ).fetchone()
    count = row[0] if row else 0
    return count < limit, max(0, limit - count)


def increment_usage(key: str, limit: int = MONTHLY_LIMIT) -> int:
    """Upsert scan_count for key+month. Returns remaining scans after increment."""
    month = _month()
    with _connect() as con:
        con.execute(
            """
            INSERT INTO scan_usage (api_key, month, scan_count) VALUES (?, ?, 1)
            ON CONFLICT(api_key, month) DO UPDATE SET scan_count = scan_count + 1
            """,
            (key, month),
        )
        row = con.execute(
            "SELECT scan_count FROM scan_usage WHERE api_key=? AND month=?",
            (key, month),
        ).fetchone()
    count = row[0] if row else 1
    return max(0, limit - count)


# ── API keys ──────────────────────────────────────────────────────────────────

def store_api_key(
    api_key: str,
    email: str,
    plan: str,
    razorpay_sub_id: str = '',
    ls_sub_id: str = '',
) -> None:
    """Insert a new active API key. Silently ignores duplicate keys."""
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        con.execute(
            """
            INSERT OR IGNORE INTO api_keys
              (api_key, email, plan, created_at, status,
               razorpay_subscription_id, lemonsqueezy_subscription_id)
            VALUES (?, ?, ?, ?, 'active', ?, ?)
            """,
            (api_key, email, plan, created_at, razorpay_sub_id, ls_sub_id),
        )


def get_api_key(api_key: str) -> dict | None:
    """Return the key record as a dict, or None if not found."""
    with _connect() as con:
        row = con.execute(
            """
            SELECT api_key, email, plan, created_at, status,
                   razorpay_subscription_id, lemonsqueezy_subscription_id
            FROM api_keys WHERE api_key=?
            """,
            (api_key,),
        ).fetchone()
    if not row:
        return None
    return {
        "api_key":                      row[0],
        "email":                        row[1],
        "plan":                         row[2],
        "created_at":                   row[3],
        "status":                       row[4],
        "razorpay_subscription_id":     row[5],
        "lemonsqueezy_subscription_id": row[6],
    }


def update_subscription_status(api_key: str, status: str) -> None:
    """Update the status field for an api_key record."""
    with _connect() as con:
        con.execute("UPDATE api_keys SET status=? WHERE api_key=?", (status, api_key))


def get_api_key_by_rzp_sub_id(sub_id: str) -> dict | None:
    """Return the api_keys record whose razorpay_subscription_id matches, or None."""
    if not sub_id:
        return None
    with _connect() as con:
        row = con.execute(
            """
            SELECT api_key, email, plan, created_at, status,
                   razorpay_subscription_id, lemonsqueezy_subscription_id
            FROM api_keys
            WHERE razorpay_subscription_id=? AND razorpay_subscription_id != ''
            """,
            (sub_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "api_key":                      row[0],
        "email":                        row[1],
        "plan":                         row[2],
        "created_at":                   row[3],
        "status":                       row[4],
        "razorpay_subscription_id":     row[5],
        "lemonsqueezy_subscription_id": row[6],
    }


def get_api_key_by_ls_sub_id(sub_id: str) -> dict | None:
    """Return the api_keys record whose lemonsqueezy_subscription_id matches, or None."""
    if not sub_id:
        return None
    with _connect() as con:
        row = con.execute(
            """
            SELECT api_key, email, plan, created_at, status,
                   razorpay_subscription_id, lemonsqueezy_subscription_id
            FROM api_keys
            WHERE lemonsqueezy_subscription_id=? AND lemonsqueezy_subscription_id != ''
            """,
            (sub_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "api_key":                      row[0],
        "email":                        row[1],
        "plan":                         row[2],
        "created_at":                   row[3],
        "status":                       row[4],
        "razorpay_subscription_id":     row[5],
        "lemonsqueezy_subscription_id": row[6],
    }


def downgrade_subscription(api_key: str) -> None:
    """Downgrade a Pro key to free tier on cancellation/payment failure.
    Sets plan='free', status='cancelled', and clears both subscription IDs."""
    with _connect() as con:
        con.execute(
            """
            UPDATE api_keys
            SET plan='free', status='cancelled',
                razorpay_subscription_id='', lemonsqueezy_subscription_id=''
            WHERE api_key=?
            """,
            (api_key,),
        )


def update_ls_sub_id(email: str, ls_sub_id: str) -> None:
    """Link a LemonSqueezy subscription ID to the most recent api_keys row for this
    email that does not yet have a subscription ID set.
    Called from the LS subscription_created webhook event."""
    if not email or not ls_sub_id:
        return
    with _connect() as con:
        con.execute(
            """
            UPDATE api_keys
            SET lemonsqueezy_subscription_id=?
            WHERE email=? AND lemonsqueezy_subscription_id=''
            """,
            (ls_sub_id, email),
        )


def deactivate_agency(agency_id: str) -> None:
    """Mark an agency subscription as inactive and clear its payment sub IDs.
    Called when a Razorpay or LemonSqueezy subscription is cancelled/halted/expired."""
    with _connect() as con:
        con.execute(
            """
            UPDATE agency_subscriptions
            SET active=0,
                razorpay_subscription_id=NULL,
                lemonsqueezy_subscription_id=NULL
            WHERE id=?
            """,
            (agency_id,),
        )


# ── Hall of Fame ──────────────────────────────────────────────────────────────

def get_halloffame() -> list[dict]:
    """Return all cached Hall of Fame results ordered by score descending."""
    with _connect() as con:
        rows = con.execute(
            "SELECT domain, grade, score, last_scanned FROM halloffame_cache ORDER BY score DESC"
        ).fetchall()
    return [{"domain": r[0], "grade": r[1], "score": r[2], "last_scanned": r[3]} for r in rows]


def upsert_halloffame(domain: str, grade: str, score: int) -> None:
    """Insert or update a Hall of Fame cache entry."""
    last_scanned = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with _connect() as con:
        con.execute(
            """
            INSERT INTO halloffame_cache (domain, grade, score, last_scanned)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                grade=excluded.grade,
                score=excluded.score,
                last_scanned=excluded.last_scanned
            """,
            (domain, grade, score, last_scanned),
        )


def get_domain_grade(domain: str) -> dict | None:
    """Return {grade, score} for a domain from halloffame_cache, or None if not cached."""
    with _connect() as con:
        row = con.execute(
            "SELECT grade, score FROM halloffame_cache WHERE domain=?",
            (domain,),
        ).fetchone()
    if not row:
        return None
    return {"grade": row[0], "score": row[1]}


def clear_halloffame() -> None:
    """Delete all Hall of Fame cache rows."""
    with _connect() as con:
        con.execute("DELETE FROM halloffame_cache")


def halloffame_needs_refresh(n_expected: int = 1) -> bool:
    """Return True if cache has fewer than n_expected entries or oldest entry is > 7 days."""
    with _connect() as con:
        row = con.execute(
            "SELECT COUNT(*), MIN(last_scanned) FROM halloffame_cache"
        ).fetchone()
    count, oldest = row
    if count < n_expected:
        return True
    if not oldest:
        return True
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    return oldest < cutoff


# ── Shared reports ────────────────────────────────────────────────────────────

def save_shared_report(share_id: str, url: str, result_json: str) -> None:
    """Store a serialised scan result that expires after 7 days."""
    now        = datetime.now(timezone.utc)
    created_at = now.isoformat()
    expires_at = (now + timedelta(days=7)).isoformat()
    with _connect() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO shared_reports (id, url, result, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (share_id, url, result_json, created_at, expires_at),
        )


def get_shared_report(share_id: str) -> dict | None:
    """Return the report record, or None if not found or expired."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        row = con.execute(
            """
            SELECT id, url, result, created_at, expires_at
            FROM shared_reports
            WHERE id=? AND expires_at > ?
            """,
            (share_id, now),
        ).fetchone()
    if not row:
        return None
    return {
        "id":         row[0],
        "url":        row[1],
        "result":     row[2],
        "created_at": row[3],
        "expires_at": row[4],
    }


def cleanup_expired_reports() -> None:
    """Delete all reports whose expiry has passed."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        con.execute("DELETE FROM shared_reports WHERE expires_at <= ?", (now,))


# ── One-time scan tokens ──────────────────────────────────────────────────────

def payment_id_already_used(payment_id: str) -> bool:
    """Return True if a token for this payment_id already exists."""
    with _connect() as con:
        row = con.execute(
            "SELECT 1 FROM one_time_scans WHERE payment_id=?",
            (payment_id,),
        ).fetchone()
    return bool(row)


def create_one_time_token(payment_id: str) -> str:
    """Create a one-time scan token for a verified payment. Expires in 24 hours."""
    token      = uuid.uuid4().hex
    now        = datetime.now(timezone.utc)
    created_at = now.isoformat()
    expires_at = (now + timedelta(hours=24)).isoformat()
    with _connect() as con:
        con.execute(
            """
            INSERT INTO one_time_scans (token, payment_id, used, created_at, expires_at)
            VALUES (?, ?, 0, ?, ?)
            """,
            (token, payment_id, created_at, expires_at),
        )
    return token


def get_one_time_token(token: str) -> dict | None:
    """Return the token record if valid, unused, and not expired. Else None."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        row = con.execute(
            """
            SELECT token, payment_id, used, created_at, expires_at
            FROM one_time_scans
            WHERE token=? AND used=0 AND expires_at > ?
            """,
            (token, now),
        ).fetchone()
    if not row:
        return None
    return {
        "token":      row[0],
        "payment_id": row[1],
        "used":       row[2],
        "created_at": row[3],
        "expires_at": row[4],
    }


def mark_one_time_token_used(token: str) -> None:
    """Mark a one-time token as consumed."""
    with _connect() as con:
        con.execute("UPDATE one_time_scans SET used=1 WHERE token=?", (token,))


def claim_one_time_token(token: str) -> dict | None:
    """Atomically claim a valid, unused, unexpired token (single conditional UPDATE).
    Returns the record if THIS caller won the claim, else None. Prevents two
    concurrent requests from both redeeming the same token."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        cur = con.execute(
            "UPDATE one_time_scans SET used=1 WHERE token=? AND used=0 AND expires_at > ?",
            (token, now),
        )
        if cur.rowcount != 1:
            return None
        row = con.execute(
            "SELECT token, payment_id, used, created_at, expires_at FROM one_time_scans WHERE token=?",
            (token,),
        ).fetchone()
    if not row:
        return None
    return {
        "token":      row[0],
        "payment_id": row[1],
        "used":       row[2],
        "created_at": row[3],
        "expires_at": row[4],
    }


def release_one_time_token(token: str) -> None:
    """Un-claim a token (used=1 → 0) so the buyer can retry after a transient
    failure that prevented delivery of the scan result."""
    with _connect() as con:
        con.execute("UPDATE one_time_scans SET used=0 WHERE token=?", (token,))


# ── Compliance report tokens ─────────────────────────────────────────────────

def compliance_payment_already_used(payment_id: str) -> bool:
    """Return True if a compliance token for this payment_id already exists."""
    with _connect() as con:
        row = con.execute(
            "SELECT 1 FROM compliance_tokens WHERE payment_id=?",
            (payment_id,),
        ).fetchone()
    return bool(row)


def create_compliance_token(payment_id: str, email: str = "") -> str:
    """Create a compliance report token for a verified payment. Expires in 48 hours."""
    token      = uuid.uuid4().hex
    now        = datetime.now(timezone.utc)
    created_at = now.isoformat()
    expires_at = (now + timedelta(hours=48)).isoformat()
    with _connect() as con:
        con.execute(
            """
            INSERT INTO compliance_tokens (token, payment_id, email, used, created_at, expires_at)
            VALUES (?, ?, ?, 0, ?, ?)
            """,
            (token, payment_id, email, created_at, expires_at),
        )
    return token


def get_compliance_token(token: str) -> dict | None:
    """Return the compliance token record if valid, unused, and not expired. Else None."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        row = con.execute(
            """
            SELECT token, payment_id, email, used, created_at, expires_at
            FROM compliance_tokens
            WHERE token=? AND used=0 AND expires_at > ?
            """,
            (token, now),
        ).fetchone()
    if not row:
        return None
    return {
        "token":      row[0],
        "payment_id": row[1],
        "email":      row[2],
        "used":       row[3],
        "created_at": row[4],
        "expires_at": row[5],
    }


def mark_compliance_token_used(token: str) -> None:
    """Mark a compliance token as consumed."""
    with _connect() as con:
        con.execute("UPDATE compliance_tokens SET used=1 WHERE token=?", (token,))


def claim_compliance_token(token: str) -> dict | None:
    """Atomically claim a valid, unused, unexpired compliance token. Returns the
    record if THIS caller won the claim, else None."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        cur = con.execute(
            "UPDATE compliance_tokens SET used=1 WHERE token=? AND used=0 AND expires_at > ?",
            (token, now),
        )
        if cur.rowcount != 1:
            return None
        row = con.execute(
            "SELECT token, payment_id, email, used, created_at, expires_at FROM compliance_tokens WHERE token=?",
            (token,),
        ).fetchone()
    if not row:
        return None
    return {
        "token":      row[0],
        "payment_id": row[1],
        "email":      row[2],
        "used":       row[3],
        "created_at": row[4],
        "expires_at": row[5],
    }


def release_compliance_token(token: str) -> None:
    """Un-claim a compliance token so the buyer can retry after a transient failure."""
    with _connect() as con:
        con.execute("UPDATE compliance_tokens SET used=0 WHERE token=?", (token,))


def reserve_compliance_payment(payment_id: str, email: str = "") -> bool:
    """Atomically reserve a Razorpay payment_id for a compliance report, relying on
    the UNIQUE(payment_id) constraint. Returns True if newly reserved (caller may
    proceed), False if this payment was already used (replay)."""
    token      = uuid.uuid4().hex
    now        = datetime.now(timezone.utc)
    created_at = now.isoformat()
    expires_at = (now + timedelta(hours=48)).isoformat()
    try:
        with _connect() as con:
            con.execute(
                """
                INSERT INTO compliance_tokens (token, payment_id, email, used, created_at, expires_at)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (token, payment_id, email, created_at, expires_at),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def release_compliance_payment(payment_id: str) -> None:
    """Remove a compliance payment reservation so the buyer can retry after a
    transient failure that prevented report delivery."""
    with _connect() as con:
        con.execute("DELETE FROM compliance_tokens WHERE payment_id=?", (payment_id,))


# ── Agency subscriptions ──────────────────────────────────────────────────────

def _agency_row_to_dict(row: tuple) -> dict:
    cols = [
        "id", "razorpay_subscription_id", "lemonsqueezy_subscription_id",
        "encrypted_email", "api_key", "domains", "schedule_type", "schedule_day",
        "scan_count_month", "scan_month", "created_at", "active", "domain_pdf_prefs",
    ]
    d = dict(zip(cols, row))
    try:
        d["domains"] = json.loads(d["domains"])
    except (json.JSONDecodeError, TypeError):
        d["domains"] = []
    try:
        prefs = json.loads(d.get("domain_pdf_prefs") or "{}")
        d["domain_pdf_prefs"] = prefs if isinstance(prefs, dict) else {}
    except (json.JSONDecodeError, TypeError):
        d["domain_pdf_prefs"] = {}
    return d


def create_agency_subscription(
    agency_id: str,
    razorpay_sub_id: str | None,
    ls_sub_id: str | None,
    encrypted_email: str,
    api_key: str,
    domains: list,
    schedule_type: str,
    schedule_day: int,
    domain_pdf_prefs: dict | None = None,
) -> None:
    created_at   = datetime.now(timezone.utc).isoformat()
    scan_month   = _month()
    domains_json = json.dumps(domains)
    prefs_json   = json.dumps(domain_pdf_prefs if isinstance(domain_pdf_prefs, dict) else {})
    with _connect() as con:
        con.execute(
            """
            INSERT INTO agency_subscriptions
              (id, razorpay_subscription_id, lemonsqueezy_subscription_id,
               encrypted_email, api_key, domains, schedule_type, schedule_day,
               scan_count_month, scan_month, created_at, active, domain_pdf_prefs)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 1, ?)
            """,
            (agency_id, razorpay_sub_id, ls_sub_id,
             encrypted_email, api_key, domains_json,
             schedule_type, schedule_day, scan_month, created_at, prefs_json),
        )


def get_agency_by_api_key(api_key: str) -> dict | None:
    with _connect() as con:
        row = con.execute(
            """
            SELECT id, razorpay_subscription_id, lemonsqueezy_subscription_id,
                   encrypted_email, api_key, domains, schedule_type, schedule_day,
                   scan_count_month, scan_month, created_at, active, domain_pdf_prefs
            FROM agency_subscriptions WHERE api_key=? AND active=1
            """,
            (api_key,),
        ).fetchone()
    if not row:
        return None
    return _agency_row_to_dict(row)


def get_agency_by_subscription_id(rzp_sub_id: str | None = None, ls_sub_id: str | None = None) -> dict | None:
    """Return agency record if a subscription ID is already registered."""
    with _connect() as con:
        if rzp_sub_id:
            row = con.execute(
                """
                SELECT id, razorpay_subscription_id, lemonsqueezy_subscription_id,
                       encrypted_email, api_key, domains, schedule_type, schedule_day,
                       scan_count_month, scan_month, created_at, active
                FROM agency_subscriptions WHERE razorpay_subscription_id=?
                """,
                (rzp_sub_id,),
            ).fetchone()
        elif ls_sub_id:
            row = con.execute(
                """
                SELECT id, razorpay_subscription_id, lemonsqueezy_subscription_id,
                       encrypted_email, api_key, domains, schedule_type, schedule_day,
                       scan_count_month, scan_month, created_at, active
                FROM agency_subscriptions WHERE lemonsqueezy_subscription_id=?
                """,
                (ls_sub_id,),
            ).fetchone()
        else:
            return None
    if not row:
        return None
    return _agency_row_to_dict(row)


def get_all_active_agencies() -> list[dict]:
    with _connect() as con:
        rows = con.execute(
            """
            SELECT id, razorpay_subscription_id, lemonsqueezy_subscription_id,
                   encrypted_email, api_key, domains, schedule_type, schedule_day,
                   scan_count_month, scan_month, created_at, active, domain_pdf_prefs
            FROM agency_subscriptions WHERE active=1
            """
        ).fetchall()
    return [_agency_row_to_dict(r) for r in rows]


def update_agency_settings(
    agency_id: str,
    domains: list,
    schedule_type: str,
    schedule_day: int,
    domain_pdf_prefs: dict | None = None,
) -> None:
    prefs_json = json.dumps(domain_pdf_prefs if isinstance(domain_pdf_prefs, dict) else {})
    with _connect() as con:
        con.execute(
            """
            UPDATE agency_subscriptions
            SET domains=?, schedule_type=?, schedule_day=?, domain_pdf_prefs=?
            WHERE id=?
            """,
            (json.dumps(domains), schedule_type, schedule_day, prefs_json, agency_id),
        )


def update_agency_scan_count(agency_id: str) -> int:
    """Increment monthly scan counter, resetting if the month has changed. Returns new count."""
    current_month = _month()
    with _connect() as con:
        row = con.execute(
            "SELECT scan_count_month, scan_month FROM agency_subscriptions WHERE id=?",
            (agency_id,),
        ).fetchone()
        if not row:
            return 0
        count, stored_month = row
        if stored_month != current_month:
            count = 0
        new_count = count + 1
        con.execute(
            "UPDATE agency_subscriptions SET scan_count_month=?, scan_month=? WHERE id=?",
            (new_count, current_month, agency_id),
        )
    return new_count


def get_agency_scan_count(agency_id: str) -> int:
    """Return current month's scan count for an agency, resetting counter if new month."""
    current_month = _month()
    with _connect() as con:
        row = con.execute(
            "SELECT scan_count_month, scan_month FROM agency_subscriptions WHERE id=?",
            (agency_id,),
        ).fetchone()
    if not row:
        return 0
    count, stored_month = row
    return count if stored_month == current_month else 0


def save_agency_scan(
    agency_id: str,
    domain: str,
    score: int,
    grade: str,
    pdf_path: str = "",
) -> str:
    """Insert a scan history record. Returns the new history ID."""
    history_id = uuid.uuid4().hex
    scanned_at = datetime.now(timezone.utc).isoformat()
    with _connect() as con:
        con.execute(
            """
            INSERT INTO agency_scan_history (id, agency_id, domain, score, grade, scanned_at, pdf_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (history_id, agency_id, domain, score, grade, scanned_at, pdf_path),
        )
    return history_id


def get_agency_history(agency_id: str, limit: int = 150) -> list[dict]:
    with _connect() as con:
        rows = con.execute(
            """
            SELECT id, agency_id, domain, score, grade, scanned_at, pdf_path
            FROM agency_scan_history
            WHERE agency_id=?
            ORDER BY scanned_at DESC
            LIMIT ?
            """,
            (agency_id, limit),
        ).fetchall()
    return [
        {
            "id":         r[0],
            "agency_id":  r[1],
            "domain":     r[2],
            "score":      r[3],
            "grade":      r[4],
            "scanned_at": r[5],
            "has_pdf":    bool(r[6]),
        }
        for r in rows
    ]


def get_agency_scan_by_id(history_id: str) -> dict | None:
    with _connect() as con:
        row = con.execute(
            "SELECT id, agency_id, domain, pdf_path FROM agency_scan_history WHERE id=?",
            (history_id,),
        ).fetchone()
    if not row:
        return None
    return {"id": row[0], "agency_id": row[1], "domain": row[2], "pdf_path": row[3]}


# ── World Security Index ──────────────────────────────────────────────────────

def world_index_count() -> int:
    with _connect() as con:
        row = con.execute("SELECT COUNT(*) FROM world_index_cache").fetchone()
    return row[0] if row else 0


def get_world_index() -> list[dict]:
    """Return all world index entries ordered by rank ascending."""
    with _connect() as con:
        rows = con.execute(
            """SELECT domain, rank, score, grade, headers_score, tls_score, dns_score,
                      country, last_scanned
               FROM world_index_cache ORDER BY rank ASC"""
        ).fetchall()
    return [
        {
            "domain":       r[0],
            "rank":         r[1],
            "score":        r[2],
            "grade":        r[3],
            "headers":      r[4],
            "tls":          r[5],
            "dns":          r[6],
            "country":      r[7],
            "last_scanned": r[8],
        }
        for r in rows
    ]


def upsert_world_index_entry(
    domain: str,
    rank: int,
    score: int,
    grade: str,
    headers_score: int,
    tls_score: int,
    dns_score: int,
    country: str,
    last_scanned: str,
) -> None:
    with _connect() as con:
        con.execute(
            """
            INSERT INTO world_index_cache
              (domain, rank, score, grade, headers_score, tls_score, dns_score, country, last_scanned)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                rank=excluded.rank,
                score=excluded.score,
                grade=excluded.grade,
                headers_score=excluded.headers_score,
                tls_score=excluded.tls_score,
                dns_score=excluded.dns_score,
                last_scanned=excluded.last_scanned
            """,
            (domain, rank, score, grade, headers_score, tls_score, dns_score, country, last_scanned),
        )


def rerank_world_index() -> None:
    """Reassign rank values based on score DESC ordering."""
    with _connect() as con:
        rows = con.execute(
            "SELECT domain FROM world_index_cache ORDER BY score DESC"
        ).fetchall()
        for i, (domain,) in enumerate(rows, start=1):
            con.execute("UPDATE world_index_cache SET rank=? WHERE domain=?", (i, domain))


# ── Admin stats ───────────────────────────────────────────────────────────────

def get_admin_stats(whitelisted_ips: set | None = None) -> dict:
    month = _month()
    with _connect() as con:
        total_all_time = con.execute(
            "SELECT COALESCE(SUM(scan_count), 0) FROM scan_usage"
        ).fetchone()[0]

        scans_this_month = con.execute(
            "SELECT COALESCE(SUM(scan_count), 0) FROM scan_usage WHERE month=?",
            (month,),
        ).fetchone()[0]

        # Free tier uses 'ip:x.x.x.x' keys; paid keys use 'wa_' prefix
        free_scans = con.execute(
            "SELECT COALESCE(SUM(scan_count), 0) FROM scan_usage WHERE api_key LIKE 'ip:%'"
        ).fetchone()[0]

        paid_scans = con.execute(
            "SELECT COALESCE(SUM(scan_count), 0) FROM scan_usage WHERE api_key NOT LIKE 'ip:%'"
        ).fetchone()[0]

        total_keys = con.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]

        active_keys = con.execute(
            "SELECT COUNT(*) FROM api_keys WHERE status='active'"
        ).fetchone()[0]

        active_agencies = con.execute(
            "SELECT COUNT(*) FROM agency_subscriptions WHERE active=1"
        ).fetchone()[0]

        keys_by_plan = con.execute(
            "SELECT plan, COUNT(*) FROM api_keys WHERE status='active' GROUP BY plan"
        ).fetchall()

        # Whitelisted IP scans — scan_usage stores free-tier IPs as 'ip:<address>'
        whitelisted_scans = 0
        if whitelisted_ips:
            placeholders = ",".join("?" * len(whitelisted_ips))
            prefixed = [f"ip:{ip}" for ip in whitelisted_ips]
            row = con.execute(
                f"SELECT COALESCE(SUM(scan_count), 0) FROM scan_usage WHERE api_key IN ({placeholders})",
                prefixed,
            ).fetchone()
            whitelisted_scans = row[0] if row else 0

    external_ip_scans = free_scans - whitelisted_scans

    return {
        "scans": {
            "total_all_time":  total_all_time,
            "this_month":      scans_this_month,
            "today":           None,
            "this_week":       None,
        },
        "breakdown": {
            "free":                 free_scans,
            "paid":                 paid_scans,
            "whitelisted_ip":       whitelisted_scans,
            "external_ip":          max(0, external_ip_scans),
        },
        "users": {
            "total_registered_keys":        total_keys,
            "active_keys":                  active_keys,
            "active_agency_subscriptions":  active_agencies,
            "active_keys_by_plan":          {plan: count for plan, count in keys_by_plan},
        },
        "note": "today/this_week not tracked at sub-month granularity in current schema",
    }
