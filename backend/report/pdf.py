"""
PDF report generation for SecureScanr — professional white design.
Color used only on text and thin borders; no dark/colored backgrounds.
WeasyPrint renders plain block elements, colored text, and light fills reliably.
"""

import html as _html_mod
import textwrap
from datetime import datetime, timezone
from urllib.parse import urlparse as _urlparse

from weasyprint import HTML

# ── Grade colours (text + border on white) ────────────────────────────────────
_GRADE_COLORS = {
    "A+": {"text": "#2ed573", "border": "#2ed573"},
    "A":  {"text": "#2ed573", "border": "#2ed573"},
    "B":  {"text": "#00d4aa", "border": "#00d4aa"},
    "C":  {"text": "#ffa502", "border": "#ffa502"},
    "D":  {"text": "#ff6b35", "border": "#ff6b35"},
    "F":  {"text": "#ff4757", "border": "#ff4757"},
}
_GRADE_DEFAULT = {"text": "#475569", "border": "#94a3b8"}

# ── Status (colored text only, no backgrounds) ────────────────────────────────
_STATUS = {
    "good":       ("#16a34a", "✓ Good"),
    "missing":    ("#dc2626", "✗ Missing"),
    "weak":       ("#d97706", "⚠ Weak"),
    "invalid":    ("#d97706", "⚠ Invalid"),
    "insecure":   ("#dc2626", "✗ Insecure"),
    "bad":        ("#dc2626", "✗ Bad"),
    "undetected": ("#d97706", "? Undetected"),
}

_SEVERITY_COLOR = {
    "critical":  "#dc2626",
    "important": "#d97706",
    "minor":     "#2563eb",
}
_SEVERITY_ORDER = {"critical": 0, "important": 1, "minor": 2}

_HEADER_META = {
    "Content-Security-Policy":    ("Low effort", "High impact"),
    "Strict-Transport-Security":  ("Low effort", "High impact"),
    "X-Frame-Options":            ("Low effort", "Medium impact"),
    "X-Content-Type-Options":     ("Low effort", "Medium impact"),
    "Referrer-Policy":            ("Low effort", "Low impact"),
    "Permissions-Policy":         ("Low effort", "Low impact"),
    "Cross-Origin-Opener-Policy":  ("Low effort", "Medium impact"),
    "Cross-Origin-Embedder-Policy": ("Low effort", "Medium impact"),
    "Cross-Origin-Resource-Policy": ("Low effort", "Low impact"),
}

# Shared wrapper style for sections that follow the first page-break section.
_FLOW_DIV = 'style="page-break-before:auto;margin-top:28px"'


def _tls_deduction_sev(reason: str, points: int) -> str:
    r = reason.lower()
    if any(k in r for k in ('expired', 'self-signed', 'not reachable', 'verification failed', 'handshake failed')):
        return 'critical'
    if points >= 10:
        return 'important'
    return 'minor'

# Column widths shared across all 3-column section tables.
_COL1_W = "28%"   # Header / Record name
_COL2_W = "18%"   # Status / Impact  (centered)
_COL3_W = "54%"   # Details & Fix


# ── HTML-escape helper ────────────────────────────────────────────────────────
def _e(v) -> str:
    if v is None:
        return "—"
    return _html_mod.escape(str(v))


# ── Inline renderers (text/border color only) ─────────────────────────────────
def _badge(status: str) -> str:
    fg, label = _STATUS.get(status, ("#64748b", status.title()))
    return f'<span style="color:{fg};font-size:8pt;font-weight:700;white-space:nowrap">{label}</span>'


def _pts(deduction: int) -> str:
    if deduction > 0:
        return f'<span style="color:#dc2626;font-size:7.5pt;font-weight:700">&#8722;{deduction}&nbsp;pts</span>'
    return '<span style="color:#16a34a;font-size:7.5pt;font-weight:600">0&nbsp;pts</span>'


def _flag(ok: bool, label: str) -> str:
    color = "#16a34a" if ok else "#dc2626"
    mark = "✓" if ok else "✗"
    return f'<span style="color:{color};font-size:8pt;font-weight:600;white-space:nowrap">{mark}&nbsp;{_e(label)}</span>'


def _sev_label(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, "#64748b")
    return (
        f'<span style="color:{color};font-size:6.5pt;font-weight:700;'
        f'text-transform:uppercase;letter-spacing:0.5px">{_e(severity)}</span>'
    )


def _effort_label(effort: str) -> str:
    color = {"Low effort": "#16a34a", "Medium effort": "#d97706", "High effort": "#dc2626"}.get(effort, "#64748b")
    return f'<span style="color:{color};font-size:7pt;font-weight:600">{_e(effort)}</span>'


def _impact_label(impact: str) -> str:
    color = {"High impact": "#dc2626", "Medium impact": "#d97706", "Low impact": "#2563eb"}.get(impact, "#64748b")
    return f'<span style="color:{color};font-size:7pt;font-weight:600">{_e(impact)}</span>'


def _impact_html(text: str) -> str:
    """Render a business-impact line. Strips stray ⚡ (U+26A1) characters that cause WeasyPrint rendering artifacts."""
    clean = (text or "").replace("⚡", "").strip()
    if not clean:
        return ""
    return (
        f'<div style="color:#d97706;font-size:8pt;font-style:italic;margin-top:4px">'
        f'<span style="font-style:normal;font-weight:700">Impact: </span>{_e(clean)}</div>'
    )


def _fix_box(text: str) -> str:
    lines = textwrap.wrap(text, width=80) or [text]
    escaped = _html_mod.escape("\n".join(lines))
    return (
        f'<div style="margin-top:5px;background:#f5f5f5;border-left:3px solid #94a3b8;'
        f'padding:5px 8px;font-family:\'Space Mono\',\'Courier New\',monospace;'
        f'font-size:7.5pt;color:#334155;white-space:pre-wrap;word-break:break-all">{escaped}</div>'
    )


def _section_hdr(title: str, result_text: str, result_color: str = "#1e3a5f") -> str:
    # Use CSS display:table on divs — avoids WeasyPrint merging adjacent HTML tables,
    # which caused the header row to render below the last data row.
    return (
        f'<div style="border-left:4px solid #1e3a5f;margin-bottom:2px;display:block;'
        f'page-break-after:avoid">'
        f'<div style="display:table;width:100%">'
        f'<div style="display:table-row">'
        f'<div style="display:table-cell;padding:9px 0 9px 12px;vertical-align:middle">'
        f'<span style="color:#1e3a5f;font-size:12pt;font-weight:700">{_e(title)}</span>'
        f'</div>'
        f'<div style="display:table-cell;padding:9px 10px 9px 0;text-align:right;'
        f'vertical-align:middle;white-space:nowrap">'
        f'<span style="color:{result_color};font-size:8pt;font-weight:700">{_e(result_text)}</span>'
        f'</div>'
        f'</div>'
        f'</div>'
        f'</div>'
    )


# ── Shared 3-column table header ──────────────────────────────────────────────
def _section_thead(col1_label: str, col3_label: str = "Details &amp; Fix") -> str:
    """Standard 3-column <thead> row used by all main section tables."""
    return (
        f'<tr style="page-break-inside:avoid;page-break-after:avoid">'
        f'<th style="width:{_COL1_W}">{col1_label}</th>'
        f'<th style="width:{_COL2_W};text-align:center">Status · Score Impact</th>'
        f'<th style="width:{_COL3_W};padding-left:12px">{col3_label}</th>'
        f'</tr>'
    )


# ── Finding counts + narrative ────────────────────────────────────────────────
def _count_findings(data: dict) -> tuple[int, int, int]:
    critical = important = minor = 0

    for info in (data.get("headers") or {}).values():
        if info.get("status") != "good":
            sev = info.get("severity", "minor")
            if sev == "critical":
                critical += 1
            elif sev == "important":
                important += 1
            else:
                minor += 1

    tls = data.get("tls") or {}
    if not tls.get("supported"):
        critical += 1
    else:
        for d in (tls.get("deductions") or []):
            pts = d.get("points", 0)
            if pts >= 15:
                critical += 1
            elif pts >= 10:
                important += 1
            else:
                minor += 1

    for key in ("spf", "dmarc"):
        rec = (data.get("dns") or {}).get(key) or {}
        if rec.get("status") != "good":
            important += 1

    for key in ("dkim", "caa", "dnssec"):
        rec = (data.get("dns") or {}).get(key) or {}
        if rec.get("status") not in ("good", None, ""):
            minor += 1

    cors = data.get("cors") or {}
    if cors.get("status") == "bad":
        important += 1

    for c in ((data.get("cookies") or {}).get("cookies") or []):
        if c.get("deduction", 0) > 0:
            minor += 1

    for info in ((data.get("cross_origin") or {}).get("headers") or {}).values():
        if info.get("status") != "good":
            sev = info.get("severity", "minor")
            if sev == "critical":
                critical += 1
            elif sev == "important":
                important += 1
            else:
                minor += 1

    return critical, important, minor


def _generate_narrative(data: dict) -> str:
    grade = data.get("grade", "?")
    score = data.get("score", 0)
    critical, important, minor = _count_findings(data)

    crit_names: list[str] = []
    for name, info in (data.get("headers") or {}).items():
        if info.get("severity") == "critical" and info.get("status") != "good":
            crit_names.append(name)
    if not (data.get("tls") or {}).get("supported"):
        crit_names.append("HTTPS")

    if critical + important + minor == 0:
        return (
            f"This site scored {grade} ({score}/100). The security configuration is "
            "excellent — no actionable issues were found across all tested areas."
        )

    parts: list[str] = []
    if critical > 0:
        suffix = ""
        if crit_names:
            shown = crit_names[:2]
            suffix = f" — including {' and '.join(shown)}"
            if len(crit_names) > 2:
                suffix += " and others"
        verb = "expose" if critical > 1 else "exposes"
        parts.append(
            f"{critical} critical finding{'s' if critical > 1 else ''}{suffix} "
            f"that {verb} users to serious attacks"
        )
    if important > 0:
        parts.append(f"{important} important finding{'s' if important > 1 else ''} requiring attention")
    if minor > 0:
        parts.append(f"{minor} minor improvement{'s' if minor > 1 else ''} recommended")

    finding_str = "; ".join(parts) + "."

    if grade in ("F", "D"):
        urgency = "Immediate remediation is recommended before this site handles sensitive data."
    elif grade == "C":
        urgency = "Security improvements should be prioritised in the next development sprint."
    else:
        urgency = "Remaining issues should be addressed to achieve a higher security rating."

    return f"This site scored {grade} ({score}/100). The assessment identified {finding_str} {urgency}"


# ── CSS ───────────────────────────────────────────────────────────────────────
def _css() -> str:
    return """
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&display=swap');

@page {
    size: A4;
    margin: 2cm 1.5cm 2.2cm 1.5cm;
    @bottom-left {
        content: "Confidential  ·  SecureScanr Security Assessment";
        font-family: 'DM Sans', Arial, sans-serif;
        font-size: 7pt;
        color: #94a3b8;
        border-top: 0.5pt solid #e2e8f0;
        padding-top: 5pt;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages) "  ·  securescanr.com";
        font-family: 'DM Sans', Arial, sans-serif;
        font-size: 7pt;
        color: #94a3b8;
        border-top: 0.5pt solid #e2e8f0;
        padding-top: 5pt;
    }
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'DM Sans', Arial, Helvetica, sans-serif;
    font-size: 9.5pt;
    color: #1e293b;
    line-height: 1.6;
    background: #ffffff;
}
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
}
th {
    background: #f8fafc;
    color: #475569;
    padding: 6px 10px;
    text-align: left;
    font-size: 7.5pt;
    font-weight: 700;
    border-bottom: 2px solid #e2e8f0;
}
td {
    padding: 5px 10px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: top;
    color: #1e293b;
}
tr:nth-child(even) td { background: #f8fafc; }
tr:nth-child(odd)  td { background: #ffffff; }
.page-break  { page-break-before: always; }
.avoid-break { page-break-inside: avoid; }
.mono { font-family: 'Space Mono', 'Courier New', monospace; font-size: 7.5pt; word-break: break-all; color: #334155; }
.dim  { color: #64748b; font-size: 8.5pt; }
"""


# ── Cover page ────────────────────────────────────────────────────────────────
def _cover(data: dict) -> str:
    grade = data.get("grade", "?")
    score = data.get("score", 0)
    url   = data.get("url", "")
    final_url   = data.get("final_url", url)
    status_code = data.get("status_code")
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    gc = _GRADE_COLORS.get(grade, _GRADE_DEFAULT)
    grade_color = gc["text"]

    redirect_line = (
        f'<div style="font-size:8pt;color:#64748b;margin-top:4px">&#8594; {_e(final_url)}</div>'
        if final_url and final_url != url else ""
    )
    status_line = (
        f'<div style="font-size:8pt;color:#64748b;margin-top:2px">HTTP {_e(status_code)}</div>'
        if status_code else ""
    )

    return f"""
<!-- ═══ COVER ═══ -->

<!-- Wordmark row -->
<table style="border:none;margin-bottom:10px">
  <tr>
    <td style="border:none;padding:0;vertical-align:top">
      <div style="font-family:'Space Mono','Courier New',monospace;font-size:20pt;
                  font-weight:700;color:#1e293b;letter-spacing:-0.5px">
        Web<span style="color:#1e3a5f">Audit</span>
      </div>
      <div style="font-size:7.5pt;color:#94a3b8;text-transform:uppercase;
                  letter-spacing:1.5px;margin-top:5px">
        Web Security Assessment
      </div>
    </td>
    <td style="border:none;padding:0;text-align:right;vertical-align:top">
      <div style="font-size:8pt;color:#64748b">{_e(now)}</div>
      <div style="font-size:7.5pt;color:#94a3b8;margin-top:3px">Generated by SecureScanr · securescanr.com</div>
    </td>
  </tr>
</table>

<div style="border-top:1px solid #e2e8f0;margin-bottom:0"></div>

<!-- Grade badge — full-width bordered box, centered text, white fill. -->
<div style="margin-top:40mm;border:3px solid {grade_color};
            text-align:center;padding:28px 32px;margin-bottom:18px">
  <div style="font-family:'Space Mono','Courier New',monospace;font-size:72pt;
              font-weight:700;color:{grade_color};line-height:1">{_e(grade)}</div>
  <div style="font-family:'Space Mono','Courier New',monospace;font-size:16pt;
              color:{grade_color};margin-top:10px">{score} / 100</div>
</div>

<!-- Target URL -->
<div style="text-align:center;margin-bottom:5px">
  <div style="font-family:'Space Mono','Courier New',monospace;font-size:10pt;
              color:#1e293b;word-break:break-all">{_e(url)}</div>
  {redirect_line}
  {status_line}
</div>
<div style="text-align:center;margin-bottom:20mm">
  <span style="font-size:8pt;color:#94a3b8">Most sites score D–F. That is normal.</span>
</div>

<!-- Disclaimer — light gray fill, safe for WeasyPrint -->
<div style="background:#f8fafc;border-left:3px solid #cbd5e1;
            padding:12px 16px;font-size:8.5pt;color:#64748b;line-height:1.7">
  <strong style="color:#1e293b">About this report:</strong> This automated assessment
  evaluates HTTP security headers, TLS/SSL certificate configuration, DNS email security
  (SPF &amp; DMARC), and cookie security attributes. Scores are based on a 100-point scale;
  missing or misconfigured controls reduce the score by severity.
  This report does not replace a full manual penetration test.
</div>
"""


# ── Executive summary ─────────────────────────────────────────────────────────
def _executive_summary(data: dict) -> str:
    grade = data.get("grade", "?")
    score = data.get("score", 0)
    critical, important, minor = _count_findings(data)
    narrative = _generate_narrative(data)

    headers     = data.get("headers") or {}
    tls         = data.get("tls") or {}
    dns         = data.get("dns") or {}
    cookies_data = data.get("cookies") or {}
    co_data     = data.get("cross_origin") or {}

    headers_lost = sum(h.get("deduction", 0) for h in headers.values())
    headers_lost += (data.get("cors") or {}).get("deduction", 0)
    headers_lost += (data.get("server_fingerprint") or {}).get("total_deduction", 0)
    tls_lost = sum(d.get("points", 0) for d in (tls.get("deductions") or []))
    if not tls.get("supported"):
        tls_lost += 20
    dns_lost = sum(
        (dns.get(k) or {}).get("deduction", 0)
        for k in ("spf", "dmarc", "dkim", "caa", "dnssec")
    )
    cookie_lost = sum(c.get("deduction", 0) for c in (cookies_data.get("cookies") or []))
    co_lost = sum(h.get("deduction", 0) for h in (co_data.get("headers") or {}).values())

    gc = _GRADE_COLORS.get(grade, _GRADE_DEFAULT)

    def score_row(module: str, lost: int) -> str:
        if lost == 0:
            val = '<span style="color:#16a34a;font-weight:600">No issues</span>'
        else:
            c = "#dc2626" if lost >= 20 else ("#d97706" if lost >= 10 else "#64748b")
            val = f'<span style="color:{c};font-weight:700">&#8722;{lost} pts</span>'
        return (
            f'<tr><td style="font-size:8.5pt">{_e(module)}</td>'
            f'<td style="text-align:right;white-space:nowrap">{val}</td></tr>'
        )

    def risk_block(count: int, label: str, color: str) -> str:
        return (
            f'<div style="margin-bottom:10px">'
            f'<span style="font-family:\'Space Mono\',monospace;font-size:22pt;'
            f'font-weight:700;color:{color}">{count}</span>'
            f'<span style="font-size:8.5pt;color:#64748b;margin-left:8px;'
            f'font-weight:600">{_e(label)}</span>'
            f'</div>'
        )

    return f"""
<div class="page-break">
<!-- ═══ EXECUTIVE SUMMARY ═══ -->
<table style="border:none;margin-bottom:14px">
  <tr>
    <td style="border:none;padding:0;vertical-align:middle">
      <div style="font-size:14pt;font-weight:700;color:#1e293b">Executive Summary</div>
      <div style="font-size:8.5pt;color:#64748b;margin-top:3px">{_e(data.get("final_url") or data.get("url", ""))}</div>
    </td>
    <td style="border:none;padding:0;text-align:right;vertical-align:middle">
      <div style="font-family:'Space Mono',monospace;font-size:28pt;font-weight:700;
                  color:{gc['text']};line-height:1">{_e(grade)}</div>
      <div style="font-family:'Space Mono',monospace;font-size:10pt;
                  color:{gc['text']}">{score} / 100</div>
    </td>
  </tr>
</table>

<div style="border-top:2px solid #e2e8f0;margin-bottom:16px"></div>

<table style="border:none;margin-bottom:16px">
  <tr>
    <!-- Left: score breakdown -->
    <td style="border:none;padding:0;width:52%;vertical-align:top;padding-right:20px">
      <div style="font-size:7.5pt;font-weight:700;color:#94a3b8;text-transform:uppercase;
                  letter-spacing:0.8px;margin-bottom:8px">Score Breakdown</div>
      <table>
        <tr>
          <th style="font-size:7pt">Module</th>
          <th style="font-size:7pt;text-align:right">Points Lost</th>
        </tr>
        {score_row("HTTP Security Headers", headers_lost)}
        {score_row("TLS / SSL Certificate", tls_lost)}
        {score_row("DNS Email Security", dns_lost)}
        {score_row("Cookie Security", cookie_lost)}
        {score_row("Cross-Origin Isolation", co_lost)}
        <tr>
          <td style="font-weight:700;border-top:2px solid #e2e8f0">Final Score</td>
          <td style="text-align:right;font-family:'Space Mono',monospace;font-size:10pt;
                     font-weight:700;color:{gc['text']};border-top:2px solid #e2e8f0">{score}/100</td>
        </tr>
      </table>
    </td>
    <!-- Right: risk summary -->
    <td style="border:none;padding:0;vertical-align:top">
      <div style="font-size:7.5pt;font-weight:700;color:#94a3b8;text-transform:uppercase;
                  letter-spacing:0.8px;margin-bottom:12px">Risk Summary</div>
      {risk_block(critical,  "CRITICAL findings",  "#dc2626")}
      {risk_block(important, "IMPORTANT findings", "#d97706")}
      {risk_block(minor,     "MINOR findings",     "#2563eb")}
    </td>
  </tr>
</table>

<!-- Narrative paragraph — light gray fill is safe in WeasyPrint -->
<div style="background:#f8fafc;border-left:3px solid #cbd5e1;
            padding:12px 16px;font-size:9pt;color:#1e293b;line-height:1.7">
  {_e(narrative)}
</div>
</div>
"""


# ── HTTP Headers section ──────────────────────────────────────────────────────
def _headers_section(data: dict) -> str:
    headers = data.get("headers") or {}
    cors    = data.get("cors") or {}
    if not headers:
        return ""

    cors_is_bad = cors.get("status") == "bad"
    issues = sum(1 for h in headers.values() if h.get("status") != "good")
    if cors_is_bad:
        issues += 1
    result_text  = "All passed" if issues == 0 else f"{issues} issue{'s' if issues != 1 else ''} found"
    result_color = "#16a34a" if issues == 0 else ("#d97706" if issues <= 2 else "#dc2626")

    rows = []
    for name, info in headers.items():
        status    = info.get("status", "unknown")
        deduction = info.get("deduction", 0)
        severity  = info.get("severity", "minor")
        sev_color = _SEVERITY_COLOR.get(severity, "#64748b")
        explanation = info.get("explanation", "")
        fix   = info.get("fix")
        value = info.get("value")
        note  = info.get("note")

        business_impact = info.get("business_impact", "")
        detail = f'<div class="dim">{_e(explanation)}</div>'
        if business_impact and status != "good":
            detail += _impact_html(business_impact)
        if value:
            display_val = value if len(value) <= 300 else value[:300] + " ... (truncated for readability)"
            detail += f'<div class="mono" style="margin-top:3px">{_e(display_val)}</div>'
        if note:
            detail += f'<div style="color:#d97706;font-size:8pt;margin-top:3px">{_e(note)}</div>'
        if fix:
            detail += _fix_box(fix)

        sev_html = (
            '<div style="margin-top:4px;font-size:6pt;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:0.5px;color:#94a3b8">Risk Severity</div>'
            f'<div style="margin-top:2px">{_sev_label(severity)}</div>'
        ) if status != "good" else ""
        rows.append(f"""
        <tr class="avoid-break">
          <td style="width:{_COL1_W};border-left:3px solid {sev_color};font-weight:600;font-size:8.5pt">
            {_e(name)}<br>
            {sev_html}
          </td>
          <td style="width:{_COL2_W};text-align:center;vertical-align:middle">
            <div style="display:block">{_badge(status)}</div>
            <div style="margin-top:6px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8;display:block">Score Impact</div>
            <div style="display:block;margin-top:2px">{_pts(deduction)}</div>
          </td>
          <td style="width:{_COL3_W};padding-left:12px">{detail}</td>
        </tr>""")

    # CORS wildcard is a scored header-level finding — render it when bad.
    if cors_is_bad:
        cors_detail = f'<div class="dim">{_e(cors.get("explanation", ""))}</div>'
        cors_val = cors.get("value")
        if cors_val:
            cors_detail += f'<div class="mono" style="margin-top:3px">{_e(cors_val)}</div>'
        cors_fix = cors.get("fix")
        if cors_fix:
            cors_detail += _fix_box(cors_fix)
        rows.append(f"""
        <tr class="avoid-break">
          <td style="width:{_COL1_W};border-left:3px solid {_SEVERITY_COLOR['important']};font-weight:600;font-size:8.5pt">
            Access-Control-Allow-Origin<br>
            <div style="margin-top:4px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8">Risk Severity</div>
            <div style="margin-top:2px">{_sev_label("important")}</div>
          </td>
          <td style="width:{_COL2_W};text-align:center;vertical-align:middle">
            <div style="display:block">{_badge("bad")}</div>
            <div style="margin-top:6px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8;display:block">Score Impact</div>
            <div style="display:block;margin-top:2px">{_pts(cors.get("deduction", 0))}</div>
          </td>
          <td style="width:{_COL3_W};padding-left:12px">{cors_detail}</td>
        </tr>""")

    # HTTP Headers flows after Detected Technologies on the same page (no forced break).
    return f"""
<div {_FLOW_DIV}>
{_section_hdr("HTTP Security Headers", result_text, result_color)}
<table style="table-layout:fixed;width:100%">
  {_section_thead("Header")}
  {"".join(rows)}
</table>
</div>"""


# ── TLS section ───────────────────────────────────────────────────────────────
def _tls_section(data: dict) -> str:
    tls = data.get("tls")
    if not tls:
        return ""

    cert       = tls.get("certificate") or {}
    conn       = tls.get("connection") or {}
    deductions = tls.get("deductions") or []
    error      = tls.get("error")

    if not tls.get("supported"):
        return f"""
<div {_FLOW_DIV}>
{_section_hdr("TLS / SSL Certificate", "HTTPS not available", "#dc2626")}
<div style="background:#fef2f2;border-left:3px solid #dc2626;padding:12px 16px;
            color:#991b1b;font-size:9pt;margin-top:0">
  <strong>HTTPS not available.</strong>
  {_e(error or "The site did not respond to HTTPS connections.")}
  All traffic is transmitted in plaintext — this is a critical finding.
</div>
</div>"""

    if error and not cert:
        return f"""
<div {_FLOW_DIV}>
{_section_hdr("TLS / SSL Certificate", "TLS Error", "#dc2626")}
<div style="background:#fef2f2;border-left:3px solid #dc2626;padding:12px 16px;
            color:#991b1b;font-size:9pt">
  <strong>TLS Error:</strong> {_e(error)}
</div>
</div>"""

    issues      = len(deductions)
    result_text  = "No issues" if issues == 0 else f"{issues} issue{'s' if issues != 1 else ''} found"
    result_color = "#16a34a" if issues == 0 else ("#d97706" if issues == 1 else "#dc2626")

    days = cert.get("days_remaining")
    if cert.get("is_expired"):
        days_color, days_text = "#dc2626", "EXPIRED"
    elif days is not None and days < 30:
        days_color, days_text = "#d97706", f"{days} days (renew immediately)"
    else:
        days_color, days_text = "#16a34a", (f"{days} days" if days is not None else "—")

    san_list = cert.get("san") or []
    san_str = ", ".join(san_list[:5])
    if len(san_list) > 5:
        san_str += f" … and {len(san_list) - 5} more"
    if not san_str:
        san_str = "—"

    ded_rows = ""
    for d in deductions:
        bi = d.get("business_impact", "")
        bi_html = _impact_html(bi)
        sev = _tls_deduction_sev(d.get("reason", ""), d.get("points", 0))
        ded_rows += (
            f'<tr style="page-break-inside:avoid">'
            f'<td style="color:#dc2626;font-size:8.5pt;border-left:3px solid #dc2626">'
            f'&#9888; {_e(d.get("reason", ""))}{bi_html}</td>'
            f'<td style="white-space:nowrap;text-align:right;vertical-align:top">'
            f'<div style="font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8;text-align:right">Risk Severity</div>'
            f'<div style="margin-top:1px">{_sev_label(sev)}</div>'
            f'<div style="margin-top:5px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8;text-align:right">Score Impact</div>'
            f'<div style="margin-top:1px;color:#dc2626;font-weight:700;font-size:8.5pt">&#8722;{d.get("points", 0)}&nbsp;pts</div>'
            f'</td></tr>'
        )
    if not ded_rows:
        ded_rows = (
            '<tr style="page-break-inside:avoid">'
            '<td colspan="2" style="color:#16a34a;font-size:8.5pt">'
            '&#10003; No TLS issues detected</td></tr>'
        )

    def cert_row(label: str, value_html: str) -> str:
        return (
            f'<tr style="page-break-inside:avoid">'
            f'<td style="font-weight:600;font-size:8.5pt;color:#64748b;width:30%">'
            f'{_e(label)}</td><td>{value_html}</td></tr>'
        )

    self_signed_html = (
        '<span style="color:#dc2626;font-weight:600">Yes — untrusted</span>'
        if cert.get("is_self_signed") else
        '<span style="color:#16a34a">No</span>'
    )

    return f"""
<div {_FLOW_DIV}>
{_section_hdr("TLS / SSL Certificate", result_text, result_color)}
<table style="page-break-inside:avoid">
  <tr style="page-break-inside:avoid"><th colspan="2">Certificate</th></tr>
  {cert_row("Subject",        _e(cert.get("subject")))}
  {cert_row("Issuer",         _e(cert.get("issuer")))}
  {cert_row("Valid From",     _e((cert.get("valid_from") or "")[:10]))}
  {cert_row("Valid Until",    f'<span style="color:{days_color};font-weight:600">{_e((cert.get("valid_until") or "")[:10])}</span>')}
  {cert_row("Days Remaining", f'<span style="color:{days_color};font-weight:600">{_e(days_text)}</span>')}
  {cert_row("Self-Signed",    self_signed_html)}
  {cert_row("SANs",           f'<span class="mono">{_e(san_str)}</span>')}
  <tr style="page-break-inside:avoid"><th colspan="2">Connection</th></tr>
  {cert_row("Protocol",     f'<span class="mono">{_e(conn.get("protocol"))}</span>')}
  {cert_row("Cipher Suite", f'<span class="mono">{_e(conn.get("cipher"))}</span>')}
  {cert_row("Key Bits",     _e(conn.get("bits")))}
  <tr style="page-break-inside:avoid"><th colspan="2">Assessment</th></tr>
  {ded_rows}
</table>
</div>"""


# ── DNS section ───────────────────────────────────────────────────────────────
def _dns_section(data: dict) -> str:
    dns = data.get("dns")
    if not dns:
        return ""

    spf    = dns.get("spf")    or {}
    dmarc  = dns.get("dmarc")  or {}
    dkim   = dns.get("dkim")   or {}
    caa    = dns.get("caa")    or {}
    dnssec = dns.get("dnssec") or {}

    _bad_statuses = {
        "spf":    ("missing", "invalid", "weak"),
        "dmarc":  ("missing", "weak"),
        "dkim":   ("undetected",),
        "caa":    ("missing",),
        "dnssec": ("missing",),
    }
    issues = sum(
        1 for key, rec in [("spf", spf), ("dmarc", dmarc), ("dkim", dkim), ("caa", caa), ("dnssec", dnssec)]
        if rec.get("status") in _bad_statuses[key]
    )
    result_text  = "All good" if issues == 0 else f"{issues} issue{'s' if issues != 1 else ''} found"
    result_color = "#16a34a" if issues == 0 else ("#d97706" if issues == 1 else "#dc2626")

    def record_row(title: str, rec: dict) -> str:
        status    = rec.get("status", "missing")
        is_good   = status == "good"
        is_warn   = status in ("weak", "invalid", "undetected")
        sev_color = "#16a34a" if is_good else ("#d97706" if is_warn else "#dc2626")
        explanation  = rec.get("explanation", "")
        record_val   = rec.get("record")
        records_list = rec.get("records") or []
        selector     = rec.get("selector")
        fix          = rec.get("fix")
        deduction    = rec.get("deduction", 0)
        policy       = rec.get("policy") or rec.get("policy_label")
        strength     = rec.get("policy_strength")

        business_impact = rec.get("business_impact", "")
        detail = f'<div class="dim">{_e(explanation)}</div>'
        if business_impact and not is_good:
            detail += _impact_html(business_impact)
        if selector:
            detail += f'<div style="margin-top:3px;font-size:8.5pt">Selector: <span class="mono">{_e(selector)}</span></div>'
        if record_val:
            detail += f'<div class="mono" style="margin-top:3px">{_e(record_val)}</div>'
        if records_list:
            detail += f'<div class="mono" style="margin-top:3px">{_e("  ".join(str(r) for r in records_list[:3]))}</div>'
        if policy:
            label = _e(policy) + (f" ({_e(strength)})" if strength else "")
            detail += f'<div style="margin-top:4px;font-size:8.5pt">Policy: <strong>{label}</strong></div>'
        if fix:
            detail += _fix_box(fix)

        sev = "important" if title in ("SPF", "DMARC") else "minor"
        return f"""
        <tr class="avoid-break">
          <td style="width:{_COL1_W};border-left:3px solid {sev_color};font-weight:700;font-size:9.5pt;white-space:nowrap">
            {_e(title)}
            {f'<div style="margin-top:4px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8">Risk Severity</div><div style="margin-top:2px">{_sev_label(sev)}</div>' if not is_good else ''}
          </td>
          <td style="width:{_COL2_W};text-align:center;vertical-align:middle">
            <div style="display:block">{_badge(status)}</div>
            <div style="margin-top:6px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8;display:block">Score Impact</div>
            <div style="display:block;margin-top:2px">{_pts(deduction)}</div>
          </td>
          <td style="width:{_COL3_W};padding-left:12px">{detail}</td>
        </tr>"""

    return f"""
<div {_FLOW_DIV}>
{_section_hdr("DNS Security", result_text, result_color)}
<table style="table-layout:fixed;width:100%">
  {_section_thead("Record")}
  {record_row("SPF", spf)}
  {record_row("DMARC", dmarc)}
  {record_row("DKIM", dkim)}
  {record_row("CAA", caa)}
  {record_row("DNSSEC", dnssec)}
</table>
</div>"""


# ── Cookies section ───────────────────────────────────────────────────────────
def _cookies_section(data: dict) -> str:
    cookies_data = data.get("cookies")
    if not cookies_data:
        return ""

    cookies = cookies_data.get("cookies") or []
    if not cookies:
        return f"""
<div {_FLOW_DIV}>
{_section_hdr("Cookie Security", "No cookies detected", "#16a34a")}
<div style="background:#f0faf4;border-left:4px solid #2ed573;padding:12px 16px;
            color:#166534;font-size:9pt">
  No cookies detected — nothing to report.
</div>
</div>"""

    issues = sum(1 for c in cookies if c.get("deduction", 0) > 0)
    result_text  = "All secure" if issues == 0 else f"{issues} insecure cookie{'s' if issues != 1 else ''}"
    result_color = "#16a34a" if issues == 0 else ("#d97706" if issues <= 2 else "#dc2626")

    rows = []
    for c in cookies:
        samesite_val = c.get("samesite") or ""
        samesite_ok  = samesite_val.lower() in ("strict", "lax")
        samesite_lbl = samesite_val or "Not set"
        deduction    = c.get("deduction", 0)
        sev_color    = "#dc2626" if deduction >= 10 else ("#d97706" if deduction > 0 else "#16a34a")

        issue_list = c.get("issues") or []
        issues_html = ""
        if issue_list:
            items = "".join(f'<div style="margin-bottom:2px">&#9888;&nbsp;{_e(i)}</div>' for i in issue_list)
            issues_html = f'<div style="margin-top:6px;font-size:8pt;color:#dc2626">{items}</div>'

        business_impact = c.get("business_impact", "")
        biz_html = _impact_html(business_impact) if business_impact and deduction > 0 else ""

        flags_html = (
            f'<div style="font-size:8pt;color:#64748b;margin-bottom:2px">'
            f'{_flag(bool(c.get("secure")), "Secure")}'
            f'&nbsp;&nbsp;&nbsp;'
            f'{_flag(bool(c.get("httponly")), "HttpOnly")}'
            f'&nbsp;&nbsp;&nbsp;'
            f'{_flag(samesite_ok, f"SameSite={samesite_lbl}")}'
            f'</div>'
        )

        rows.append(f"""
        <tr class="avoid-break">
          <td style="width:{_COL1_W};border-left:3px solid {sev_color};word-break:break-all;overflow-wrap:break-word">
            <span class="mono">{_e(c.get("name", "?"))}</span>
            {f'<div style="margin-top:4px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8">Risk Severity</div><div style="margin-top:2px">{_sev_label("minor")}</div>' if deduction > 0 else ''}
          </td>
          <td style="width:{_COL2_W};text-align:center;vertical-align:middle">
            <div style="display:block">{_badge(c.get("status", "unknown"))}</div>
            <div style="margin-top:6px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8;display:block">Score Impact</div>
            <div style="display:block;margin-top:2px">{_pts(deduction)}</div>
          </td>
          <td style="width:{_COL3_W};padding-left:12px">
            {flags_html}
            {issues_html}
            {biz_html}
          </td>
        </tr>""")

    return f"""
<div {_FLOW_DIV}>
{_section_hdr("Cookie Security", result_text, result_color)}
<table style="table-layout:fixed;width:100%;page-break-inside:avoid">
  {_section_thead("Cookie", "Attributes &amp; Issues")}
  {"".join(rows)}
</table>
</div>"""


# ── Cross-Origin Isolation section ───────────────────────────────────────────
def _cross_origin_section(data: dict) -> str:
    co = data.get("cross_origin")
    if not co:
        return ""

    headers = co.get("headers") or {}
    if not headers:
        return ""

    issues = sum(1 for h in headers.values() if h.get("status") != "good")
    result_text  = "All set" if issues == 0 else f"{issues} issue{'s' if issues != 1 else ''} found"
    result_color = "#16a34a" if issues == 0 else ("#d97706" if issues <= 1 else "#dc2626")

    rows = []
    for name, info in headers.items():
        status    = info.get("status", "unknown")
        deduction = info.get("deduction", 0)
        severity  = info.get("severity", "minor")
        sev_color = _SEVERITY_COLOR.get(severity, "#64748b")
        explanation = info.get("explanation", "")
        fix   = info.get("fix")
        value = info.get("value")

        business_impact = info.get("business_impact", "")
        detail = f'<div class="dim">{_e(explanation)}</div>'
        if business_impact and status != "good":
            detail += _impact_html(business_impact)
        if value:
            detail += f'<div class="mono" style="margin-top:3px">{_e(value)}</div>'
        if fix:
            detail += _fix_box(fix)

        co_sev_html = (
            '<div style="margin-top:4px;font-size:6pt;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:0.5px;color:#94a3b8">Risk Severity</div>'
            f'<div style="margin-top:2px">{_sev_label(severity)}</div>'
        ) if status != "good" else ""
        rows.append(f"""
        <tr class="avoid-break">
          <td style="width:{_COL1_W};border-left:3px solid {sev_color};font-weight:600;font-size:8.5pt">
            {_e(name)}<br>
            {co_sev_html}
          </td>
          <td style="width:{_COL2_W};text-align:center;vertical-align:middle">
            <div style="display:block">{_badge(status)}</div>
            <div style="margin-top:6px;font-size:6pt;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#94a3b8;display:block">Score Impact</div>
            <div style="display:block;margin-top:2px">{_pts(deduction)}</div>
          </td>
          <td style="width:{_COL3_W};padding-left:12px">{detail}</td>
        </tr>""")

    return f"""
<div {_FLOW_DIV}>
{_section_hdr("Cross-Origin Isolation", result_text, result_color)}
<table style="table-layout:fixed;width:100%">
  {_section_thead("Header")}
  {"".join(rows)}
</table>
</div>"""


# ── Detected Technologies section ────────────────────────────────────────────
def _detected_technologies_section(data: dict) -> str:
    """New page after Executive Summary: surfaces server, CDN, TLS version, redirect chain, and IP."""
    url       = data.get("url", "")
    final_url = data.get("final_url") or url

    # Server / framework
    fp         = data.get("server_fingerprint") or {}
    server_val = (fp.get("server") or {}).get("value") or "Not disclosed"
    x_powered  = (fp.get("x_powered_by") or {}).get("value")

    # CDN / proxy
    cdn = data.get("cdn") or "Not detected"

    # TLS protocol
    tls  = data.get("tls") or {}
    conn = tls.get("connection") or {}
    if not tls.get("supported"):
        protocol = "HTTP only (no TLS)"
    else:
        protocol = conn.get("protocol") or "Unknown"

    # Redirect chain
    chain = data.get("redirect_chain") or []
    if len(chain) > 1:
        if len(chain) <= 3:
            redirect_text = " → ".join(chain)
        else:
            redirect_text = f"{chain[0]} → … → {chain[-1]} ({len(chain) - 1} hops)"
    elif final_url and url and final_url.rstrip("/") != url.rstrip("/"):
        redirect_text = f"{url} → {final_url}"
    else:
        redirect_text = "No redirect (direct connection)"

    # IP address (pre-resolved by the scanner route)
    ip_addr = data.get("ip") or "—"

    def tech_row(label: str, value_html: str) -> str:
        return (
            f'<tr class="avoid-break">'
            f'<td style="width:28%;font-weight:600;font-size:8.5pt;color:#475569">{_e(label)}</td>'
            f'<td>{value_html}</td>'
            f'</tr>'
        )

    x_powered_row = (
        tech_row("Framework / Runtime", f'<span class="mono">{_e(x_powered)}</span>')
        if x_powered else ""
    )
    cdn_color = "#16a34a" if cdn != "Not detected" else "#64748b"

    return f"""
<div class="page-break" style="page-break-after:avoid">
{_section_hdr("Detected Technologies", "Informational", "#475569")}
<p class="dim" style="padding:6px 10px;border-bottom:1px solid #f1f5f9;margin-bottom:4px">
  Detected from HTTP response headers and DNS. No active fingerprinting performed.
</p>
<table style="table-layout:fixed;width:100%;page-break-inside:avoid">
  <tr style="page-break-inside:avoid;page-break-after:avoid">
    <th style="width:28%">Property</th>
    <th>Value</th>
  </tr>
  {tech_row("Server", f'<span class="mono">{_e(server_val)}</span>')}
  {x_powered_row}
  {tech_row("CDN / Proxy", f'<span style="font-weight:600;color:{cdn_color}">{_e(cdn)}</span>')}
  {tech_row("TLS Protocol", f'<span class="mono">{_e(protocol)}</span>')}
  {tech_row("Redirect Chain", f'<span class="mono" style="word-break:break-all">{_e(redirect_text)}</span>')}
  {tech_row("IP Address", f'<span class="mono">{_e(ip_addr)}</span>')}
</table>
</div>"""


# ── Recommendations ───────────────────────────────────────────────────────────
def _recommendations_section(data: dict) -> str:
    items: list[tuple[str, str, str, str, str, str]] = []

    for name, info in (data.get("headers") or {}).items():
        if info.get("fix"):
            effort, impact = _HEADER_META.get(name, ("Low effort", "Low impact"))
            items.append((
                info.get("severity", "minor"), name,
                info.get("explanation", ""), info["fix"],
                effort, impact,
            ))

    cors = data.get("cors") or {}
    if cors.get("fix"):
        items.append(("important", "Access-Control-Allow-Origin",
                      cors.get("explanation", ""), cors["fix"],
                      "Low effort", "Medium impact"))

    for key in ("spf", "dmarc", "dkim", "caa", "dnssec"):
        rec = ((data.get("dns") or {}).get(key) or {})
        if rec.get("fix"):
            sev = "important" if key in ("spf", "dmarc") else "minor"
            items.append((sev, key.upper(), rec.get("explanation", ""), rec["fix"],
                          "Low effort", "Medium impact"))

    for c in ((data.get("cookies") or {}).get("cookies") or []):
        if c.get("issues"):
            fix = f'Set-Cookie: {c["name"]}=<value>; Path=/; HttpOnly; Secure; SameSite=Strict'
            items.append(("minor", f'Cookie: {c["name"]}', c["issues"][0], fix,
                          "Low effort", "Medium impact"))

    for name, info in ((data.get("cross_origin") or {}).get("headers") or {}).items():
        if info.get("fix"):
            effort, impact = _HEADER_META.get(name, ("Low effort", "Medium impact"))
            items.append((
                info.get("severity", "minor"), name,
                info.get("explanation", ""), info["fix"],
                effort, impact,
            ))

    if not (data.get("tls") or {}).get("supported"):
        items.append(("critical", "Enable HTTPS",
                      "The site does not support HTTPS. All traffic is transmitted in plaintext.",
                      "Install a TLS certificate (free via Let's Encrypt: certbot --nginx)",
                      "High effort", "High impact"))

    if not items:
        return f"""
<div {_FLOW_DIV}>
{_section_hdr("Recommendations", "Nothing to fix", "#16a34a")}
<div style="background:#f0fdf4;border-left:3px solid #16a34a;padding:12px 16px;
            color:#166534;font-size:9pt;margin-top:0">
  &#10003; No actionable fixes required. The security configuration is excellent.
</div>
</div>"""

    items.sort(key=lambda x: _SEVERITY_ORDER.get(x[0], 3))

    _group_label = {"critical": "Fix today", "important": "Fix this week", "minor": "Fix this month"}
    _group_color = {"Fix today": "#dc2626",  "Fix this week": "#d97706",   "Fix this month": "#2563eb"}

    groups: dict[str, list] = {}
    for item in items:
        g = _group_label.get(item[0], "Fix this month")
        groups.setdefault(g, []).append(item)

    # Column widths for recommendations table: # | Finding | Explanation & Fix
    _REC_COL1 = "4%"
    _REC_COL2 = "28%"
    _REC_COL3 = "68%"

    all_rows: list[str] = []
    n = 1
    for group_label in ("Fix today", "Fix this week", "Fix this month"):
        if group_label not in groups:
            continue
        g_color = _group_color[group_label]
        all_rows.append(
            f'<tr><td colspan="3" style="background:#f8fafc;color:{g_color};'
            f'font-weight:700;font-size:8pt;text-transform:uppercase;letter-spacing:0.5px;'
            f'padding:8px 10px;border-top:2px solid #e2e8f0">{_e(group_label)}</td></tr>'
        )
        for severity, name, explanation, fix, effort, impact in groups[group_label]:
            sev_color  = _SEVERITY_COLOR.get(severity, "#64748b")
            short_expl = explanation[:140] + ("…" if len(explanation) > 140 else "")
            all_rows.append(f"""
            <tr class="avoid-break">
              <td style="width:{_REC_COL1};text-align:center;vertical-align:middle;
                         font-weight:700;color:{sev_color};font-size:10pt">{n}</td>
              <td style="width:{_REC_COL2};vertical-align:top;border-left:3px solid {sev_color}">
                <div style="font-weight:600;font-size:8.5pt">{_e(name)}</div>
                <div style="margin-top:4px">{_sev_label(severity)}</div>
                <div style="margin-top:5px">{_effort_label(effort)}</div>
                <div style="margin-top:3px">{_impact_label(impact)}</div>
              </td>
              <td style="width:{_REC_COL3};padding-left:12px">
                <div class="dim">{_e(short_expl)}</div>
                {_fix_box(fix)}
              </td>
            </tr>""")
            n += 1

    return f"""
<div {_FLOW_DIV}>
{_section_hdr("Recommendations", f"{len(items)} finding{'s' if len(items) != 1 else ''}", "#d97706")}
<p class="dim" style="padding:8px 10px;border-bottom:1px solid #f1f5f9">
  All actionable findings ordered by priority — apply critical items first.
</p>
<table style="table-layout:fixed;width:100%">
  <tr>
    <th style="width:{_REC_COL1};text-align:center">#</th>
    <th style="width:{_REC_COL2}">Finding</th>
    <th style="width:{_REC_COL3};padding-left:12px">Explanation &amp; Fix</th>
  </tr>
  {"".join(all_rows)}
</table>
</div>"""


# ── Cookie Inventory section ──────────────────────────────────────────────────
def _cookie_inventory_section(data: dict) -> str:
    """Full cookie attribute table — follows the Cookie Security section."""
    cookies_data = data.get("cookies")
    if not cookies_data:
        return ""

    cookies = cookies_data.get("cookies") or []
    if not cookies:
        return ""  # Cookie Security section already shows the no-cookies message

    n = len(cookies)
    header_label = f"{n} cookie{'s' if n != 1 else ''}"

    _IC1, _IC2, _IC3, _IC4, _IC5, _IC6 = "22%", "18%", "10%", "10%", "13%", "27%"

    def _yn(ok: bool) -> str:
        color, mark = ("#16a34a", "✓") if ok else ("#dc2626", "✗")
        return f'<span style="color:{color};font-size:9pt;font-weight:700">{mark}</span>'

    rows = []
    for c in cookies:
        samesite_raw = c.get("samesite")
        if samesite_raw is None:
            ss_text, ss_color = "Not set", "#d97706"
        elif samesite_raw.lower() == "none":
            ss_text, ss_color = "None", "#d97706"
        else:
            ss_text, ss_color = samesite_raw.title(), "#16a34a"

        expires_raw = c.get("expires")
        expires_text = expires_raw if expires_raw else "Session"

        rows.append(f"""
        <tr class="avoid-break">
          <td style="width:{_IC1}" class="mono">{_e(c.get("name", "?"))}</td>
          <td style="width:{_IC2};font-size:8.5pt;color:#475569">{_e(c.get("domain") or "—")}</td>
          <td style="width:{_IC3};text-align:center">{_yn(bool(c.get("secure")))}</td>
          <td style="width:{_IC4};text-align:center">{_yn(bool(c.get("httponly")))}</td>
          <td style="width:{_IC5};font-size:8.5pt;font-weight:600;color:{ss_color}">{_e(ss_text)}</td>
          <td style="width:{_IC6};font-size:7.5pt;color:#64748b;word-break:break-word">{_e(expires_text)}</td>
        </tr>""")

    return f"""
<div {_FLOW_DIV}>
{_section_hdr("Cookie Inventory", header_label, "#475569")}
<table style="table-layout:fixed;width:100%">
  <tr style="page-break-inside:avoid;page-break-after:avoid">
    <th style="width:{_IC1}">Name</th>
    <th style="width:{_IC2}">Domain</th>
    <th style="width:{_IC3};text-align:center">Secure</th>
    <th style="width:{_IC4};text-align:center">HttpOnly</th>
    <th style="width:{_IC5}">SameSite</th>
    <th style="width:{_IC6}">Expires</th>
  </tr>
  {"".join(rows)}
</table>
</div>"""


# ── Watermark ────────────────────────────────────────────────────────────────
def _watermark(buyer_name: str) -> tuple[str, str]:
    """Return (extra_css, html_element) for the per-page watermark, or ('', '')."""
    if not buyer_name:
        return "", ""
    safe = _html_mod.escape(buyer_name[:80].strip())
    css = """
.watermark {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%) rotate(-45deg);
    font-size: 36pt;
    font-family: 'DM Sans', Arial, sans-serif;
    font-weight: 600;
    color: rgba(0, 0, 0, 0.12);
    white-space: nowrap;
    letter-spacing: 3px;
}
"""
    html = f'<div class="watermark">Prepared for {safe}</div>'
    return css, html


# ── Assembly ──────────────────────────────────────────────────────────────────
def _build_html(data: dict, buyer_name: str = "") -> str:
    sections = [
        _cover(data),
        _executive_summary(data),
        _detected_technologies_section(data),
        _headers_section(data),
        _tls_section(data),
        _dns_section(data),
        _cookies_section(data),
        _cookie_inventory_section(data),
        _cross_origin_section(data),
        _recommendations_section(data),
    ]
    body = "\n".join(s for s in sections if s)
    wm_css, wm_html = _watermark(buyer_name)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecureScanr — Security Assessment</title>
  <style>{_css()}{wm_css}</style>
</head>
<body>
{wm_html}
{body}
</body>
</html>"""


# ── Public API ────────────────────────────────────────────────────────────────
def generate_pdf(scan_result: dict, buyer_name: str = "") -> bytes:
    """Generate a white, professional PDF security report. Returns raw PDF bytes."""
    html_str = _build_html(scan_result, buyer_name)
    return HTML(string=html_str).write_pdf()
