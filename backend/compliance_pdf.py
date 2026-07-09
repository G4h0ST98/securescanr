"""
Compliance PDF generation for SecureScanr.
Produces a professional A4 white-background PDF using ReportLab Platypus.

Public API:
    evaluate_compliance(scan_result: dict) -> dict
    generate_compliance_pdf(scan_result: dict) -> bytes
        scan_result must contain 'domain' plus the real scanner keys:
        headers_result, tls_result, dns_result, cookies_result,
        cross_origin_result, page_result.
"""

import html as _html
import io
import json
import os
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Load mapping once ──────────────────────────────────────────────────────────

_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "compliance_mapping.json")
with open(_MAPPING_PATH, encoding="utf-8") as _f:
    _MAPPING: dict = json.load(_f)

# ── Colour palette ─────────────────────────────────────────────────────────────

_TEAL       = colors.HexColor("#00d4aa")        # brand teal (cover, links)
_TEAL_SECT  = colors.HexColor("#00c9a7")        # slightly deeper teal for section headers
_GREEN      = colors.HexColor("#16a34a")
_AMBER      = colors.HexColor("#d97706")
_RED        = colors.HexColor("#dc2626")
_BLACK      = colors.HexColor("#111318")
_DARK_GRAY  = colors.HexColor("#374151")
_MID_GRAY   = colors.HexColor("#6b7280")
_LIGHT_GRAY = colors.HexColor("#f3f4f6")
_WHITE      = colors.white

_PASS_BG    = colors.HexColor("#f0fdf4")        # light green tint
_FAIL_BG    = colors.HexColor("#fef2f2")        # light red tint
_WARN_BG    = colors.HexColor("#fffbeb")        # light amber tint

_STATUS_COLORS = {"green": _GREEN, "amber": _AMBER, "red": _RED}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _truncate_sentences(text: str, max_sentences: int = 2) -> str:
    """Return at most `max_sentences` sentences from `text`, HTML-escaped for ReportLab."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return _html.escape(" ".join(sentences[:max_sentences]))


# ── Styles ─────────────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    getSampleStyleSheet()   # initialise base styles (required by reportlab)
    s = {}

    def _p(name, **kw):
        s[name] = ParagraphStyle(name, **kw)

    # Cover
    _p("cover_title",
       fontName="Helvetica-Bold", fontSize=22, leading=28,
       textColor=_BLACK, alignment=TA_CENTER, spaceAfter=10)
    _p("cover_subtitle",
       fontName="Helvetica", fontSize=14, leading=20,
       textColor=_DARK_GRAY, alignment=TA_CENTER, spaceAfter=8)
    _p("cover_domain",
       fontName="Helvetica-Bold", fontSize=16, leading=22,
       textColor=_TEAL, alignment=TA_CENTER, spaceAfter=6)
    _p("cover_date",
       fontName="Helvetica", fontSize=11, leading=16,
       textColor=_MID_GRAY, alignment=TA_CENTER, spaceAfter=4)
    _p("cover_confidential",
       fontName="Helvetica-Oblique", fontSize=9, leading=14,
       textColor=_MID_GRAY, alignment=TA_CENTER, spaceAfter=0)

    # Section headers
    _p("section_header",
       fontName="Helvetica-Bold", fontSize=14, leading=20,
       textColor=_BLACK, spaceBefore=20, spaceAfter=6)
    # Teal-accented header used for each framework section
    _p("section_header_fw",
       fontName="Helvetica-Bold", fontSize=14, leading=20,
       textColor=_TEAL_SECT, spaceBefore=16, spaceAfter=6)

    _p("subsection_header",
       fontName="Helvetica-Bold", fontSize=11, leading=16,
       textColor=_DARK_GRAY, spaceBefore=12, spaceAfter=4)

    # Body text
    _p("body",
       fontName="Helvetica", fontSize=11, leading=16,
       textColor=_DARK_GRAY, spaceBefore=0, spaceAfter=12)
    _p("body_small",
       fontName="Helvetica", fontSize=9, leading=13,
       textColor=_DARK_GRAY, spaceBefore=0, spaceAfter=4)
    _p("body_8",
       fontName="Helvetica", fontSize=8, leading=12,
       textColor=_DARK_GRAY, spaceBefore=0, spaceAfter=2)

    # Table styles
    _p("table_header",
       fontName="Helvetica-Bold", fontSize=9, leading=13,
       textColor=_WHITE, alignment=TA_LEFT)
    _p("table_cell",
       fontName="Helvetica", fontSize=9, leading=13,
       textColor=_DARK_GRAY, alignment=TA_LEFT)
    _p("table_cell_center",
       fontName="Helvetica", fontSize=9, leading=13,
       textColor=_DARK_GRAY, alignment=TA_CENTER)
    _p("table_header_8",
       fontName="Helvetica-Bold", fontSize=8, leading=12,
       textColor=_WHITE, alignment=TA_LEFT)
    _p("table_cell_8",
       fontName="Helvetica", fontSize=8, leading=12,
       textColor=_DARK_GRAY, alignment=TA_LEFT)

    _p("link",
       fontName="Helvetica", fontSize=9, leading=13,
       textColor=_TEAL, alignment=TA_LEFT)
    _p("footer",
       fontName="Helvetica-Oblique", fontSize=8, leading=11,
       textColor=_MID_GRAY, alignment=TA_CENTER)

    return s


# ── Check evaluation ───────────────────────────────────────────────────────────

def evaluate_check(key: str, scan_result: dict) -> tuple[bool, str]:
    """
    Evaluate a single compliance check key against the normalised scan_result.

    scan_result uses short-key format (produced by _normalize_scan_for_compliance
    in app.py, or supplied directly in tests):

    headers_result:
        csp:         {present: bool, unsafe_inline: bool, unsafe_eval: bool}
        hsts:        {present: bool}
        xfo:         {present: bool}
        xcto:        {present: bool}
        referrer:    {present: bool}
        permissions: {present: bool}
        cors:        {wildcard: bool}
        server_fingerprint: bool
    tls_result:      {valid: bool}
    dns_result:      {spf: bool, dmarc: bool, dmarc_enforced: bool,
                      caa: bool, dkim: bool, dnssec: bool}
    cookies_result:  {cookies: [...]}
    page_result:     {sri_missing: bool, mixed_content: bool}

    Returns (passed: bool, finding: str).
    """
    hr      = scan_result.get("headers_result") or {}
    tls     = scan_result.get("tls_result") or {}
    dns     = scan_result.get("dns_result") or {}
    cookies = (scan_result.get("cookies_result") or {}).get("cookies", [])
    page    = scan_result.get("page_result") or {}

    # ── TLS ──────────────────────────────────────────────────────────────────
    if key == "tls_valid":
        if not tls.get("valid"):
            return False, "HTTPS is not in use or TLS certificate is invalid/expired."
        return True, "TLS certificate is valid and not expired."

    # ── Headers ───────────────────────────────────────────────────────────────
    if key == "hsts_present":
        if not hr.get("hsts", {}).get("present"):
            return False, "Strict-Transport-Security header is missing."
        return True, "Strict-Transport-Security header is present and configured."

    if key == "csp_present":
        if not hr.get("csp", {}).get("present"):
            return False, "Content-Security-Policy header is missing."
        return True, "Content-Security-Policy header is present."

    if key == "csp_no_unsafe":
        csp = hr.get("csp", {})
        if not csp.get("present"):
            return False, "Content-Security-Policy is not set."
        if csp.get("unsafe_inline") or csp.get("unsafe_eval"):
            return False, "CSP contains 'unsafe-inline' or 'unsafe-eval', weakening XSS protection."
        return True, "CSP does not contain dangerous 'unsafe-inline' or 'unsafe-eval' directives."

    if key == "csp_frame_ancestors":
        xfo_ok = hr.get("xfo", {}).get("present", False)
        csp_ok = hr.get("csp", {}).get("present", False)
        if xfo_ok or csp_ok:
            return True, "Frame embedding restricted via X-Frame-Options or CSP frame-ancestors."
        return False, "Neither X-Frame-Options nor CSP frame-ancestors directive is set."

    if key == "xfo_present":
        xfo_ok = hr.get("xfo", {}).get("present", False)
        csp_ok = hr.get("csp", {}).get("present", False)
        if xfo_ok or csp_ok:
            return True, "Clickjacking protection is in place (X-Frame-Options or CSP frame-ancestors)."
        return False, "X-Frame-Options header is missing and no CSP frame-ancestors fallback is set."

    if key == "xcto_present":
        if not hr.get("xcto", {}).get("present"):
            return False, "X-Content-Type-Options header is missing."
        return True, "X-Content-Type-Options: nosniff is set."

    if key == "referrer_present":
        if not hr.get("referrer", {}).get("present"):
            return False, "Referrer-Policy header is missing."
        return True, "Referrer-Policy header is present."

    if key == "perms_present":
        if not hr.get("permissions", {}).get("present"):
            return False, "Permissions-Policy header is missing."
        return True, "Permissions-Policy header is present."

    if key == "cors_no_wildcard":
        if hr.get("cors", {}).get("wildcard"):
            return False, "Access-Control-Allow-Origin is set to '*', allowing any origin to read responses."
        return True, "CORS policy does not expose a wildcard origin."

    if key == "no_server_fingerprint":
        if hr.get("server_fingerprint"):
            return False, "Server version information is exposed in response headers."
        return True, "No server version information is exposed in response headers."

    # ── Cookies ───────────────────────────────────────────────────────────────
    if key == "cookies_secure":
        if not cookies:
            return True, "No cookies were set — Secure flag check not applicable."
        bad = [c.get("name", "?") for c in cookies if not c.get("secure")]
        if bad:
            return False, f"Cookie(s) missing Secure flag: {', '.join(bad[:5])}."
        return True, "All cookies have the Secure flag set."

    if key == "cookies_httponly":
        if not cookies:
            return True, "No cookies were set — HttpOnly flag check not applicable."
        bad = [c.get("name", "?") for c in cookies if not c.get("httponly")]
        if bad:
            return False, f"Cookie(s) missing HttpOnly flag: {', '.join(bad[:5])}."
        return True, "All cookies have the HttpOnly flag set."

    if key == "cookies_samesite":
        if not cookies:
            return True, "No cookies were set — SameSite check not applicable."
        bad = [c.get("name", "?") for c in cookies if not c.get("samesite")]
        if bad:
            return False, f"Cookie(s) without SameSite attribute: {', '.join(bad[:5])}."
        return True, "All cookies have the SameSite attribute set."

    # ── Page analysis ─────────────────────────────────────────────────────────
    if key == "no_mixed_content":
        if page.get("mixed_content"):
            return False, "Mixed HTTP resource(s) detected on HTTPS page."
        return True, "No mixed content detected."

    if key == "sri_present":
        if page.get("sri_missing"):
            return False, "External script/stylesheet(s) loaded without Subresource Integrity (SRI)."
        return True, "All external scripts and stylesheets have Subresource Integrity checks."

    # ── DNS ───────────────────────────────────────────────────────────────────
    if key == "spf_present":
        if not dns.get("spf"):
            return False, "SPF (Sender Policy Framework) DNS record is missing."
        return True, "SPF record is published for this domain."

    if key == "dmarc_present":
        if not dns.get("dmarc"):
            return False, "DMARC DNS record is missing."
        return True, "DMARC record is published for this domain."

    if key == "dmarc_enforced":
        if not dns.get("dmarc"):
            return False, "DMARC record is not set."
        if not dns.get("dmarc_enforced"):
            return False, "DMARC policy is p=none — not enforced (needs quarantine or reject)."
        return True, "DMARC is enforced with quarantine or reject policy."

    if key == "dns_caa_present":
        if not dns.get("caa"):
            return False, "CAA (Certification Authority Authorization) DNS records are not published."
        return True, "CAA records are published, restricting which CAs can issue certificates."

    # Fallback
    return True, "Check not applicable or data unavailable."


def evaluate_compliance(scan_result: dict) -> dict:
    """
    Evaluate the scan result against all compliance frameworks.
    Returns a nested dict keyed by framework ID.
    """
    result = {}
    for fw_key, fw in _MAPPING.items():
        requirements = []
        total        = 0
        passed_count = 0
        all_failures = []

        for req in fw["requirements"]:
            check_results = []
            req_passed    = True
            for ck in req["checks"]:
                passed, finding = evaluate_check(ck, scan_result)
                check_results.append({
                    "check_key":   ck,
                    "check_label": _CHECK_LABELS.get(ck, ck),
                    "passed":      passed,
                    "finding":     finding,
                })
                if not passed:
                    req_passed = False
                    all_failures.append({
                        "req_id":   req["id"],
                        "req_name": req["name"],
                        "framework": fw["name"],
                        "check":    _CHECK_LABELS.get(ck, ck),
                        "finding":  finding,
                        "fix":      req["fix"],
                    })

            total += 1
            if req_passed:
                passed_count += 1

            requirements.append({
                "id":          req["id"],
                "name":        req["name"],
                "description": req["description"],
                "checks":      check_results,
                "passed":      req_passed,
                "fix":         req.get("fix", ""),
            })

        failed = total - passed_count
        if failed == 0:
            status = "green"
        elif passed_count == 0:
            status = "red"
        else:
            status = "amber"

        result[fw_key] = {
            "name":         fw["name"],
            "version":      fw.get("version", ""),
            "url":          fw["url"],
            "internal_url": fw["internal_url"],
            "intro":        fw["intro"],
            "requirements": requirements,
            "total":        total,
            "passed":       passed_count,
            "failed":       failed,
            "status":       status,
            "failures":     all_failures,
        }

    return result


# Human-readable labels for check keys
_CHECK_LABELS: dict[str, str] = {
    "tls_valid":             "TLS Certificate Valid",
    "hsts_present":          "HSTS Header Present",
    "csp_present":           "Content Security Policy Present",
    "csp_no_unsafe":         "CSP No unsafe-inline / unsafe-eval",
    "csp_frame_ancestors":   "Frame Embedding Restricted",
    "xfo_present":           "X-Frame-Options Present",
    "xcto_present":          "X-Content-Type-Options Present",
    "referrer_present":      "Referrer-Policy Present",
    "perms_present":         "Permissions-Policy Present",
    "cors_no_wildcard":      "CORS No Wildcard Origin",
    "no_server_fingerprint": "Server Version Not Disclosed",
    "cookies_secure":        "Cookies Have Secure Flag",
    "cookies_httponly":      "Cookies Have HttpOnly Flag",
    "cookies_samesite":      "Cookies Have SameSite Attribute",
    "no_mixed_content":      "No Mixed HTTP Content",
    "sri_present":           "Subresource Integrity (SRI) Present",
    "spf_present":           "SPF DNS Record Present",
    "dmarc_present":         "DMARC DNS Record Present",
    "dmarc_enforced":        "DMARC Policy Enforced",
    "dns_caa_present":       "CAA DNS Records Present",
}


# ── PDF building ───────────────────────────────────────────────────────────────

def generate_compliance_pdf(scan_result: dict) -> bytes:
    """
    Generate a professional compliance PDF report.
    scan_result must contain 'domain' plus the real scanner output keys:
      headers_result, tls_result, dns_result, cookies_result, page_result.
    Calls evaluate_compliance() internally.
    Returns PDF as bytes.
    """
    domain          = scan_result.get("domain") or "unknown"
    date_str        = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    compliance_data = evaluate_compliance(scan_result)

    # Pre-compute deduplicated remediation rows + failed check keys
    # (referenced by both Assessment Summary and Remediation Plan)
    _rem_grouped: dict[tuple, dict] = {}
    _failed_check_keys: set[str] = set()
    for _fw_v in compliance_data.values():
        for _fail in _fw_v["failures"]:
            _gk = (_fail["req_id"], _fail["framework"])
            if _gk not in _rem_grouped:
                _rem_grouped[_gk] = {
                    "req_id":    _fail["req_id"],
                    "req_name":  _fail["req_name"],
                    "framework": _fail["framework"],
                    "findings":  [],
                    "fix":       _fail["fix"],
                }
            _rem_grouped[_gk]["findings"].append(_fail["finding"])
        for _req in _fw_v["requirements"]:
            for _ck in _req["checks"]:
                if not _ck["passed"]:
                    _failed_check_keys.add(_ck["check_key"])
    all_remediation = list(_rem_grouped.values())

    buf = io.BytesIO()
    S   = _build_styles()

    page_w, page_h = A4
    margin = 2.0 * cm

    def _footer(canvas, doc):
        canvas.saveState()
        # Thin teal top border above footer text
        canvas.setStrokeColor(_TEAL_SECT)
        canvas.setLineWidth(0.75)
        canvas.line(margin, 1.25 * cm, page_w - margin, 1.25 * cm)
        # Footer text
        canvas.setFont("Helvetica-Oblique", 8)
        canvas.setFillColor(_MID_GRAY)
        footer_text = (
            f"Confidential — Generated by SecureScanr  |  securescanr.com  |  {date_str}"
            f"  |  Page {doc.page}"
        )
        canvas.drawCentredString(page_w / 2, 0.65 * cm, footer_text)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=margin, rightMargin=margin,
        topMargin=margin,  bottomMargin=1.8 * cm,
        onFirstPage=_footer,
        onLaterPages=_footer,
    )

    story = []

    # ── Cover page ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3.5 * cm))

    story.append(Paragraph("SecureScanr", ParagraphStyle(
        "logo", fontName="Helvetica-Bold", fontSize=28, leading=34,
        textColor=_TEAL, alignment=TA_CENTER, spaceAfter=4,
    )))

    story.append(HRFlowable(
        width="60%", thickness=1, color=_TEAL,
        hAlign="CENTER", spaceAfter=20,
    ))

    story.append(Paragraph("Security Compliance Assessment", S["cover_title"]))

    # Teal rule under the cover title
    story.append(HRFlowable(
        width="50%", thickness=2, color=_TEAL_SECT,
        hAlign="CENTER", spaceAfter=18,
    ))

    story.append(Paragraph(domain, S["cover_domain"]))
    story.append(Paragraph(f"Scan Date: {date_str}", S["cover_date"]))
    story.append(Spacer(1, 1.5 * cm))

    # Framework overview on cover
    fw_names = [v["name"] for v in compliance_data.values()]
    story.append(Paragraph(
        "Frameworks assessed in this report:",
        ParagraphStyle("fw_label", fontName="Helvetica-Bold", fontSize=11,
                       textColor=_DARK_GRAY, alignment=TA_CENTER, spaceAfter=6),
    ))
    for name in fw_names:
        story.append(Paragraph(f"• {name}", ParagraphStyle(
            "fw_item", fontName="Helvetica", fontSize=10, textColor=_DARK_GRAY,
            alignment=TA_CENTER, spaceAfter=3,
        )))

    story.append(Spacer(1, 2.5 * cm))
    story.append(HRFlowable(width="80%", thickness=0.5, color=_LIGHT_GRAY,
                             hAlign="CENTER", spaceAfter=16))
    story.append(Paragraph(
        "CONFIDENTIAL — This report is intended solely for the organisation that commissioned it. "
        "Do not distribute without authorisation.",
        S["cover_confidential"],
    ))
    story.append(PageBreak())

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["section_header"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_LIGHT_GRAY,
                             hAlign="LEFT", spaceAfter=10))
    story.append(Paragraph(
        f"This report assesses the security posture of <b>{domain}</b> against four major compliance "
        "frameworks. Each framework maps specific technical controls to the corresponding SecureScanr "
        "scan findings. Requirements are marked <b><font color='#16a34a'>PASS</font></b> when all "
        "associated checks succeed, or <b><font color='#dc2626'>FAIL</font></b> when one or more "
        "checks are not met.",
        S["body"],
    ))

    # Build exec table with per-row status bg tints
    exec_data = [[
        Paragraph("Framework",      S["table_header"]),
        Paragraph("Requirements",   S["table_header"]),
        Paragraph("Passed",         S["table_header"]),
        Paragraph("Failed",         S["table_header"]),
        Paragraph("Overall Status", S["table_header"]),
    ]]
    exec_bg_styles = []
    for i, (fw_key, fw) in enumerate(compliance_data.items()):
        row_idx      = i + 1
        status_color = _STATUS_COLORS.get(fw["status"], _AMBER)
        status_label = {
            "green": "✓ COMPLIANT",
            "amber": "⚠ PARTIAL",
            "red":   "✗ NON-COMPLIANT",
        }[fw["status"]]
        # Row background tint based on status
        row_bg = {"green": _PASS_BG, "amber": _WARN_BG, "red": _FAIL_BG}[fw["status"]]
        exec_bg_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), row_bg))

        exec_data.append([
            Paragraph(fw["name"], S["table_cell"]),
            Paragraph(str(fw["total"]), S["table_cell_center"]),
            Paragraph(str(fw["passed"]), ParagraphStyle(
                f"pass_n_{i}", fontName="Helvetica-Bold", fontSize=9,
                textColor=_GREEN, alignment=TA_CENTER)),
            Paragraph(str(fw["failed"]), ParagraphStyle(
                f"fail_n_{i}", fontName="Helvetica-Bold", fontSize=9,
                textColor=_RED if fw["failed"] else _DARK_GRAY, alignment=TA_CENTER)),
            Paragraph(status_label, ParagraphStyle(
                f"status_cell_{i}", fontName="Helvetica-Bold", fontSize=9,
                textColor=status_color, alignment=TA_CENTER)),
        ])

    col_widths = [8.5 * cm, 2.8 * cm, 2.2 * cm, 2.2 * cm, 3.8 * cm]
    exec_table = Table(exec_data, colWidths=col_widths, repeatRows=1)
    exec_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), _BLACK),
        *exec_bg_styles,
        ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("LINEBELOW",    (0, 0), (-1, 0), 1, _TEAL),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(exec_table)
    story.append(PageBreak())

    # ── Per-framework sections (no page break between them) ────────────────────
    for fw_key, fw in compliance_data.items():
        # Teal-accented section header
        story.append(Paragraph(fw["name"], S["section_header_fw"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_LIGHT_GRAY,
                                 hAlign="LEFT", spaceAfter=8))

        # Links
        link_text = (
            f'Official documentation: <a href="{fw["url"]}" color="#00d4aa">{fw["url"]}</a>'
            f'  |  SecureScanr guide: <a href="{fw["internal_url"]}" color="#00d4aa">{fw["internal_url"]}</a>'
        )
        story.append(Paragraph(link_text, S["link"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph(fw["intro"], S["body"]))

        # Requirements table
        req_data = [[
            Paragraph("Req ID",        S["table_header"]),
            Paragraph("Requirement",   S["table_header"]),
            Paragraph("SecureScanr Check",S["table_header"]),
            Paragraph("Status",        S["table_header"]),
            Paragraph("Finding",       S["table_header"]),
        ]]
        row_styles = []

        for i, req in enumerate(fw["requirements"]):
            row_idx = i + 1
            bg      = _PASS_BG if req["passed"] else _FAIL_BG
            row_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg))

            status_p = Paragraph(
                "✓ PASS" if req["passed"] else "✗ FAIL",
                ParagraphStyle(
                    f"st_{fw_key}_{i}",
                    fontName="Helvetica-Bold", fontSize=9,
                    textColor=_GREEN if req["passed"] else _RED,
                    alignment=TA_CENTER,
                )
            )

            findings   = [c["finding"] for c in req["checks"] if not c["passed"]]
            find_text  = " ".join(findings) if findings else "All checks passed."
            check_names = "; ".join(c["check_label"] for c in req["checks"])

            req_data.append([
                Paragraph(req["id"],   S["table_cell"]),
                Paragraph(req["name"], S["table_cell"]),
                Paragraph(check_names, S["body_small"]),
                status_p,
                Paragraph(find_text,   S["body_small"]),
            ])

        col_w     = [1.8 * cm, 4.2 * cm, 4.5 * cm, 1.8 * cm, 5.0 * cm]
        req_table = Table(req_data, colWidths=col_w, repeatRows=1)
        req_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), _BLACK),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("LINEBELOW",     (0, 0), (-1, 0), 1, _TEAL),
            ("LEFTPADDING",   (0, 0), (-1, -1), 7),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            *row_styles,
        ]))
        story.append(req_table)
        story.append(Spacer(1, 18))
        # No PageBreak here — frameworks flow continuously

    # ── Assessment Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Assessment Summary", S["section_header_fw"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_LIGHT_GRAY,
                             hAlign="LEFT", spaceAfter=8))

    # Dynamic risk paragraph
    total_failed  = sum(fw["failed"] for fw in compliance_data.values())
    total_reqs    = sum(fw["total"]  for fw in compliance_data.values())
    risk_level    = "LOW" if total_failed <= 3 else ("MEDIUM" if total_failed <= 9 else "HIGH")
    risk_color    = {"LOW": "#16a34a", "MEDIUM": "#d97706", "HIGH": "#dc2626"}[risk_level]
    worst_fw      = max(compliance_data.values(), key=lambda f: f["failed"])
    worst_fw_name = worst_fw["name"]

    summary_para = (
        f"Based on the scan of <b>{domain}</b>, the overall risk level is "
        f"<b><font color='{risk_color}'>{risk_level}</font></b> — "
        f"{total_failed} of {total_reqs} requirements failed across all four frameworks. "
        f"The framework with the weakest compliance posture is <b>{worst_fw_name}</b> "
        f"({worst_fw['failed']} failed requirement{'s' if worst_fw['failed'] != 1 else ''}). "
    )
    if all_remediation:
        top_finding = all_remediation[0]["findings"][0]
        top_req     = all_remediation[0]["req_name"]
        summary_para += (
            f"The highest-priority finding is: <i>{top_finding}</i> "
            f"(requirement: {top_req}). "
        )
    summary_para += (
        "SecureScanr recommends addressing the items in the remediation plan below, "
        "starting with cryptographic and injection controls."
    )
    story.append(Paragraph(summary_para, S["body"]))

    # CWE mapping table — only rows where the check actually failed
    _CWE_ENTRIES = [
        ({"csp_present", "csp_no_unsafe"},
            "CWE-79",  "Improper Neutralisation of Input (XSS)"),
        ({"hsts_present"},
            "CWE-319", "Cleartext Transmission of Sensitive Information"),
        ({"xfo_present", "csp_frame_ancestors"},
            "CWE-1021","Improper Restriction of Rendered UI Layers"),
        ({"cors_no_wildcard"},
            "CWE-942", "Permissive Cross-domain Policy"),
        ({"spf_present", "dmarc_present", "dmarc_enforced"},
            "CWE-290", "Authentication Bypass by Spoofing"),
        ({"dns_caa_present"},
            "CWE-295", "Improper Certificate Validation"),
        ({"sri_present"},
            "CWE-353", "Missing Support for Integrity Check"),
        ({"perms_present"},
            "CWE-266", "Incorrect Privilege Assignment"),
    ]

    cwe_rows = []
    for check_set, cwe_id, cwe_desc in _CWE_ENTRIES:
        matched = check_set & _failed_check_keys
        if matched:
            labels = ", ".join(_CHECK_LABELS.get(ck, ck) for ck in sorted(matched))
            cwe_rows.append((labels, f"{cwe_id} — {cwe_desc}"))

    if cwe_rows:
        story.append(Spacer(1, 6))
        cwe_data = [[
            Paragraph("Finding",       S["table_header"]),
            Paragraph("CWE Reference", S["table_header"]),
        ]]
        cwe_bg = []
        for i, (finding_label, cwe_ref) in enumerate(cwe_rows):
            row_bg = _LIGHT_GRAY if i % 2 == 0 else _WHITE
            cwe_bg.append(("BACKGROUND", (0, i + 1), (-1, i + 1), row_bg))
            cwe_data.append([
                Paragraph(finding_label, S["table_cell"]),
                Paragraph(cwe_ref,       S["table_cell"]),
            ])
        col_w     = [8.0 * cm, 9.5 * cm]
        cwe_table = Table(cwe_data, colWidths=col_w, repeatRows=1)
        cwe_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), _BLACK),
            *cwe_bg,
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("LINEBELOW",     (0, 0), (-1, 0), 1, _TEAL),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(cwe_table)
    story.append(Spacer(1, 12))

    # ── Remediation Plan ───────────────────────────────────────────────────────
    story.append(PageBreak())

    story.append(Paragraph("Remediation Plan", S["section_header"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_LIGHT_GRAY,
                             hAlign="LEFT", spaceAfter=8))

    if all_remediation:
        story.append(Paragraph(
            "The following table lists all failed requirements, grouped by requirement ID. "
            "Address each item to improve your compliance posture.",
            S["body"],
        ))

        rem_data = [[
            Paragraph("Req ID",          S["table_header_8"]),
            Paragraph("Requirement",     S["table_header_8"]),
            Paragraph("Framework",       S["table_header_8"]),
            Paragraph("Finding(s)",      S["table_header_8"]),
            Paragraph("Recommended Fix", S["table_header_8"]),
        ]]
        rem_bg_styles = []

        for i, item in enumerate(all_remediation):
            row_bg = _FAIL_BG if i % 2 == 0 else _WARN_BG
            rem_bg_styles.append(("BACKGROUND", (0, i + 1), (-1, i + 1), row_bg))

            # Concatenate multiple findings (escaped) with newline separator
            findings_text = "\n".join(_html.escape(f) for f in item["findings"])
            # Truncate fix to 2 sentences (also escaped inside _truncate_sentences)
            fix_text = _truncate_sentences(item["fix"], 2)

            rem_data.append([
                Paragraph(item["req_id"],      S["table_cell_8"]),
                Paragraph(item["req_name"],    S["table_cell_8"]),
                Paragraph(item["framework"],   S["table_cell_8"]),
                Paragraph(findings_text,       S["table_cell_8"]),
                Paragraph(fix_text,            S["table_cell_8"]),
            ])

        col_w     = [1.8 * cm, 3.2 * cm, 3.2 * cm, 4.2 * cm, 5.4 * cm]
        rem_table = Table(rem_data, colWidths=col_w, repeatRows=1)
        rem_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), _BLACK),
            *rem_bg_styles,
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("LINEBELOW",     (0, 0), (-1, 0), 1, _TEAL),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(rem_table)
        story.append(Spacer(1, 12))
    else:
        story.append(Paragraph(
            "No remediation actions are required — all checks passed across all frameworks. "
            "Continue to monitor your security posture with regular scans.",
            S["body"],
        ))

    # ── Disclaimer ─────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Disclaimer", S["subsection_header"]))
    story.append(Paragraph(
        "This compliance report is generated automatically by SecureScanr (securescanr.com) based on "
        "observable HTTP/TLS/DNS characteristics of the target domain. It assesses technical "
        "web-layer controls only and does not constitute a formal audit, legal advice, or "
        "certification under any of the frameworks referenced. Compliance with PCI-DSS, GDPR, "
        "ISO 27001, or OWASP requires additional organisational, procedural, and operational "
        "controls beyond those assessed here. Consult a qualified auditor or legal counsel for "
        "formal compliance determination.",
        S["body"],
    ))

    doc.build(story)
    return buf.getvalue()
