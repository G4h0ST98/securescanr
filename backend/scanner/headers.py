import re
import requests
from urllib.parse import urlparse, urlunparse

REQUEST_TIMEOUT = 10
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

HEADER_DEFINITIONS = {
    "Content-Security-Policy": {
        "deduction": 20,
        "explanation": (
            "Content Security Policy (CSP) tells the browser which sources of "
            "content (scripts, images, styles) are allowed to load on your page. "
            "Without it, attackers can inject malicious scripts via XSS attacks."
        ),
        "business_impact": (
            "A successful XSS attack lets attackers steal session tokens, log keystrokes, "
            "redirect users, and exfiltrate data — all invisibly in the background."
        ),
        "fix": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';",
        "severity": "critical",
    },
    "Strict-Transport-Security": {
        "deduction": 20,
        "explanation": (
            "HTTP Strict Transport Security (HSTS) forces browsers to always use "
            "HTTPS when connecting to your site, preventing protocol-downgrade attacks "
            "and cookie hijacking. A max-age of at least 6 months (15768000 seconds) is recommended."
        ),
        "business_impact": (
            "Without HSTS, a network attacker can intercept credentials and session cookies "
            "before the browser finishes negotiating an HTTPS connection."
        ),
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "severity": "critical",
        "min_max_age": 15768000,
    },
    "X-Frame-Options": {
        "deduction": 10,
        "explanation": (
            "X-Frame-Options prevents your page from being embedded in an <iframe> "
            "on another site, blocking clickjacking attacks where users are tricked "
            "into clicking hidden elements."
        ),
        "business_impact": (
            "Clickjacking lets attackers invisibly overlay your page and capture user clicks — "
            "stealing authorisations, payments, and account actions without the user realising."
        ),
        "fix": "X-Frame-Options: SAMEORIGIN",
        "severity": "important",
        "valid_values": ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "deduction": 10,
        "explanation": (
            "X-Content-Type-Options with the value 'nosniff' stops browsers from "
            "guessing (sniffing) the content type of a response, which can allow "
            "attackers to trick browsers into executing files as a different type."
        ),
        "business_impact": (
            "Browsers may execute uploaded images or text files as scripts, turning a "
            "file-upload feature into a remote code execution vector."
        ),
        "fix": "X-Content-Type-Options: nosniff",
        "severity": "important",
        "required_value": "nosniff",
    },
    "Referrer-Policy": {
        "deduction": 5,
        "explanation": (
            "Referrer-Policy controls how much referrer information is included with "
            "requests. Without it, the full URL of your page (including sensitive query "
            "parameters) may leak to third-party sites."
        ),
        "business_impact": (
            "Full page URLs — including session tokens or internal paths in query strings — "
            "leak to every analytics or ad service your site loads."
        ),
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
        "severity": "minor",
        "safe_values": [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ],
    },
    "Permissions-Policy": {
        "deduction": 5,
        "explanation": (
            "Permissions-Policy (formerly Feature-Policy) lets you control which "
            "browser features and APIs (camera, microphone, geolocation) can be used "
            "on your page and in embedded iframes, reducing your attack surface."
        ),
        "business_impact": (
            "Third-party scripts embedded on your page can silently access the device "
            "camera, microphone, or location without any user awareness."
        ),
        "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "severity": "minor",
    },
}

_VERSION_RE = re.compile(r"\d+\.\d+")

_SEVERITY_DOWNGRADE = {"critical": "important", "important": "minor", "minor": "minor"}


def _effective_severity(base: str, status: str) -> str:
    """Return a downgraded severity for weak/warn findings (present but misconfigured)."""
    if status in ("weak", "warn"):
        return _SEVERITY_DOWNGRADE.get(base, base)
    return base


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _check_hsts(value: str, min_max_age: int) -> tuple[bool, str]:
    for part in value.lower().split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                age = int(part.split("=", 1)[1].strip())
                if age >= min_max_age:
                    return True, ""
                return False, f"max-age={age} is too short (minimum recommended: {min_max_age})"
            except ValueError:
                return False, "max-age value is not a valid integer"
    return False, "max-age directive is missing"


def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    """Split a CSP string into {directive_name: [sources]} mapping (all lowercased)."""
    directives: dict[str, list[str]] = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def _check_csp_quality(value: str) -> tuple[str, int, str | None]:
    """
    Evaluate a present CSP value for common weaknesses.
    Returns (status, deduction, note).
    """
    directives = _parse_csp_directives(value)
    # script-src takes precedence; fall back to default-src if absent
    script_sources = directives.get("script-src") or directives.get("default-src", [])

    if "'unsafe-inline'" in script_sources or "'unsafe-eval'" in script_sources:
        return (
            "warn",
            10,
            "CSP present but weakened by unsafe-inline or unsafe-eval — XSS protection is bypassed",
        )
    if "*" in script_sources:
        return (
            "warn",
            10,
            "CSP present but wildcard source allows any script — effectively no XSS protection",
        )
    return "good", 0, None


def _csp_has_frame_ancestors(raw_headers: dict) -> bool:
    """Return True if a CSP header is present and contains a frame-ancestors directive."""
    csp = raw_headers.get("Content-Security-Policy") or raw_headers.get("content-security-policy", "")
    if not csp:
        return False
    directives = _parse_csp_directives(csp)
    return "frame-ancestors" in directives


def _evaluate_header(name: str, raw_headers: dict) -> dict:
    defn = HEADER_DEFINITIONS[name]
    value = raw_headers.get(name) or raw_headers.get(name.lower())

    if value is None:
        # Fix 4: X-Frame-Options missing — accept CSP frame-ancestors as equivalent
        if name == "X-Frame-Options" and _csp_has_frame_ancestors(raw_headers):
            return {
                "present": False,
                "value": None,
                "status": "good",
                "explanation": defn["explanation"],
                "fix": None,
                "severity": defn["severity"],
                "deduction": 0,
                "note": (
                    "X-Frame-Options not set but CSP frame-ancestors provides "
                    "equivalent clickjacking protection"
                ),
            }
        return {
            "present": False,
            "value": None,
            "status": "missing",
            "explanation": defn["explanation"],
            "business_impact": defn.get("business_impact", ""),
            "fix": defn["fix"],
            "severity": defn["severity"],
            "deduction": defn["deduction"],
        }

    status = "good"
    fix = None
    deduction = 0
    note = None

    if name == "Content-Security-Policy":
        status, deduction, note = _check_csp_quality(value)
        if status == "warn":
            fix = defn["fix"]

    elif name == "Strict-Transport-Security":
        valid, reason = _check_hsts(value, defn["min_max_age"])
        if not valid:
            status = "weak"
            note = reason
            fix = defn["fix"]
            deduction = defn["deduction"] // 2

    elif name == "X-Frame-Options":
        if value.upper() not in defn["valid_values"]:
            status = "weak"
            note = f"Value '{value}' is non-standard. Use DENY or SAMEORIGIN."
            fix = defn["fix"]
            deduction = defn["deduction"] // 2

    elif name == "X-Content-Type-Options":
        if value.lower().strip() != defn["required_value"]:
            status = "weak"
            note = f"Value should be 'nosniff', got '{value}'."
            fix = defn["fix"]
            deduction = defn["deduction"] // 2

    elif name == "Referrer-Policy":
        if value.lower().strip() not in defn["safe_values"]:
            status = "weak"
            note = f"Value '{value}' may expose referrer information. Use a stricter policy."
            fix = defn["fix"]
            deduction = defn["deduction"] // 2

    result = {
        "present": True,
        "value": value,
        "status": status,
        "explanation": defn["explanation"],
        "business_impact": defn.get("business_impact", "") if status != "good" else "",
        "fix": fix,
        "severity": _effective_severity(defn["severity"], status),
        "deduction": deduction,
    }
    if note:
        result["note"] = note
    return result


def _check_cors(raw_headers: dict) -> dict:
    """Check Access-Control-Allow-Origin for wildcard misconfiguration."""
    acao = (
        raw_headers.get("Access-Control-Allow-Origin")
        or raw_headers.get("access-control-allow-origin", "")
    ).strip()

    if not acao:
        return {
            "present": False,
            "value": None,
            "status": "missing",
            "explanation": (
                "No Access-Control-Allow-Origin header found. "
                "This is normal for sites not serving cross-origin API requests."
            ),
            "fix": None,
            "deduction": 0,
        }

    if acao == "*":
        # Only flag on HTML pages. Non-HTML endpoints (SVG badges, JSON APIs, images)
        # legitimately use CORS: * for public cross-origin embedding — not a security risk.
        content_type = (
            raw_headers.get("Content-Type")
            or raw_headers.get("content-type", "")
        ).lower()
        is_html_response = not content_type or "text/html" in content_type
        if not is_html_response:
            return {
                "present": True,
                "value": acao,
                "status": "good",
                "explanation": (
                    "CORS wildcard on a non-HTML response — expected for public "
                    "embed endpoints (SVG, JSON, images). Not a security risk."
                ),
                "fix": None,
                "deduction": 0,
            }
        return {
            "present": True,
            "value": acao,
            "status": "bad",
            "explanation": (
                "Access-Control-Allow-Origin is set to wildcard (*), allowing any origin "
                "to make cross-origin requests and read responses. This creates a CSRF "
                "risk for any authenticated endpoints on this domain."
            ),
            "business_impact": (
                "Any website can issue credentialed cross-origin requests to your API and "
                "read the response — enabling silent data theft from logged-in users."
            ),
            "fix": "Access-Control-Allow-Origin: https://yourdomain.com",
            "deduction": 5,
        }

    return {
        "present": True,
        "value": acao,
        "status": "good",
        "explanation": "CORS policy is restricted — only specific origins are permitted.",
        "fix": None,
        "deduction": 0,
    }


def _check_server_fingerprint(raw_headers: dict) -> dict:
    """Check Server and X-Powered-By headers for technology/version disclosure."""
    server  = (raw_headers.get("Server")       or raw_headers.get("server",       "")).strip() or None
    powered = (raw_headers.get("X-Powered-By") or raw_headers.get("x-powered-by", "")).strip() or None

    total_deduction = 0

    if server and _VERSION_RE.search(server):
        server_result = {
            "present": True,
            "value": server,
            "status": "warn",
            "explanation": (
                "Server header reveals software name and version. Attackers can "
                "look up known CVEs for this exact version and target unpatched vulnerabilities."
            ),
            "business_impact": (
                "Attackers can look up public CVE databases for this exact version and "
                "run targeted exploits before your next patch window."
            ),
            "fix": (
                "Configure your web server to suppress or genericise the Server header. "
                "e.g. nginx: server_tokens off;  Apache: ServerTokens Prod"
            ),
            "deduction": 3,
        }
        total_deduction += 3
    elif server:
        server_result = {
            "present": True,
            "value": server,
            "status": "ok",
            "explanation": "Server header is present but does not reveal a specific version.",
            "fix": None,
            "deduction": 0,
        }
    else:
        server_result = {
            "present": False,
            "value": None,
            "status": "good",
            "explanation": "Server header is not present — no software information disclosed.",
            "fix": None,
            "deduction": 0,
        }

    if powered:
        powered_result = {
            "present": True,
            "value": powered,
            "status": "warn",
            "explanation": (
                "X-Powered-By discloses the server-side technology stack. "
                "Attackers use this to fingerprint your framework and target known exploits."
            ),
            "business_impact": (
                "Framework version disclosure enables attackers to select known exploits "
                "and probe default file paths specific to your technology stack."
            ),
            "fix": (
                "Remove X-Powered-By entirely. "
                "PHP: expose_php = Off in php.ini. "
                "Express.js: app.disable('x-powered-by'). "
                "ASP.NET: <httpRuntime enableVersionHeader='false'>"
            ),
            "deduction": 3,
        }
        total_deduction += 3
    else:
        powered_result = {
            "present": False,
            "value": None,
            "status": "good",
            "explanation": "X-Powered-By header is not present — no framework information disclosed.",
            "fix": None,
            "deduction": 0,
        }

    return {
        "server": server_result,
        "x_powered_by": powered_result,
        "total_deduction": total_deduction,
    }


def _check_security_txt(response_url: str) -> dict:
    """
    Check if /.well-known/security.txt (or /security.txt) exists and contains a Contact field.
    Returns an informational result — deduction is always 0.
    """
    parsed = urlparse(response_url)
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = requests.get(
                base + path,
                timeout=5,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                verify=True,
            )
            if r.status_code == 200 and "Contact:" in r.text:
                return {
                    "present": True,
                    "url": base + path,
                    "status": "good",
                    "explanation": (
                        "security.txt is present and contains a Contact field, making it easy "
                        "for security researchers to report vulnerabilities responsibly."
                    ),
                    "deduction": 0,
                }
        except Exception:
            pass

    return {
        "present": False,
        "url": None,
        "status": "missing",
        "explanation": (
            "No security.txt found at /.well-known/security.txt or /security.txt. "
            "RFC 9116 security.txt files tell security researchers how to report "
            "vulnerabilities responsibly."
        ),
        "fix": (
            "Create /.well-known/security.txt with:\n"
            "Contact: mailto:security@yourdomain.com\n"
            "Expires: 2027-01-01T00:00:00.000Z"
        ),
        "deduction": 0,
    }


def analyze_headers(response: requests.Response) -> dict:
    """Evaluate security headers from an existing requests.Response object."""
    raw_headers = dict(response.headers)
    results = {}
    total_deduction = 0
    issues = {"critical": 0, "important": 0, "minor": 0}

    for header_name in HEADER_DEFINITIONS:
        result = _evaluate_header(header_name, raw_headers)
        results[header_name] = result
        total_deduction += result["deduction"]
        if result["status"] in ("missing", "weak", "warn"):
            issues[result["severity"]] += 1

    n = sum(issues.values())
    if n == 0:
        summary = "All security headers are present and configured correctly."
    else:
        parts = [
            f"{issues[k]} {k}"
            for k in ("critical", "important", "minor")
            if issues[k]
        ]
        summary = f"{n} issue{'s' if n > 1 else ''} found ({', '.join(parts)})."

    cors_result   = _check_cors(raw_headers)
    fp_result     = _check_server_fingerprint(raw_headers)
    security_txt  = _check_security_txt(response.url)

    # If the response arrived from a different hostname than originally requested
    # (cross-domain redirect, e.g. securescanr.com → api.securescanr.com/api/badge),
    # the CORS policy belongs to that other domain — suppress the finding.
    if cors_result.get("deduction", 0) > 0 and response.history:
        scanned_host = urlparse(response.history[0].url).hostname or ""
        final_host   = urlparse(response.url).hostname or ""
        if scanned_host and final_host and scanned_host != final_host:
            cors_result = {
                **cors_result,
                "status":      "good",
                "deduction":   0,
                "fix":         None,
                "explanation": (
                    f"CORS wildcard is set on {final_host}, which is a different "
                    f"hostname from the scanned domain ({scanned_host}). "
                    "Not scored against the scanned domain."
                ),
            }

    total_deduction += cors_result["deduction"] + fp_result["total_deduction"]

    return {
        "headers":            results,
        "total_deduction":    total_deduction,
        "summary":            summary,
        "cors":               cors_result,
        "server_fingerprint": fp_result,
        "security_txt":       security_txt,
    }


def fetch_url(url: str) -> requests.Response:
    """
    Fetch url and return the Response.
    Raises ValueError on unsupported scheme, requests.RequestException on failure.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{parsed.scheme}'. Only http/https allowed.")

    try:
        return requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            verify=True,
        )
    except requests.exceptions.SSLError as exc:
        raise requests.RequestException(f"TLS/SSL error connecting to {url}: {exc}") from exc
    except requests.exceptions.ConnectionError as exc:
        raise requests.RequestException(f"Could not connect to {url}: {exc}") from exc
    except requests.exceptions.Timeout:
        raise requests.RequestException(f"Request to {url} timed out after {REQUEST_TIMEOUT}s")


def scan_headers(url: str) -> dict:
    """Convenience wrapper: fetch url then analyze headers. Used for standalone testing."""
    response = fetch_url(url)
    result = analyze_headers(response)
    result["status_code"] = response.status_code
    result["final_url"] = response.url
    return result
