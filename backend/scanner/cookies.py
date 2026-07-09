import requests

SAMESITE_STRONG = {"strict", "lax"}


def _parse_raw_cookie(raw: str) -> dict:
    """Parse a raw Set-Cookie header value into name and security attributes."""
    parts = [p.strip() for p in raw.split(";")]

    # First segment is always name=value (or just a name with no value)
    name = parts[0].split("=", 1)[0].strip()

    secure = False
    httponly = False
    samesite = None
    domain = None
    expires = None

    for part in parts[1:]:
        pl = part.lower().strip()
        if pl == "secure":
            secure = True
        elif pl == "httponly":
            httponly = True
        elif pl.startswith("samesite="):
            samesite = part.split("=", 1)[1].strip()
        elif pl.startswith("domain="):
            domain = part.split("=", 1)[1].strip()
        elif pl.startswith("expires="):
            expires = part.split("=", 1)[1].strip()

    return {
        "name": name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "domain": domain,
        "expires": expires,
    }


def scan_cookies(response: requests.Response) -> dict:
    """
    Evaluate security attributes of all Set-Cookie headers in response.
    Each missing Secure or HttpOnly flag deducts 5 pts per cookie.
    """
    # urllib3's HTTPHeaderDict preserves duplicate Set-Cookie headers
    raw_cookies = response.raw.headers.getlist("set-cookie")

    if not raw_cookies:
        return {
            "count": 0,
            "cookies": [],
            "total_deduction": 0,
            "summary": "No cookies were set by this page.",
        }

    cookies = []
    total_deduction = 0

    for raw in raw_cookies:
        parsed = _parse_raw_cookie(raw)
        issues = []
        deduction = 0

        if not parsed["secure"]:
            issues.append("Missing Secure flag — cookie transmitted over HTTP (interception risk)")
            deduction += 5
        if not parsed["httponly"]:
            issues.append("Missing HttpOnly flag — readable by JavaScript (XSS escalation risk)")
            deduction += 5

        samesite_val = parsed["samesite"]
        if samesite_val is None or samesite_val.lower() == "none":
            issues.append(
                "SameSite=None or Missing — cookie sent with cross-site requests "
                "(CSRF risk; informational, no score impact)"
            )

        total_deduction += deduction

        business_impact = ""
        if not parsed["secure"] and not parsed["httponly"]:
            business_impact = "Cookie can be stolen over plain HTTP and read by injected JavaScript — both network and XSS attackers can hijack this session."
        elif not parsed["secure"]:
            business_impact = "Cookie is transmitted over plain HTTP connections — an attacker on the same network can steal the session token."
        elif not parsed["httponly"]:
            business_impact = "Cookie is readable by JavaScript — a single XSS flaw anywhere on the page gives attackers this session token."

        cookie_entry = {
            "name":     parsed["name"],
            "domain":   parsed["domain"],
            "expires":  parsed["expires"],
            "secure":   parsed["secure"],
            "httponly": parsed["httponly"],
            "samesite": parsed["samesite"],
            "status":   "good" if deduction == 0 else "insecure",
            "issues":   issues,
            "business_impact": business_impact,
            "deduction": deduction,
        }
        cookies.append(cookie_entry)

    insecure = sum(1 for c in cookies if c["deduction"] > 0)
    n = len(cookies)

    if insecure == 0:
        summary = f"All {n} cookie{'s' if n != 1 else ''} have correct security attributes."
    else:
        summary = (
            f"{insecure} of {n} cookie{'s' if n != 1 else ''} "
            f"{'have' if insecure != 1 else 'has'} missing security attributes."
        )

    return {
        "count": n,
        "cookies": cookies,
        "total_deduction": total_deduction,
        "summary": summary,
    }
