from html.parser import HTMLParser
from urllib.parse import urlparse

import requests

# Tags whose URL attributes we inspect
_TAG_ATTR = {
    "script": "src",
    "img":    "src",
    "link":   "href",
    "iframe": "src",
}

# Only these tags are checked for SRI (executable/styleable content)
_SRI_TAGS = {"script", "link"}


class _PageScanner(HTMLParser):
    def __init__(self, base_scheme: str, base_host: str) -> None:
        super().__init__()
        self.base_scheme  = base_scheme
        self.base_host    = base_host
        self.mixed_content: list[str]  = []
        self.sri_missing:   list[str]  = []
        self.external_domains: set[str] = set()
        self.base_tag: dict | None      = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        tag = tag.lower()
        attr = dict(attrs)

        # Base-tag check
        if tag == "base":
            href = (attr.get("href") or "").strip()
            if href:
                self.base_tag = {"href": href}

        url_attr = _TAG_ATTR.get(tag)
        if not url_attr:
            return

        url = (attr.get(url_attr) or "").strip()
        if not url or url.startswith("data:") or url.startswith("blob:"):
            return

        parsed = urlparse(url)

        # Mixed content: http:// resource on https:// page
        if self.base_scheme == "https" and parsed.scheme == "http":
            self.mixed_content.append(url)

        # External domain tracking
        host = parsed.netloc.lower()
        if host and host != self.base_host.lower():
            self.external_domains.add(host)

            # SRI check: external executable content without integrity attribute
            if tag in _SRI_TAGS and parsed.scheme in ("http", "https"):
                if not attr.get("integrity"):
                    self.sri_missing.append(url)


def scan_page(response: requests.Response) -> dict:
    """
    Parse the HTML body of response and check for page-level security issues.
    Returns dict with mixed_content, sri, base_tag, external_deps, total_deduction.
    """
    _empty = {
        "mixed_content":  {"urls": [], "count": 0, "status": "good", "explanation": "No mixed content detected.", "deduction": 0},
        "sri":            {"missing_count": 0, "missing_urls": [], "status": "good", "explanation": "No external scripts or stylesheets without SRI.", "deduction": 0},
        "base_tag":       {"present": False, "href": None, "status": "good", "explanation": "No <base> tag found.", "deduction": 0},
        "external_deps":  {"domains": [], "count": 0, "explanation": "0 unique external domains loaded.", "deduction": 0},
        "total_deduction": 0,
    }

    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return _empty

    try:
        html = response.text
    except Exception:
        return _empty

    parsed_url  = urlparse(response.url)
    base_scheme = parsed_url.scheme
    base_host   = parsed_url.netloc

    scanner = _PageScanner(base_scheme, base_host)
    try:
        scanner.feed(html)
    except Exception:
        pass

    # Deduplicate while preserving order
    mixed_urls  = list(dict.fromkeys(scanner.mixed_content))
    sri_missing = list(dict.fromkeys(scanner.sri_missing))

    mixed_deduction = 2 if mixed_urls  else 0
    sri_deduction   = 2 if sri_missing else 0
    base_deduction  = 2 if scanner.base_tag else 0
    total_deduction = mixed_deduction + sri_deduction + base_deduction

    ext_domains = sorted(scanner.external_domains)
    ext_count   = len(ext_domains)

    return {
        "mixed_content": {
            "urls":   mixed_urls[:10],
            "count":  len(mixed_urls),
            "status": "warn" if mixed_urls else "good",
            "explanation": (
                f"{len(mixed_urls)} HTTP resource{'s' if len(mixed_urls) != 1 else ''} loaded on an HTTPS page. "
                "Browsers block or warn on mixed content, and unblocked resources can be intercepted."
                if mixed_urls else
                "No mixed content detected — all resources are loaded over HTTPS."
            ),
            "deduction": mixed_deduction,
        },
        "sri": {
            "missing_count": len(sri_missing),
            "missing_urls":  sri_missing[:10],
            "status": "warn" if sri_missing else "good",
            "explanation": (
                f"{len(sri_missing)} external script/stylesheet{' is' if len(sri_missing) == 1 else 's are'} "
                "loaded without Subresource Integrity (SRI) checks. "
                "An attacker who compromises the CDN could inject malicious code."
                if sri_missing else
                "All external scripts and stylesheets include Subresource Integrity checks, or none are loaded externally."
            ),
            "deduction": sri_deduction,
        },
        "base_tag": {
            "present": scanner.base_tag is not None,
            "href":    (scanner.base_tag or {}).get("href"),
            "status":  "warn" if scanner.base_tag else "good",
            "explanation": (
                "A <base> tag is present. If an attacker can inject arbitrary HTML, they can "
                "override the base URL and redirect all relative links to a malicious domain "
                "(base tag hijacking)."
                if scanner.base_tag else
                "No <base> tag found."
            ),
            "deduction": base_deduction,
        },
        "external_deps": {
            "domains":     ext_domains[:20],
            "count":       ext_count,
            "explanation": (
                f"{ext_count} unique external domain{'s' if ext_count != 1 else ''} "
                "loaded by this page."
            ),
            "deduction": 0,
        },
        "total_deduction": total_deduction,
    }
