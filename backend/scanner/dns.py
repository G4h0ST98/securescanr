import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor

DNS_LIFETIME = 5  # seconds — per-lookup cap (dnspython retries within this budget)

# SPF 'all' mechanism → policy label
_SPF_ALL_LABELS = {
    "+all": "pass_all",
    "?all": "neutral",
    "~all": "softfail",
    "-all": "hardfail",
}

# DMARC policy → extra deduction (on top of base 0 for presence)
_DMARC_POLICY_DEDUCTIONS = {
    "none": 3,          # monitoring only — weak
    "quarantine": 0,
    "reject": 0,
}

_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "k1", "s1", "s2",
    "mail", "email", "default", "sendgrid", "dkim", "smtp",
]

# Two-label TLDs where the registered domain has 3 parts (e.g. bbc.co.uk)
_TWO_LABEL_TLDS = {
    "co.uk", "co.in", "co.jp", "co.nz", "co.za", "co.au", "co.ke",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.ar",
    "net.au", "org.au", "gov.au", "edu.au",
    "org.uk", "gov.uk", "ac.uk", "me.uk",
    "ne.jp", "or.jp", "ac.jp",
}


def _apex_domain(domain: str) -> str:
    """Strip subdomains and return the registrable apex domain.

    www.walmart.com  → walmart.com
    shop.walmart.com → walmart.com
    m.bbc.co.uk      → bbc.co.uk
    walmart.com      → walmart.com  (unchanged)
    """
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return domain
    two_label = ".".join(parts[-2:])
    if two_label in _TWO_LABEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _resolve_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=DNS_LIFETIME)
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
            dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def _resolve_type(name: str, rdtype: str) -> list:
    """Resolve any DNS record type. Returns list of rdata objects, empty on failure."""
    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=DNS_LIFETIME)
        return list(answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
            dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def _scan_spf(domain: str) -> dict:
    records = [r for r in _resolve_txt(domain) if r.startswith("v=spf1")]

    if not records:
        return {
            "present": False,
            "record": None,
            "policy": None,
            "policy_label": None,
            "status": "missing",
            "explanation": (
                "No SPF record found. SPF (Sender Policy Framework) specifies which mail "
                "servers are authorised to send email for your domain, preventing spoofing."
            ),
            "business_impact": (
                "Anyone can forge your From address and send convincing phishing emails that "
                "appear to come from your domain, harming your brand and your users."
            ),
            "fix": f"v=spf1 include:_spf.yourmailprovider.com -all  (add as TXT record on {domain})",
            "deduction": 3,
        }

    if len(records) > 1:
        return {
            "present": True,
            "record": records[0],
            "policy": None,
            "policy_label": "invalid",
            "status": "invalid",
            "explanation": "Multiple SPF records found — this is invalid per RFC 7208 and breaks email delivery.",
            "business_impact": (
                "Multiple SPF records break email authentication — legitimate emails may fail "
                "SPF while spoofed ones pass, making your domain trivially impersonatable."
            ),
            "fix": f"Keep only one SPF TXT record on {domain}.",
            "deduction": 3,
        }

    record = records[0]
    all_mechanism = next(
        (p for p in record.lower().split() if p.endswith("all")), None
    )
    policy_label = _SPF_ALL_LABELS.get(all_mechanism, "unknown") if all_mechanism else "unknown"
    is_weak = all_mechanism in ("+all", "?all")

    return {
        "present": True,
        "record": record,
        "policy": all_mechanism,
        "policy_label": policy_label,
        "status": "weak" if is_weak else "good",
        "explanation": "SPF record controls which servers may send email as your domain.",
        "business_impact": (
            "+all or ?all allows any server in the world to pass SPF checks, making "
            "your domain trivially spoofable for phishing campaigns."
        ) if is_weak else "",
        "fix": (
            f"v=spf1 include:_spf.yourmailprovider.com -all  (replace on {domain})"
            if is_weak else None
        ),
        "deduction": 3 if is_weak else 0,
    }


def _scan_dmarc(domain: str) -> dict:
    records = [r for r in _resolve_txt(f"_dmarc.{domain}") if r.startswith("v=DMARC1")]

    if not records:
        return {
            "present": False,
            "record": None,
            "policy": None,
            "policy_strength": None,
            "status": "missing",
            "explanation": (
                "No DMARC record found. DMARC (Domain-based Message Authentication, Reporting "
                "and Conformance) builds on SPF and DKIM to block phishing emails that spoof "
                "your domain."
            ),
            "business_impact": (
                "Without DMARC, mail providers have no enforcement policy for spoofed emails — "
                "phishing messages impersonating your domain land in inboxes unchallenged."
            ),
            "fix": (
                f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; pct=100"
                f"  (add as TXT record on _dmarc.{domain})"
            ),
            "deduction": 5,
        }

    record = records[0]
    policy = None
    for tag in record.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("p="):
            policy = tag.split("=", 1)[1].strip().lower()
            break

    extra_deduction = _DMARC_POLICY_DEDUCTIONS.get(policy, 5) if policy else 5

    if policy == "none":
        policy_strength = "weak"
        fix = (
            f"Update to p=reject or p=quarantine: "
            f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; pct=100"
        )
    elif policy == "quarantine":
        policy_strength = "medium"
        fix = None
    elif policy == "reject":
        policy_strength = "strong"
        fix = None
    else:
        policy_strength = "unknown"
        fix = f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; pct=100  (update on _dmarc.{domain})"

    return {
        "present": True,
        "record": record,
        "policy": policy,
        "policy_strength": policy_strength,
        "status": "weak" if extra_deduction > 0 else "good",
        "explanation": "DMARC tells receiving mail servers what to do with emails that fail SPF/DKIM checks.",
        "business_impact": (
            "p=none only monitors — spoofed emails reach inboxes unchecked while you receive "
            "reports that rarely lead to action."
        ) if extra_deduction > 0 else "",
        "fix": fix,
        "deduction": extra_deduction,
    }


def _scan_dkim(domain: str) -> dict:
    """Probe common DKIM selectors for a public key record.

    Selectors are probed in parallel so an unresponsive nameserver can't
    serialise 12 × DNS_LIFETIME of waiting (which previously blew past the
    gunicorn worker timeout and returned 502). First selector (in list order)
    with a valid record wins."""
    def _probe(selector: str) -> list:
        return [
            r for r in _resolve_txt(f"{selector}._domainkey.{domain}")
            if "v=DKIM1" in r or "p=" in r
        ]

    with ThreadPoolExecutor(max_workers=len(_DKIM_SELECTORS)) as pool:
        results_by_selector = dict(zip(_DKIM_SELECTORS, pool.map(_probe, _DKIM_SELECTORS)))

    for selector in _DKIM_SELECTORS:
        records = results_by_selector.get(selector) or []
        if records:
            rec = records[0]
            return {
                "present": True,
                "selector": selector,
                "record": (rec[:80] + "...") if len(rec) > 80 else rec,
                "status": "good",
                "explanation": (
                    "DKIM cryptographically signs outgoing emails so recipients can verify "
                    "they genuinely came from your domain."
                ),
                "fix": None,
                "deduction": 0,
            }
    return {
        "present": False,
        "selector": None,
        "record": None,
        "status": "undetected",
        "explanation": (
            "No DKIM record found at common selectors. DKIM signs outgoing emails to verify "
            "authenticity. It may be configured with a custom selector not checked here."
        ),
        "business_impact": (
            "Unsigned outbound emails are easier to spoof in transit and more likely to land "
            "in spam, harming deliverability and brand trust."
        ),
        "fix": (
            f"Add a TXT record at <selector>._domainkey.{domain} "
            "with your mail provider's DKIM public key."
        ),
        "deduction": 2,
    }


def _scan_caa(domain: str) -> dict:
    """Check CAA records that restrict which CAs may issue certificates."""
    records = _resolve_type(domain, "CAA")
    if records:
        return {
            "present": True,
            "records": [str(r) for r in records],
            "status": "good",
            "explanation": (
                "CAA records restrict which Certificate Authorities can issue TLS certificates "
                "for your domain, preventing unauthorised certificate issuance."
            ),
            "fix": None,
            "deduction": 0,
        }
    return {
        "present": False,
        "records": [],
        "status": "missing",
        "explanation": (
            "No CAA records found. CAA (Certification Authority Authorization) DNS records "
            "restrict which CAs can issue TLS certificates for your domain, preventing "
            "unauthorised certificate issuance."
        ),
        "business_impact": (
            "Without CAA records, any trusted Certificate Authority can issue a certificate for "
            "your domain — enabling MITM attacks if a CA's infrastructure is compromised."
        ),
        "fix": f'0 issue "letsencrypt.org"  (add as CAA record on {domain})',
        "deduction": 2,
    }


def _scan_dnssec(domain: str) -> dict:
    """Check for DS records as evidence of DNSSEC delegation."""
    records = _resolve_type(domain, "DS")
    if records:
        return {
            "enabled": True,
            "status": "good",
            "explanation": (
                "DNSSEC cryptographically signs DNS records, preventing DNS cache poisoning "
                "and spoofing attacks."
            ),
            "fix": None,
            "deduction": 0,
        }
    return {
        "enabled": False,
        "status": "missing",
        "explanation": (
            "DNSSEC is not enabled. DNSSEC adds cryptographic signatures to DNS records, "
            "protecting against cache poisoning attacks where attackers redirect your domain "
            "to malicious servers."
        ),
        "business_impact": (
            "DNS cache poisoning can silently redirect your domain to attacker-controlled "
            "servers, intercepting all user traffic without their knowledge."
        ),
        "fix": f"Enable DNSSEC at your domain registrar or DNS provider for {domain}.",
        "deduction": 3,
    }


def scan_dns(domain: str) -> dict:
    """
    Query SPF, DMARC, DKIM, CAA, and DNSSEC records for domain and evaluate their security posture.
    DNS email security records are always on the apex domain, so www.walmart.com → walmart.com.
    """
    apex   = _apex_domain(domain)
    spf    = _scan_spf(apex)
    dmarc  = _scan_dmarc(apex)
    dkim   = _scan_dkim(apex)
    caa    = _scan_caa(apex)
    dnssec = _scan_dnssec(apex)

    total_deduction = (
        spf["deduction"] + dmarc["deduction"]
        + dkim["deduction"] + caa["deduction"] + dnssec["deduction"]
    )

    issues = []
    if spf["status"] in ("missing", "invalid", "weak"):
        issues.append(f"SPF: {spf['status']}")
    if dmarc["status"] in ("missing", "weak"):
        issues.append(f"DMARC: {dmarc['status']}")
    if dkim["status"] == "undetected":
        issues.append("DKIM: not detected")
    if caa["status"] == "missing":
        issues.append("CAA: missing")
    if dnssec["status"] == "missing":
        issues.append("DNSSEC: not enabled")

    summary = (
        "DNS email security and certificate protections are fully configured."
        if not issues
        else "; ".join(issues) + "."
    )

    return {
        "spf":    spf,
        "dmarc":  dmarc,
        "dkim":   dkim,
        "caa":    caa,
        "dnssec": dnssec,
        "total_deduction": total_deduction,
        "summary": summary,
    }
