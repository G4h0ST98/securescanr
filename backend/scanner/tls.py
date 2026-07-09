import ssl
import socket
from datetime import datetime, timezone

CONNECT_TIMEOUT = 10

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "ANON"}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _parse_cert_date(s: str) -> datetime:
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _get_common_name(rdns_seq) -> str:
    for rdn in rdns_seq:
        for attr in rdn:
            if attr[0] == "commonName":
                return attr[1]
    return ""


def _error_result(supported: bool, message: str, deduction: int) -> dict:
    if not supported:
        bi = "All user data — passwords, tokens, personal information — is transmitted in plaintext and visible to any network observer."
    else:
        bi = "Browsers refuse to connect due to the TLS error, making the site effectively unavailable to most users."
    return {
        "supported": supported,
        "error": message,
        "certificate": None,
        "connection": None,
        "deductions": [{"reason": message, "points": deduction, "business_impact": bi}],
        "total_deduction": deduction,
        "summary": message,
    }


def scan_tls(hostname: str, port: int = 443) -> dict:
    """
    Open a TLS connection to hostname:port and evaluate the certificate and
    cipher suite. Returns a structured result with deductions.
    """
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                cipher_name, _, bits = tls.cipher()
                tls_version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return _error_result(True, f"Certificate verification failed: {exc}", 15)
    except ssl.SSLError as exc:
        return _error_result(True, f"TLS handshake failed: {exc}", 15)
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        return _error_result(False, f"HTTPS not reachable on port {port}: {exc}", 20)

    now = datetime.now(timezone.utc)
    deductions = []

    # Certificate expiry
    try:
        not_before = _parse_cert_date(cert["notBefore"])
        not_after = _parse_cert_date(cert["notAfter"])
        days_remaining = (not_after - now).days
        is_expired = days_remaining < 0
    except (KeyError, ValueError):
        not_before = not_after = None
        days_remaining = None
        is_expired = False

    if is_expired:
        deductions.append({
            "reason": "Certificate is expired",
            "points": 30,
            "business_impact": "Browsers display a hard block page — users cannot proceed and see a full-screen certificate error, causing complete service unavailability.",
        })
    elif days_remaining is not None:
        if days_remaining <= 14:
            deductions.append({
                "reason": f"Certificate expires in {days_remaining} day{'s' if days_remaining != 1 else ''}",
                "points": 20,
                "business_impact": "The certificate expires within two weeks — browsers will warn users imminently and block access entirely on expiry.",
            })
        elif days_remaining <= 30:
            deductions.append({
                "reason": f"Certificate expires in {days_remaining} day{'s' if days_remaining != 1 else ''}",
                "points": 10,
                "business_impact": "Imminent expiry risks a full browser block — missing the renewal window makes your site inaccessible to all visitors.",
            })
        elif days_remaining <= 60:
            deductions.append({
                "reason": f"Certificate expires in {days_remaining} day{'s' if days_remaining != 1 else ''}",
                "points": 5,
                "business_impact": "Plan certificate renewal now — lapses cause immediate browser errors and lose user trust.",
            })

    # Cipher strength
    cipher_upper = cipher_name.upper()
    if any(w in cipher_upper for w in WEAK_CIPHERS):
        deductions.append({
            "reason": f"Weak cipher in use: {cipher_name}",
            "points": 10,
            "business_impact": "An attacker capturing your encrypted traffic can decrypt it offline, exposing all HTTPS-protected user data and credentials.",
        })

    # Protocol version
    if tls_version in WEAK_PROTOCOLS:
        deductions.append({
            "reason": f"Deprecated TLS protocol in use: {tls_version}",
            "points": 10,
            "business_impact": "TLSv1.0/1.1 are vulnerable to BEAST and POODLE attacks that break HTTPS encryption and can expose session data.",
        })

    # Certificate metadata
    subject_cn = _get_common_name(cert.get("subject", ()))
    issuer_cn = _get_common_name(cert.get("issuer", ()))
    san = [val for key, val in cert.get("subjectAltName", ()) if key == "DNS"]
    is_self_signed = bool(subject_cn and subject_cn == issuer_cn)

    if is_self_signed:
        deductions.append({
            "reason": "Self-signed certificate — not trusted by browsers",
            "points": 20,
            "business_impact": "Browsers show a full-screen untrusted-certificate warning; most users will leave rather than add a security exception.",
        })

    total_deduction = sum(d["points"] for d in deductions)
    summary = (
        "TLS configuration looks good."
        if not deductions
        else "; ".join(d["reason"] for d in deductions) + "."
    )

    return {
        "supported": True,
        "error": None,
        "certificate": {
            "subject": subject_cn,
            "issuer": issuer_cn,
            "valid_from": not_before.isoformat() if not_before else None,
            "valid_until": not_after.isoformat() if not_after else None,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "san": san,
        },
        "connection": {
            "protocol": tls_version,
            "cipher": cipher_name,
            "bits": bits,
        },
        "deductions": deductions,
        "total_deduction": total_deduction,
        "summary": summary,
    }
