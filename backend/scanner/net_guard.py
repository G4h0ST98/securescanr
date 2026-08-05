"""
SSRF-hardened outbound networking.

Every outbound HTTP(S) fetch the scanner makes MUST go through safe_get(), and
every raw-socket connection (e.g. the TLS scanner) MUST validate the target with
resolve_and_validate() first. The guard:

  * resolves the hostname to concrete IPs *before* connecting,
  * rejects any address in a private/reserved range (canonical integer compare
    via the ipaddress module — never string matching),
  * pins the validated IP for the actual connection so the name cannot be
    re-resolved to an internal address between the check and the fetch
    (DNS-rebinding / TOCTOU),
  * follows redirects manually, re-validating every hop, with a hop cap,
  * allows only http/https, and caps timeout + response body size.
"""

import ipaddress
import socket
import threading
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS       = 5
DEFAULT_TIMEOUT     = 10          # seconds, per hop
MAX_RESPONSE_BYTES  = 3_000_000   # 3 MB cap on body we read

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Explicit disallowed networks. ipaddress flag checks (is_private etc.) already
# cover most of these, but the explicit list guarantees the exact ranges the
# audit calls out regardless of Python version differences.
_BLOCKED_NETS = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8",         # "this host on this network"
        "10.0.0.0/8",        # RFC1918
        "100.64.0.0/10",     # CGNAT (Railway internal networking often lives here)
        "127.0.0.0/8",       # loopback
        "169.254.0.0/16",    # link-local + cloud metadata (169.254.169.254)
        "172.16.0.0/12",     # RFC1918
        "192.168.0.0/16",    # RFC1918
        "::1/128",           # IPv6 loopback
        "fc00::/7",          # IPv6 unique-local
        "fe80::/10",         # IPv6 link-local
    )
]


class SSRFBlocked(Exception):
    """Raised when a target resolves to a disallowed (private/reserved) address."""


def _is_disallowed_ip(ip_str: str) -> bool:
    """True if ip_str is private/reserved/loopback/etc. Unparseable → disallowed."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    # Normalise IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to the embedded IPv4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return True
    return any(ip in net for net in _BLOCKED_NETS)


# ── DNS-rebinding-safe resolution ─────────────────────────────────────────────
#
# We pin resolution by intercepting socket.getaddrinfo (process-wide, installed
# once) but only acting when a thread-local pin map is set. Because the pin is
# thread-local it is safe under the scanner's ThreadPoolExecutor concurrency and
# is a no-op for every other caller (dnspython, unrelated sockets, etc.).

_pin = threading.local()
_orig_getaddrinfo = socket.getaddrinfo


def _patched_getaddrinfo(host, port, *args, **kwargs):
    pin_map = getattr(_pin, "map", None)
    if pin_map and host in pin_map:
        family, ip = pin_map[host]
        if family == socket.AF_INET6:
            sockaddr = (ip, port or 0, 0, 0)
        else:
            sockaddr = (ip, port or 0)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]
    return _orig_getaddrinfo(host, port, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo


def resolve_and_validate(hostname: str) -> tuple[int, str]:
    """
    Resolve hostname (using the real resolver, bypassing any pin) and validate
    every returned address. Returns (family, ip) of the first address to pin.
    Raises SSRFBlocked if resolution fails or ANY address is disallowed.
    """
    if not hostname:
        raise SSRFBlocked("missing host")
    try:
        infos = _orig_getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"DNS resolution failed for {hostname}") from exc
    if not infos:
        raise SSRFBlocked(f"no addresses for {hostname}")
    first: tuple[int, str] | None = None
    for family, _stype, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if _is_disallowed_ip(ip):
            raise SSRFBlocked(f"{hostname} resolves to a private or reserved address")
        if first is None:
            first = (family, ip)
    assert first is not None
    return first


def safe_get(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
    max_bytes: int = MAX_RESPONSE_BYTES,
    headers: dict | None = None,
) -> requests.Response:
    """
    SSRF-safe GET. Follows redirects manually, re-validating every hop. Returns a
    requests.Response (with .history populated) whose body has been read (capped).
    Raises SSRFBlocked on a disallowed target, or requests.RequestException on a
    network error.
    """
    req_headers = headers or {"User-Agent": USER_AGENT}
    session = requests.Session()
    history: list[requests.Response] = []
    current = url
    try:
        for _hop in range(max_redirects + 1):
            parsed = urlparse(current)
            if parsed.scheme not in ("http", "https"):
                raise SSRFBlocked(f"unsupported scheme '{parsed.scheme}'")
            host = parsed.hostname
            family, ip = resolve_and_validate(host)

            _pin.map = {host: (family, ip)}
            try:
                resp = session.get(
                    current,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                    headers=req_headers,
                )
            finally:
                _pin.map = None

            # Read a capped body, then detach from the stream.
            try:
                body = resp.raw.read(max_bytes + 1, decode_content=True)
            except Exception:
                body = b""
            resp._content = body[:max_bytes]
            resp._content_consumed = True

            if resp.is_redirect and resp.headers.get("Location"):
                history.append(resp)
                current = urljoin(current, resp.headers["Location"])
                continue

            resp.history = history
            return resp

        raise requests.TooManyRedirects(f"Exceeded {max_redirects} redirects")
    finally:
        session.close()
