"""Live internet checks: DNS, SSL certificate, and domain age (via RDAP).

Every function fails safely: if the internet is down or blocked it returns None and the
caller simply skips that check (no penalty). Hosts that resolve to private/internal
addresses are never contacted (protects the server from being used to probe internal networks).
"""
import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import config

_online = {"t": 0.0, "v": None}
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")


def is_online():
    if time.time() - _online["t"] < 30 and _online["v"] is not None:
        return _online["v"]
    try:
        socket.getaddrinfo("example.com", 443)
        v = True
    except OSError:
        v = False
    _online.update(t=time.time(), v=v)
    return v


def _public_host(host):
    """True only if the host resolves and every address is a normal public IP."""
    try:
        infos = socket.getaddrinfo(host, 443)
    except OSError:
        return None  # does not resolve
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def tls_info(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=config.LIVE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        nb = ssl.cert_time_to_seconds(cert["notBefore"])
        na = ssl.cert_time_to_seconds(cert["notAfter"])
        now = time.time()
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "unknown")
        return {"valid": True, "age_days": int((now - nb) / 86400),
                "expires_in_days": int((na - now) / 86400), "issuer": issuer}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": getattr(e, "verify_message", "certificate problem")}
    except (OSError, KeyError, ValueError):
        return None


def domain_age_days(domain):
    if not _DOMAIN_RE.match(domain):
        return None
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}",
                                     headers={"Accept": "application/rdap+json", "User-Agent": "OfferCheck/2"})
        with urllib.request.urlopen(req, timeout=config.LIVE_TIMEOUT + 2) as r:
            data = json.load(r)
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                d = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (dt.datetime.now(dt.timezone.utc) - d).days
    except Exception:
        return None
    return None


def run_live_checks(host, domain, check_tls=True):
    """Returns {"resolves", "tls", "age_days"} or None when live checks are off/unavailable."""
    if not config.LIVE_CHECKS or not host or not is_online():
        return None
    public = _public_host(host)
    if public is None:
        return {"resolves": False, "tls": None, "age_days": None}
    if public is False:
        return None   # internal address: never touch it
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_age = ex.submit(domain_age_days, domain)
        f_tls = ex.submit(tls_info, host) if check_tls else None
        return {"resolves": True, "tls": f_tls.result() if f_tls else None, "age_days": f_age.result()}
