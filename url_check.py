"""Module 4: Website / URL analysis (offline heuristics, no network calls)."""
import re
from urllib.parse import urlparse

from .risk import Scorer, build_result

SUSPICIOUS_TLDS = {"xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "work",
                   "buzz", "loan", "icu", "rest", "monster", "cyou"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
BAD_KEYWORDS = ["login", "verify", "secure", "payment", "registration-fee", "fee",
                "bonus", "lottery", "urgent", "confirm", "claim", "winner"]
TWO_PART_SLDS = {"co", "com", "org", "net", "ac", "gov", "edu"}


def normalize(url):
    url = (url or "").strip()
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    if not has_scheme:
        url = "http://" + url
    return url, has_scheme


def host_of(url):
    parsed = urlparse(normalize(url)[0])
    return (parsed.hostname or "").lower()


def registrable_domain(host):
    """Naive 'example.co.in' / 'example.com' extraction (good enough for Phase 1)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in TWO_PART_SLDS and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(url):
    s = Scorer()
    full, has_scheme = normalize(url)
    parsed = urlparse(full)
    host = (parsed.hostname or "").lower()

    if not host or "." not in host:
        s.add(60, "Not a valid website address")
        return build_result("url", s.score, s.flags, {"url": url})

    if has_scheme and parsed.scheme == "http":
        s.add(20, "Website does not use HTTPS (connection is not secure)")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        s.add(35, "Uses a raw IP address instead of a domain name")
    if "@" in parsed.netloc:
        s.add(30, "URL contains '@' - often used to disguise the real destination")
    if host.startswith("xn--") or ".xn--" in host:
        s.add(30, "Domain uses punycode (can imitate real brand names)")

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        s.add(25, f"Domain ends in '.{tld}', commonly used by throwaway scam sites")
    if host in SHORTENERS:
        s.add(25, "Shortened link hides the real destination")

    labels = host.split(".")
    if len(labels) > 4:
        s.add(15, "Unusually many subdomains")
    if host.count("-") >= 3:
        s.add(15, "Domain has many hyphens")
    if len(full) > 100:
        s.add(10, "Very long URL")
    if sum(c.isdigit() for c in host) >= 4:
        s.add(10, "Domain contains many digits")

    hits = [k for k in BAD_KEYWORDS if k in (host + parsed.path).lower()]
    if hits:
        s.add(min(30, 10 * len(hits)), "Suspicious words in URL: " + ", ".join(hits))

    return build_result("url", s.score, s.flags, {"url": url, "domain": registrable_domain(host)})
