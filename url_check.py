"""Module 4: Website / URL analysis - structure heuristics + brand look-alikes + live checks."""
import re
from urllib.parse import urlparse

from . import live
from .brands import brand_lookalike, pretty
from .risk import Scorer, build_result

SUSPICIOUS_TLDS = {"xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "work", "buzz", "loan",
                   "icu", "rest", "monster", "cyou", "cam", "sbs", "zip", "mov"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly"}
BAD_KEYWORDS = ["login", "verify", "secure", "payment", "registration-fee", "fee", "bonus",
                "lottery", "urgent", "confirm", "claim", "winner", "kyc", "refund"]
TWO_PART_SLDS = {"co", "com", "org", "net", "ac", "gov", "edu"}


def normalize(url):
    url = (url or "").strip()
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    return (url if has_scheme else "http://" + url), has_scheme


def host_of(url):
    return (urlparse(normalize(url)[0]).hostname or "").lower()


def registrable_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in TWO_PART_SLDS and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(url, live_checks=True):
    s = Scorer()
    full, has_scheme = normalize(url)
    parsed = urlparse(full)
    host = (parsed.hostname or "").lower()

    if not host or "." not in host or " " in host:
        s.add(60, "Not a valid website address", "Check the address for typos and copy it exactly from the official source.")
        return build_result("url", s, {"url": url})

    domain = registrable_domain(host)
    label = domain.split(".")[0]

    # ---------- structure
    if has_scheme and parsed.scheme == "http":
        s.add(20, "Website does not use HTTPS (connection is not secure)", "Never enter personal data on a site without HTTPS.")
    elif has_scheme and parsed.scheme == "https":
        s.ok("Uses HTTPS")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        s.add(35, "Uses a raw IP address instead of a domain name", "Real companies use proper domain names, not IP addresses.")
    if "@" in parsed.netloc:
        s.add(30, "URL contains '@' - often used to disguise the real destination")
    if host.startswith("xn--") or ".xn--" in host:
        s.add(30, "Domain uses punycode (can imitate real brand names with foreign characters)")
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        s.add(25, f"Domain ends in '.{tld}', commonly used by throwaway scam sites", "Prefer companies whose official domain you can confirm independently.")
    if host in SHORTENERS:
        s.add(35, "Shortened link hides the real destination", "Ask for the full link, or search for the company yourself.")
    if len(host.split(".")) > 4:
        s.add(15, "Unusually many subdomains")
    if host.count("-") >= 3:
        s.add(15, "Domain has many hyphens")
    if len(full) > 100:
        s.add(10, "Very long URL")
    if sum(c.isdigit() for c in host) >= 4:
        s.add(10, "Domain contains many digits")
    hits = [k for k in BAD_KEYWORDS if k in (host + parsed.path).lower()]
    if hits:
        s.add(min(30, 10 * len(hits)), "Suspicious words in URL: " + ", ".join(hits),
              "Genuine hiring pages never ask you to 'verify', 'confirm' or pay through a link.")

    # ---------- brand imitation
    look = brand_lookalike(label)
    if look:
        s.add(50 if look[2] else 35, f"Domain '{domain}' {look[1]} {pretty(look[0])}",
              f"Type the real {pretty(look[0])} website yourself instead of using this link.")

    # ---------- live checks
    live_res = live.run_live_checks(host, domain, check_tls=(parsed.scheme == "https" or not has_scheme)) if live_checks else None
    live_ok = False
    if live_res is not None:
        if not live_res["resolves"]:
            s.add(25, "This domain does not exist on the internet (it does not resolve)", "A working company website must exist - ask the recruiter for the correct one.")
        else:
            live_ok = True
            age = live_res["age_days"]
            if age is not None:
                if age < 30:
                    s.add(35, f"Domain was registered only {age} days ago", "Scam sites are usually brand new; real companies have older domains.")
                elif age < 180:
                    s.add(20, f"Domain is only {age // 30} months old")
                elif age < 365:
                    s.add(8, "Domain is less than a year old")
                else:
                    s.ok(f"Domain registered {age // 365} year(s) ago")
            tls = live_res["tls"]
            if tls is not None:
                if not tls["valid"]:
                    s.add(30, "SSL certificate is invalid: " + str(tls.get("error", "problem")), "Do not open or enter details on sites with certificate warnings.")
                else:
                    s.ok(f"Valid SSL certificate ({tls['issuer']})")
                    if tls["age_days"] < 10:
                        s.add(8, f"SSL certificate was issued only {tls['age_days']} days ago")
            s.ok("Domain exists and resolves")

    return build_result("url", s, {"url": url, "domain": domain, "live_checked": live_res is not None}, live_ok=live_ok)
