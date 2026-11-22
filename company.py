"""Module 1: Company verification - consistency, impersonation and registration checks."""
import datetime as dt
import re

from . import live
from .brands import KNOWN_BRANDS, pretty, brand_lookalike
from .risk import Scorer, build_result
from .url_check import analyze_url, host_of, registrable_domain

FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "yahoo.in", "yahoo.co.in", "outlook.com", "hotmail.com",
                      "rediffmail.com", "protonmail.com", "proton.me", "icloud.com", "live.com", "aol.com",
                      "zoho.in.net", "ymail.com", "mail.com", "gmx.com"}
DISPOSABLE_DOMAINS = {"mailinator.com", "tempmail.com", "temp-mail.org", "guerrillamail.com", "10minutemail.com",
                      "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com",
                      "maildrop.cc", "fakeinbox.com", "throwawaymail.com"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
CIN_RE = re.compile(r"^[LU]\d{5}[A-Z]{2}(\d{4})[A-Z]{3}\d{6}$")
LEGAL_SUFFIX = re.compile(r"\b(pvt|private|ltd|limited|llp|inc|corp|corporation|plc|gmbh|co)\b\.?", re.I)
RECRUIT_LABEL = re.compile(r"\b(hiring|recruitment|recruiters?|placements?|consultancy|careers?|jobs?|hr|vacancy|vacancies)\b", re.I)


def analyze_company(name, website="", email="", cin=""):
    s = Scorer()
    name = (name or "").strip()
    website = (website or "").strip()
    email = (email or "").strip().lower()
    cin = (cin or "").strip().upper()
    email_domain = email.split("@")[-1] if "@" in email else ""
    site_domain = registrable_domain(host_of(website)) if website else ""
    live_ok = False

    # ---------- name
    if len(name) < 3:
        s.add(10, "Company name is very short or missing", "Ask for the full legal company name.")
    if RECRUIT_LABEL.search(name) and not LEGAL_SUFFIX.search(name):
        s.add(10, "Name reads like a recruiting label, not a registered company name",
              "Ask for the legal name (e.g. '... Pvt Ltd') and its registration number.")

    # ---------- email
    if not email:
        s.add(10, "No company email provided", "Genuine recruiters write from an official company email.")
    elif not EMAIL_RE.match(email):
        s.add(20, "Email address looks invalid")
    else:
        if email_domain in DISPOSABLE_DOMAINS:
            s.add(35, f"Disposable/temporary email service ({email_domain})", "Real companies never hire through throwaway email addresses.")
        elif email_domain in FREE_EMAIL_DOMAINS:
            s.add(25, f"Recruiter uses a free email ({email_domain}) instead of a company domain",
                  "Ask for an official company email address (name@company.com).")
        else:
            look = brand_lookalike(registrable_domain(email_domain).split(".")[0])
            if look:
                s.add(50 if look[2] else 35, f"Email domain '{email_domain}' {look[1]} {pretty(look[0])}",
                      "Check the sender's email domain letter by letter before trusting it.")
            else:
                s.ok("Email uses a company (non-free) domain")

    # ---------- website (full URL analysis, counted at half weight)
    if not website:
        s.add(20, "No company website provided", "Every genuine company has an official website. Ask for it.")
    else:
        u = analyze_url(website)
        live_ok = u["details"].get("live_checked", False)
        if u["flags"]:
            worst = max(f["severity"] for f in u["flags"])
            s.add(u["risk_score"] * 0.5, "Website: " + "; ".join(f["text"] for f in u["flags"]))
            s.flags[-1]["severity"] = worst
            s.tips.extend(t for t in u["tips"] if t not in s.tips)
        for p in u["passed"]:
            s.ok("Website: " + p)

    # ---------- email vs website consistency
    if email_domain and site_domain and email_domain not in FREE_EMAIL_DOMAINS | DISPOSABLE_DOMAINS:
        if registrable_domain(email_domain) != site_domain:
            s.add(30, f"Email domain ({email_domain}) does not match website domain ({site_domain})",
                  "The recruiter's email and the company website should share the same domain.")
        else:
            s.ok("Email domain matches the website domain")

    # ---------- age of the email domain (when different from the website)
    if email_domain and email_domain not in FREE_EMAIL_DOMAINS | DISPOSABLE_DOMAINS and registrable_domain(email_domain) != site_domain:
        if live.run_live_checks(email_domain, registrable_domain(email_domain), check_tls=False):
            age = live.domain_age_days(registrable_domain(email_domain))
            if age is not None and age < 90:
                s.add(30, f"Email domain was registered only {age} days ago")

    # ---------- brand impersonation
    lowered = name.lower()
    for brand in KNOWN_BRANDS:
        if brand in lowered.split() or lowered.startswith(brand + " "):
            domains = {site_domain}
            if email_domain and email_domain not in FREE_EMAIL_DOMAINS | DISPOSABLE_DOMAINS:
                domains.add(registrable_domain(email_domain))
            domains.discard("")
            if domains and not any(d.split(".")[0] == brand for d in domains):
                s.add(30, f"Claims to be '{pretty(brand)}' but uses unrelated domain(s): {', '.join(sorted(domains))}",
                      f"Open {pretty(brand)}'s real careers page yourself and look for this role there.")
            elif domains:
                s.ok(f"Domain matches the claimed brand ({pretty(brand)})")
            break

    # ---------- registration number (CIN) - format only; cannot be looked up offline
    if cin:
        m = CIN_RE.match(cin)
        if not m or not (1850 <= int(m.group(1)) <= dt.date.today().year):
            s.add(25, "CIN (company registration number) has an invalid format",
                  "A real CIN has 21 characters, e.g. U72200KA2010PTC123456. Verify it on mca.gov.in.")
        else:
            s.ok("CIN has a valid format (look it up on mca.gov.in to confirm it belongs to this company)")
    else:
        s.tips.append("Ask for the company's CIN and verify it on the MCA portal (mca.gov.in) - fake firms often can't provide one.")

    return build_result("company", s, {"name": name, "website": website, "email": email, "cin": cin, "live_checked": live_ok}, live_ok=live_ok)
