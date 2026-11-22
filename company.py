"""Module 1: Company verification (consistency checks on what the user provides)."""
from .risk import Scorer, build_result
from .url_check import analyze_url, host_of, registrable_domain

FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com",
                      "rediffmail.com", "protonmail.com", "icloud.com", "live.com", "aol.com"}
KNOWN_BRANDS = ["google", "amazon", "microsoft", "tcs", "infosys", "wipro", "accenture",
                "cognizant", "deloitte", "flipkart", "zoho", "ibm", "meta", "apple", "capgemini"]


def analyze_company(name, website="", email=""):
    s = Scorer()
    name = (name or "").strip()
    website = (website or "").strip()
    email = (email or "").strip().lower()
    email_domain = email.split("@")[-1] if "@" in email else ""
    site_domain = registrable_domain(host_of(website)) if website else ""

    if len(name) < 3:
        s.add(10, "Company name is very short or missing")

    # --- email checks
    if not email:
        s.add(10, "No company email provided")
    elif "@" not in email or "." not in email_domain:
        s.add(20, "Email address looks invalid")
    elif email_domain in FREE_EMAIL_DOMAINS:
        s.add(25, f"Recruiter uses a free email ({email_domain}) instead of a company domain")

    # --- website checks
    if not website:
        s.add(20, "No company website provided")
    else:
        url_result = analyze_url(website)
        if url_result["risk_score"] > 0:
            s.add(url_result["risk_score"] * 0.5, "Website issues: " + "; ".join(url_result["flags"]))

    # --- consistency between email and website
    if email_domain and site_domain and email_domain not in FREE_EMAIL_DOMAINS:
        if registrable_domain(email_domain) != site_domain:
            s.add(30, f"Email domain ({email_domain}) does not match website domain ({site_domain})")

    # --- brand impersonation (claims a known brand but domain's main label isn't that brand)
    lowered = name.lower()
    for brand in KNOWN_BRANDS:
        if brand in lowered.split() or lowered.startswith(brand):
            domains = {site_domain}
            if email_domain and email_domain not in FREE_EMAIL_DOMAINS:
                domains.add(registrable_domain(email_domain))
            domains.discard("")
            if domains and not any(d.split(".")[0] == brand for d in domains):
                s.add(30, f"Claims to be '{brand.title()}' but uses unrelated domain(s): {', '.join(sorted(domains))}")
            break

    return build_result("company", s.score, s.flags, {"name": name, "website": website, "email": email})
