"""Module 2: Offer letter analysis - extract text (PDF), then content + structure + consistency checks."""
import datetime as dt
import re

import pdfplumber

from .brands import KNOWN_BRANDS, pretty
from .message import analyze_message, URL_RE
from .risk import Scorer, build_result, level_for, NEXT_STEPS, confidence_for
from .url_check import analyze_url, registrable_domain, host_of

EMAIL_ANY = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[a-z]{2,})", re.I)
FREE = {"gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "rediffmail.com", "ymail.com"}
MONTHS = "jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec"
DATE_RE = re.compile(rf"\b(\d{{1,2}})[/\-.](\d{{1,2}})[/\-.](\d{{2,4}})\b|\b(\d{{1,2}})(?:st|nd|rd|th)?\s+({MONTHS})[a-z]*\.?,?\s+(\d{{4}})\b|\b({MONTHS})[a-z]*\.?\s+(\d{{1,2}}),?\s+(\d{{4}})\b", re.I)

# (pattern, message when MISSING, weight, tip)
STRUCTURE_CHECKS = [
    (DATE_RE, "No clear date found in the letter", 8, "A real offer letter is dated."),
    (re.compile(r"\b(intern|engineer|analyst|developer|executive|manager|associate|trainee|designer|position|designation|role)\b", re.I),
     "No job title / designation mentioned", 10, "The role/designation must be stated clearly."),
    (re.compile(r"\b(sincerely|regards|authori[sz]ed signatory|signature|hr (manager|department|team)|human resources)\b", re.I),
     "No signature / authorised signatory section", 10, "Offer letters are signed by a named authorised person."),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}|\+?\d[\d\s-]{8,}", re.I),
     "No contact email or phone number", 8, None),
    (re.compile(r"\b(stipend|salary|ctc|compensation|remuneration|lpa|per month)\b", re.I),
     "No stipend / salary details", 6, "Compensation (or 'unpaid') should be written in the letter."),
    (re.compile(r"\b(ref(erence)?\.?\s*(no|number|#)|offer\s*(id|no)|emp(loyee)?\s*id)\b", re.I),
     "No reference / offer number", 4, "Companies usually number their offer letters."),
    (re.compile(r"\b(joining|reporting|start(ing)?)\s*(date|on)\b|\bjoin (us )?on\b|\bcommenc", re.I),
     "No joining / start date", 6, None),
    (re.compile(r"\b\d{6}\b|\b(address|registered office|corporate office|road|street|sector|floor)\b", re.I),
     "No company address / letterhead details", 6, "A genuine letter shows the company's registered address."),
]


def extract_pdf_text(file_stream, max_pages=10):
    parts = []
    with pdfplumber.open(file_stream) as pdf:
        for page in pdf.pages[:max_pages]:
            parts.append(page.extract_text() or "")
    return "\n".join(parts).strip()


def _first_date(text):
    m = DATE_RE.search(text)
    if not m:
        return None
    try:
        if m.group(1):
            d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
            y += 2000 if y < 100 else 0
            return dt.date(y, mo, d)
        mon = (m.group(5) or m.group(7))[:3].lower()
        day = int(m.group(4) or m.group(8))
        y = int(m.group(6) or m.group(9))
        return dt.date(y, MONTHS.split("|").index(mon) + 1, day)
    except ValueError:
        return None


def _monthly_amount(text):
    """Best-effort: the first stipend/salary figure, converted to rupees per month."""
    m = re.search(r"(stipend|salary|ctc|compensation|package)[^.\n]{0,40}?(?:rs\.?|₹|inr)?\s*([\d,]+(?:\.\d+)?)\s*(lpa|lakhs?|k)?(?:\s*(?:/|per)\s*(month|annum|year|pm))?", text, re.I)
    if not m:
        return None
    try:
        val = float(m.group(2).replace(",", ""))
    except ValueError:
        return None
    unit = (m.group(3) or "").lower()
    if unit in ("lpa", "lakh", "lakhs"):
        return val * 100000 / 12
    if unit == "k":
        return val * 1000
    per = (m.group(4) or "").lower()
    if per in ("annum", "year"):
        return val / 12
    return val


def analyze_offer_letter(text):
    text = (text or "").strip()
    msg = analyze_message(text, module="offer_letter", scan_links=False)   # content-level scam signals
    s = Scorer()
    s.flags.extend(msg["flags"])
    s.tips.extend(msg["tips"])
    s.passed.extend(msg["passed"])

    # ---------- structure
    missing = 0
    for pattern, message, weight, tip in STRUCTURE_CHECKS:
        if not pattern.search(text):
            s.add(weight, message, tip)
            missing += 1
    if missing == 0:
        s.ok("All standard parts of an offer letter are present")
    if re.search(r"\bdear\s+(candidate|applicant|sir|madam|student|intern)\b", text, re.I):
        s.add(5, "Generic greeting - a real letter addresses you by name", "Genuine offers use your actual name.")

    # ---------- dates
    d = _first_date(text)
    if d:
        today = dt.date.today()
        if d > today + dt.timedelta(days=60):
            s.add(10, "Letter is dated far in the future")
        elif d < today - dt.timedelta(days=3 * 365):
            s.add(10, "Letter date is more than 3 years old")

    # ---------- unrealistic pay for the role
    amt = _monthly_amount(text)
    is_intern = bool(re.search(r"\bintern(ship)?\b|\btrainee\b", text, re.I))
    if amt:
        if is_intern and amt >= 80000:
            s.add(25, f"Stipend (~₹{int(amt):,}/month) is unusually high for an internship",
                  "Very high pay for little work is a classic bait; verify the company before replying.")
        elif amt * 12 >= 4000000 and not is_intern:
            s.add(20, "Salary looks unrealistically high for a fresher role")

    # ---------- emails / links consistency + brand claims
    emails = [e.lower() for e in EMAIL_ANY.findall(text)]
    corp = {registrable_domain(e) for e in emails if e not in FREE}
    urls = URL_RE.findall(text)
    link_domains = {registrable_domain(host_of(u)) for u in urls}
    if corp and link_domains and not (corp & link_domains):
        s.add(20, "Email domain and website link in the letter belong to different domains",
              "A real letter's email and website share the same company domain.")
    low = text.lower()
    brand = next((b for b in KNOWN_BRANDS if len(b) >= 3 and re.search(rf"\b{re.escape(b)}\b", low)), None)
    if brand and emails and not any(f['text'].startswith('Mentions') for f in s.flags) and not any(registrable_domain(e).split(".")[0] == brand for e in emails if e not in FREE):
        s.add(25, f"Letter claims to be from {pretty(brand)} but no {pretty(brand)} email address appears",
              f"Real {pretty(brand)} letters come from {brand} domains - confirm with their official HR.")

    # ---------- links inside the letter (live-checked for the first two)
    live_ok = False
    worst = None
    for i, u in enumerate(urls[:4]):
        r = analyze_url(u, live_checks=(i < 2))
        live_ok = live_ok or r["details"].get("live_checked", False)
        if worst is None or r["risk_score"] > worst["risk_score"]:
            worst = r
    link_extra = 0
    if worst and worst["risk_score"] >= 30:
        link_extra = worst["risk_score"] * 0.4
        s.add(0, f"Suspicious link in letter ({worst['details']['url']}): " + "; ".join(f["text"] for f in worst["flags"]))
        s.flags[-1]["severity"] = "high" if worst["risk_score"] >= 60 else "medium"

    final = 0.7 * msg["risk_score"] + s.score + link_extra
    if msg["risk_score"] >= 70:
        final = max(final, 70)
    score = int(round(max(0, min(100, final))))
    level = level_for(score)
    return {
        "module": "offer_letter", "risk_score": score, "risk_level": level,
        "confidence": confidence_for(score, agree=(msg["risk_score"] >= 35) == (missing >= 2),
                                     live_ok=live_ok, n_signals=len(s.flags)),
        "flags": s.flags, "passed": s.passed, "tips": s.tips, "next_steps": NEXT_STEPS[level],
        "details": {"characters_read": len(text), "message_risk": msg["risk_score"],
                    "links_found": len(urls), "emails_found": len(emails), "live_checked": live_ok},
    }
