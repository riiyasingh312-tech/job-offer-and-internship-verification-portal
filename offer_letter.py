"""Module 2: Offer letter analysis - extract text (PDF) then check content + structure."""
import re

import pdfplumber

from .message import analyze_message
from .risk import Scorer, build_result
from .url_check import analyze_url

FREE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(gmail|yahoo|outlook|hotmail|rediffmail)\.[a-z.]+", re.I)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s)>\]\"']+", re.I)

# (pattern, message when MISSING, weight)
STRUCTURE_CHECKS = [
    (re.compile(r"\b(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\d{1,2}(st|nd|rd|th)?\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+\d{2,4}|(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b", re.I),
     "No clear date found in the letter", 8),
    (re.compile(r"\b(intern|engineer|analyst|developer|executive|manager|associate|trainee|designer|position|designation|role)\b", re.I),
     "No job title / designation mentioned", 10),
    (re.compile(r"\b(sincerely|regards|authori[sz]ed signatory|signature|hr (manager|department|team)|human resources)\b", re.I),
     "No signature / authorised signatory section", 10),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}|\+?\d[\d\s-]{8,}", re.I),
     "No contact email or phone number", 8),
    (re.compile(r"\b(stipend|salary|ctc|compensation|remuneration|lpa|per month)\b", re.I),
     "No stipend / salary details", 6),
]


def extract_pdf_text(file_stream, max_pages=10):
    parts = []
    with pdfplumber.open(file_stream) as pdf:
        for page in pdf.pages[:max_pages]:
            parts.append(page.extract_text() or "")
    return "\n".join(parts).strip()


def analyze_offer_letter(text):
    text = (text or "").strip()
    msg = analyze_message(text, module="offer_letter")   # content-level scam signals
    s = Scorer()
    s.flags.extend(msg["flags"])

    # structure: missing standard parts of a real offer letter
    for pattern, message, weight in STRUCTURE_CHECKS:
        if not pattern.search(text):
            s.add(weight, message)

    # free-email contact inside the letter (already flagged by message rules; avoid double-listing)
    # embedded links: score the worst one
    urls = URL_RE.findall(text)
    worst = None
    for u in urls[:5]:
        r = analyze_url(u)
        if worst is None or r["risk_score"] > worst["risk_score"]:
            worst = r
    if worst and worst["risk_score"] >= 30:
        s.add(worst["risk_score"] * 0.4, f"Suspicious link in letter ({worst['details']['url']}): " + "; ".join(worst["flags"]))

    final = 0.7 * msg["risk_score"] + s.score
    if msg["risk_score"] >= 70:
        final = max(final, 70)
    return build_result("offer_letter", final, s.flags,
                        {"characters_read": len(text), "message_risk": msg["risk_score"], "links_found": len(urls)})
