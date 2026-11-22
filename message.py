"""Module 3: Email / message scam detection = ML (TF-IDF + LogisticRegression) + strict rules + link scanning."""
import os
import re

import joblib

import config
from .brands import KNOWN_BRANDS, pretty
from .risk import Scorer, build_result
from .url_check import analyze_url

_model = None


def get_model():
    """Load the trained model; train it on first use if the file is missing."""
    global _model
    if _model is None:
        if not os.path.exists(config.MODEL_PATH):
            from ml.train import train
            train(verbose=False)
        _model = joblib.load(config.MODEL_PATH)
    return _model


def reset_model():
    global _model
    _model = None


# phrases that look scary but are reassuring - removed before rule matching
SAFE_PHRASES = re.compile(
    r"no (payment|fee|fees|charges?)( is)?( required| needed| charged)?|free of charge|"
    r"without (any )?(fee|fees|payment|charges?)|never (ask|asks) for (money|payment)|"
    r"koi (fee|paisa|charge) nahi", re.I)

FEE_TIP = "Genuine employers never charge candidates. Do not pay registration, training, kit or security fees."
ID_TIP = "Share Aadhaar/PAN/bank details only after you have joined a verified company, never before."
FREEMAIL = r"[A-Za-z0-9._%+-]+@(gmail|yahoo|outlook|hotmail|rediffmail|ymail)\.[a-z.]+"

# (regex, weight, message, tip, critical)
RULES = [
    (re.compile(r"\b(registration|processing|security|training|onboarding|verification|clearance|joining|refundable|agent|certification|course|kit|laptop|id card|file|admin|booking|activation|stamp)\s+(fee|fees|charges?|deposit|amount|money)\b", re.I),
     45, "Asks for a fee/deposit - genuine employers never charge candidates", FEE_TIP, True),
    (re.compile(r"\b(pay|deposit|transfer|send|remit)\b[^.\n]{0,40}\b(rs\.?|₹|rupees|inr|upi|paytm|phonepe|gpay|google pay|\d{3,})", re.I),
     40, "Asks you to send money", FEE_TIP, True),
    (re.compile(r"\b(paisa|paise|rupaye|fees?|charges?|amount)\b[^.\n]{0,40}\b(bhejo|bhej|jama|dena|de do|dalo|transfer karo|bharo)\b", re.I),
     40, "Asks you to send money (Hindi/Hinglish)", FEE_TIP, True),
    (re.compile(r"\b(aadhaar|aadhar|pan card|pan number|bank (account )?details|account number|passbook|otp|cvv|card details|debit card|passport copy|net ?banking)\b", re.I),
     40, "Asks for sensitive documents/bank details/OTP too early", ID_TIP, True),
    (re.compile(r"\bno (interview|experience|skills?|qualification)\b|\bwithout (an )?interview\b|\bbina interview\b", re.I),
     25, "Promises a job with no interview/experience", "Real jobs always involve some selection process.", False),
    (re.compile(r"\b(guaranteed|100%|pakka)\b[^.\n]{0,30}\b(job|placement|selection|salary|payment|income|naukri)\b", re.I),
     20, "Makes guarantees no real employer can make", "Be wary of anyone who guarantees a job.", False),
    (re.compile(r"\b(whatsapp|telegram)\b", re.I),
     15, "Moves the conversation to WhatsApp/Telegram", "Official hiring happens over company email and portals.", False),
    (re.compile(r"\b(urgent|hurry|last chance|limited (seats|slots)|expires? in|within \d+ hours?|only today|immediately|turant|jaldi)\b", re.I),
     15, "Creates false urgency / pressure", "Scammers rush you so you don't think. Take your time and verify.", False),
    (re.compile(r"\b(earn|earning|kamao|kamaye)\b[^.\n]{0,25}\b(\d{4,}|lakhs?)\b[^.\n]{0,25}\b(daily|per day|weekly|per week|per hour|monthly|roz|din)\b", re.I),
     25, "Unrealistic earnings promised", "If it sounds too good to be true, it is.", False),
    (re.compile(r"\b(work from home|ghar baithe|home based)\b[^.\n]{0,60}\b(typing|data entry|liking|simple (online )?tasks?|copy paste|ad posting|kamao)\b", re.I),
     20, "Typical work-from-home scam pattern", None, False),
    (re.compile(r"\b(like|subscribe|follow|rate|review)\b[^.\n]{0,25}\b(videos?|youtube|instagram|products?|hotels?)\b[^.\n]{0,40}\b(earn|paid|pay|income|commission)\b", re.I),
     30, "'Like/subscribe and earn' task scam pattern", "Task-for-money jobs are a common scam that start small and then ask you to deposit money.", False),
    (re.compile(r"\b(bitcoin|crypto|forex|trading|investment|double your)\b", re.I),
     20, "Mentions crypto/investment - unusual for a job offer", None, False),
    (re.compile(r"\b(click|tap|open)\b[^.\n]{0,15}\b(here|link|below)\b[^.\n]{0,25}\b(apply|register|claim|verify|confirm|join)\b", re.I),
     15, "Pushes you to click a link to register/claim", "Don't click links in unexpected job messages. Go to the company's website yourself.", False),
    (re.compile(r"congratulations[^.!\n]{0,40}\b(selected|shortlisted|won|winner|chosen)\b", re.I),
     10, "Unsolicited 'you are selected' claim", "Did you actually apply to this company? Unexpected offers are a red flag.", False),
    (re.compile(r"\bforward\b[^.\n]{0,30}\b(contacts|friends|groups|10|5)\b", re.I),
     10, "Asks you to forward the message (chain pattern)", None, False),
    (re.compile(FREEMAIL, re.I),
     10, "Contact email is a free provider, not a company domain", "Official recruiters use company email addresses.", False),
    (re.compile(r"!{3,}"), 8, "Excessive exclamation marks", None, False),
]
SAFE_CONTEXT = re.compile(r"after (you )?(have )?(accept|accepting|accepted|join|joining|joined)|official (hr |careers? )?portal|company portal|hr portal|secure (hr )?portal|at the time of onboarding|on your first day", re.I)
ID_RULE_INDEX = 3   # position of the sensitive-documents rule in RULES
URL_RE = re.compile(r"(?:https?://|www\.)[^\s)>\]\"']+", re.I)


def rule_check(text):
    cleaned = SAFE_PHRASES.sub(" ", text)
    s = Scorer()
    critical = False
    for i, (pattern, weight, message, tip, is_critical) in enumerate(RULES):
        if pattern.search(cleaned):
            if i == ID_RULE_INDEX and SAFE_CONTEXT.search(cleaned) and not re.search(r"\botp\b|\bcvv\b|net ?banking", cleaned, re.I):
                # asked only after acceptance / on an official portal: normal onboarding, but still worth a caution
                s.add(12, "Asks for ID/bank details - only share these on the company's official portal after you have accepted the offer", ID_TIP)
                continue
            s.add(weight, message, tip)
            critical = critical or is_critical
    # brand claimed + free email contact = impersonation
    low = text.lower()
    brand = next((b for b in KNOWN_BRANDS if len(b) >= 3 and re.search(rf"\b{re.escape(b)}\b", low)), None)
    if brand and re.search(FREEMAIL, text, re.I):
        s.add(20, f"Mentions '{pretty(brand)}' but asks you to contact a free email address",
              f"{pretty(brand)} recruiters write from official {brand}.com addresses.")
    return min(100, s.score), s, critical


def analyze_message(text, module="message", scan_links=True):
    text = (text or "").strip()
    ml_prob = float(get_model().predict_proba([text])[0][1])  # P(scam)
    rule_score, s, critical = rule_check(text)

    final = 0.5 * (ml_prob * 100) + 0.5 * rule_score
    if critical:
        final = max(final, 70)          # asking for money/ID is always high risk

    if ml_prob >= 0.8 and not s.flags:
        s.add(0, "Language closely matches known scam messages")
    elif ml_prob >= 0.6:
        s.add(0, "Language resembles known scam messages")

    # links inside the message are analysed like standalone URLs
    live_ok = False
    urls = URL_RE.findall(text)[:3] if scan_links else []
    worst = None
    for i, u in enumerate(urls):
        r = analyze_url(u, live_checks=(i < 2))
        live_ok = live_ok or r["details"].get("live_checked", False)
        if worst is None or r["risk_score"] > worst["risk_score"]:
            worst = r
    extra = 0
    if worst and worst["risk_score"] >= 30:
        extra = worst["risk_score"] * 0.4
        s.add(0, f"Suspicious link in message ({worst['details']['url']}): " + "; ".join(f["text"] for f in worst["flags"]))
        s.flags[-1]["severity"] = "high" if worst["risk_score"] >= 60 else "medium"
        s.tips.extend(t for t in worst["tips"] if t not in s.tips)
    elif urls:
        s.ok("Links in the message look structurally normal")

    if not s.flags:
        s.ok("No scam phrases, fee requests or pressure tactics found")
    agree = (ml_prob >= 0.5) == (rule_score >= 25)
    res = build_result(module, s, {"ml_scam_probability": round(ml_prob, 3), "rule_score": rule_score,
                                   "links_found": len(urls)}, agree=agree, live_ok=live_ok,
                       extra_score=0)
    # fold ML/rule blend and link penalty in (build_result only knew about the rule flags' weights)
    from .risk import level_for, NEXT_STEPS, confidence_for
    score = int(round(min(100, final + extra)))
    res["risk_score"], res["risk_level"] = score, level_for(score)
    res["next_steps"] = NEXT_STEPS[res["risk_level"]]
    res["confidence"] = confidence_for(score, agree, live_ok, len(res["flags"]))
    res["details"]["live_checked"] = live_ok
    return res
