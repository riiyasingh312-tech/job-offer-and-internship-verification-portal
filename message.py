"""Module 3: Email / message scam detection = ML (TF-IDF + LogisticRegression) + rule checks."""
import os
import re

import joblib

import config
from .risk import Scorer, build_result

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


# phrases that look scary but are actually reassuring - removed before rule matching
SAFE_PHRASES = re.compile(r"no (payment|fee|fees|charges?)( is)?( required| needed)?|free of charge|"
                          r"without (any )?(fee|fees|payment|charges?)|never (ask|asks) for (money|payment)", re.I)

# (regex, weight, message, critical)
RULES = [
    (re.compile(r"\b(registration|processing|security|training|onboarding|verification|clearance|joining|refundable|agent|certification|course)\s+(fee|fees|charges?|deposit|amount)\b", re.I),
     45, "Asks for a fee/deposit - genuine employers never charge candidates", True),
    (re.compile(r"\b(pay|deposit|transfer|send)\b[^.\n]{0,40}\b(rs\.?|₹|rupees|inr|upi|paytm|\d{3,})", re.I),
     40, "Asks you to send money", True),
    (re.compile(r"\b(aadhaar|aadhar|pan card|bank (account )?details|passbook|otp|cvv|card details|passport copy)\b", re.I),
     40, "Asks for sensitive documents/bank details/OTP too early", True),
    (re.compile(r"\bno (interview|experience|skills?)\b|\bwithout (an )?interview\b", re.I),
     25, "Promises a job with no interview/experience", False),
    (re.compile(r"\b(guaranteed|100%)\b[^.\n]{0,30}\b(job|placement|selection|salary|payment|income)\b", re.I),
     20, "Makes guarantees no real employer can make", False),
    (re.compile(r"\b(whatsapp|telegram)\b", re.I),
     15, "Moves the conversation to WhatsApp/Telegram", False),
    (re.compile(r"\b(urgent|hurry|last chance|limited (seats|slots)|expires? in|within \d+ hours?|only today|immediately)\b", re.I),
     15, "Creates false urgency / pressure", False),
    (re.compile(r"\b(earn|earning)\b[^.\n]{0,25}\b(\d{4,}|lakhs?)\b[^.\n]{0,25}\b(daily|per day|weekly|per week|per hour|monthly)\b", re.I),
     25, "Unrealistic earnings promised", False),
    (re.compile(r"\bwork from home\b[^.\n]{0,60}\b(typing|data entry|liking|simple online tasks?)\b", re.I),
     15, "Typical work-from-home scam pattern", False),
    (re.compile(r"[A-Za-z0-9._%+-]+@(gmail|yahoo|outlook|hotmail|rediffmail)\.[a-z.]+", re.I),
     10, "Contact email is a free provider, not a company domain", False),
    (re.compile(r"!{3,}"), 8, "Excessive exclamation marks", False),
]


def rule_check(text):
    cleaned = SAFE_PHRASES.sub(" ", text)
    s = Scorer()
    critical = False
    for pattern, weight, message, is_critical in RULES:
        if pattern.search(cleaned):
            s.add(weight, message)
            critical = critical or is_critical
    return min(100, s.score), s.flags, critical


def analyze_message(text, module="message"):
    text = (text or "").strip()
    ml_prob = float(get_model().predict_proba([text])[0][1])  # P(scam)
    rule_score, flags, critical = rule_check(text)

    final = 0.5 * (ml_prob * 100) + 0.5 * rule_score
    if critical:
        final = max(final, 70)          # asking for money/ID is always high risk
    if ml_prob >= 0.8 and not flags:
        flags = ["Language closely matches known scam messages"]
    elif ml_prob >= 0.6:
        flags = flags + ["Language resembles known scam messages"]

    return build_result(module, final, flags, {"ml_scam_probability": round(ml_prob, 3), "rule_score": rule_score})
