"""Shared scoring helpers: every risk module returns the same result shape."""

GENUINE_MAX = 34     # 0-34  -> Likely Genuine
SUSPICIOUS_MAX = 64  # 35-64 -> Suspicious, 65+ -> High Risk

NEXT_STEPS = {
    "Likely Genuine": [
        "No major warning signs, but still confirm the offer on the company's official careers page.",
        "Never pay any fee to get a job or internship, even if everything else looks fine.",
    ],
    "Suspicious": [
        "Do not share documents, OTPs or money until you verify this independently.",
        "Search the company's official website yourself (don't use links from the message) and contact them there.",
        "Ask a mentor, placement cell or senior to look at the offer.",
    ],
    "High Risk / Likely Fake": [
        "Do NOT pay anything or share Aadhaar, PAN, bank details or OTP.",
        "Stop replying and block the sender.",
        "Report it: National Cyber Crime helpline 1930 or cybercrime.gov.in.",
        "If you already paid, tell your bank immediately and report within hours.",
    ],
}


def level_for(score):
    if score <= GENUINE_MAX:
        return "Likely Genuine"
    if score <= SUSPICIOUS_MAX:
        return "Suspicious"
    return "High Risk / Likely Fake"


def severity_for(weight):
    return "high" if weight >= 30 else "medium" if weight >= 15 else "low"


class Scorer:
    """Collects weighted warning signs, tips for fixing them, and checks that passed."""

    def __init__(self):
        self.score = 0.0
        self.flags = []     # [{"text", "severity"}]
        self.tips = []
        self.passed = []

    def add(self, weight, text, tip=None):
        self.score += weight
        self.flags.append({"text": text, "severity": severity_for(weight)})
        if tip and tip not in self.tips:
            self.tips.append(tip)

    def ok(self, text):
        if text not in self.passed:
            self.passed.append(text)


def confidence_for(score, agree=None, live_ok=False, n_signals=0):
    """How sure the system is about its verdict (0-100). It is NOT a guarantee of correctness.

    More confident when the score is far from the level boundaries, when independent
    signals agree, and when live internet checks succeeded.
    """
    d = min(abs(score - 34.5), abs(score - 64.5))
    c = 52 + 33 * (min(d, 30) / 30)
    if agree is True:
        c += 6
    elif agree is False:
        c -= 10
    if live_ok:
        c += 4
    c += min(n_signals, 3)
    if score <= GENUINE_MAX and not live_ok:
        c = min(c, 88)       # "nothing found" is weaker evidence than "scam found"
    return int(max(50, min(97, round(c))))


def build_result(module, s, details=None, agree=None, live_ok=False, extra_score=0):
    score = max(0, min(100, int(round(s.score + extra_score))))
    level = level_for(score)
    return {
        "module": module,
        "risk_score": score,
        "risk_level": level,
        "confidence": confidence_for(score, agree, live_ok, len(s.flags)),
        "flags": s.flags,
        "passed": s.passed,
        "tips": s.tips,
        "next_steps": NEXT_STEPS[level],
        "details": details or {},
    }
