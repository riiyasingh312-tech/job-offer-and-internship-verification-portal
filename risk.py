"""Shared scoring helpers: every module returns the same result shape."""

GENUINE_MAX = 34     # 0-34  -> Likely Genuine
SUSPICIOUS_MAX = 64  # 35-64 -> Suspicious, 65+ -> High Risk


def level_for(score):
    if score <= GENUINE_MAX:
        return "Likely Genuine"
    if score <= SUSPICIOUS_MAX:
        return "Suspicious"
    return "High Risk / Likely Fake"


class Scorer:
    """Collects weighted warning signs."""

    def __init__(self):
        self.score = 0
        self.flags = []

    def add(self, weight, message):
        self.score += weight
        self.flags.append(message)


def build_result(module, score, flags, details=None):
    score = max(0, min(100, int(round(score))))
    return {
        "module": module,
        "risk_score": score,
        "risk_level": level_for(score),
        "flags": flags,
        "details": details or {},
    }
