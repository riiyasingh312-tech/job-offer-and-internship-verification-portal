"""Module 5: Resume analysis - ATS-readiness score, red flags and prioritised improvement tips.

NOTE: unlike the other modules, a HIGHER score here is BETTER.
"""
import datetime as dt
import re
from collections import Counter

ACTION_VERBS = {
    "developed", "built", "designed", "implemented", "led", "managed", "created", "analyzed", "analysed", "optimized",
    "improved", "reduced", "increased", "deployed", "automated", "collaborated", "organized", "launched", "trained",
    "tested", "integrated", "researched", "presented", "coordinated", "achieved", "delivered", "maintained",
    "engineered", "mentored", "resolved", "streamlined", "established", "initiated", "executed", "wrote", "won",
}
STOP = set("the a an and or of to in for with on at by from is are was were as be this that it its i my we our".split())

SECTIONS = [  # (key, label, points, regex, tip)
    ("education", "Education", 10, r"\b(education|academic|qualification|b\.?tech|bca|b\.?sc|bachelor|master|university|college|cgpa|gpa)\b",
     "Add an Education section: degree, college, years and CGPA/percentage."),
    ("skills", "Skills", 10, r"\b(skills|technical skills|technologies|tools|proficien)\w*",
     "Add a Skills section listing your languages, tools and frameworks."),
    ("experience", "Experience / Internships", 10, r"\b(experience|internship|intern|employment|work history|trainee)\b",
     "Add internships, training or any work experience (even freelance or volunteering)."),
    ("projects", "Projects", 10, r"\b(projects?|capstone|hackathon|portfolio)\b",
     "Add 2-3 projects with what you built, the tech used and the result."),
    ("summary", "Summary / Objective", 6, r"\b(summary|objective|profile|about me|career objective)\b",
     "Add a 2-3 line summary at the top stating your goal and strongest skills."),
    ("certs", "Certifications / Achievements", 4, r"\b(certifications?|certificates?|achievements?|awards?|courses?|honou?rs)\b",
     "Add certifications and achievements to stand out."),
]


def analyze_resume(text):
    text = (text or "").strip()
    low = text.lower()
    words = re.findall(r"[A-Za-z][A-Za-z+#.'-]*", text)
    n_words = len(words)
    checks, tips, strengths, red_flags = [], [], [], []

    def check(name, points, ok, tip, group):
        checks.append({"name": name, "points": points, "earned": points if ok else 0, "ok": bool(ok), "group": group})
        (strengths if ok else tips).append(name if ok else {"text": tip, "points": points})

    # ---------- contact (20)
    check("Email address", 8, re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), "Add a professional email address at the top.", "Contact")
    check("Phone number", 6, re.search(r"(\+?\d[\d\s-]{8,}\d)", text), "Add your phone number.", "Contact")
    check("LinkedIn / GitHub link", 6, re.search(r"linkedin\.com|github\.com|portfolio", low), "Add your LinkedIn and GitHub (or portfolio) link.", "Contact")

    # ---------- sections (50)
    found = []
    for key, label, pts, rx, tip in SECTIONS:
        ok = re.search(rx, low)
        check(label, pts, ok, tip, "Sections")
        if ok:
            found.append(label)

    # ---------- content quality (30)
    bullets = len(re.findall(r"^\s*[•\-\*▪●◦‣]|\n\s*[•\-\*▪●◦‣]", text))
    verbs = sum(1 for w in words if w.lower() in ACTION_VERBS)
    metrics = len(re.findall(r"\d+\s*%|\b\d{2,}\+?\s*(users|students|customers|records|projects|members|ms|x)\b|[₹$]\s?\d+|\b\d+x\b", text, re.I))
    check("Good length (250-800 words)", 8, 250 <= n_words <= 800,
          f"Aim for 250-800 words (one page for freshers). Yours has {n_words} words.", "Content")
    check("Strong action verbs (5+)", 8, verbs >= 5,
          f"Start bullets with action verbs: Built, Designed, Improved, Led, Automated. Found only {verbs}.", "Content")
    check("Measurable results (3+)", 8, metrics >= 3,
          f"Add numbers: 'improved accuracy by 12%', 'handled 500+ records', 'cut load time by 40%'. Found {metrics}.", "Content")
    check("Bullet points used", 6, bullets >= 4, "Use bullet points instead of long paragraphs so recruiters can scan quickly.", "Content")

    # ---------- red flags (subtract points)
    penalty = 0
    em = re.search(r"([\w.+-]+)@", text)
    if em and re.search(r"(cute|sexy|hot|baby|bad|cool|king|queen|lover|hunk|angel|dude)", em.group(1), re.I):
        red_flags.append("Unprofessional email address - use firstname.lastname@gmail.com"); penalty += 5
    if n_words > 1200:
        red_flags.append("Too long - cut it down to 1-2 pages"); penalty += 5
    freq = Counter(w.lower() for w in words if w.lower() not in STOP and len(w) > 3)
    if freq:
        top, cnt = freq.most_common(1)[0]
        if cnt >= 10 and cnt / max(n_words, 1) > 0.05:
            red_flags.append(f"Keyword stuffing: '{top}' appears {cnt} times - ATS and recruiters penalise this"); penalty += 5
    years = [int(y) for y in re.findall(r"\b(19[89]\d|20\d{2})\b", text)]
    if any(y > dt.date.today().year + 6 for y in years):
        red_flags.append("Dates far in the future - check for typos"); penalty += 5
    if re.search(r"references? (are )?available|available upon request", low):
        red_flags.append("'References available upon request' is outdated - remove it to save space")
    if re.search(r"\b(date of birth|dob|marital status|religion|father'?s name|nationality)\b", low):
        red_flags.append("Remove personal details (DOB, marital status, religion, father's name) - not needed and can invite bias")
    if re.search(r"\b(i am|i have|i was|my)\b", low) and n_words > 50:
        red_flags.append("Avoid first-person ('I am', 'my') - write bullets without pronouns")
    if n_words < 120:
        red_flags.append("Very little text found - if this is a scanned/image PDF, export a text-based PDF instead"); penalty += 20

    score = max(0, min(100, sum(c["earned"] for c in checks) - penalty))
    grade = "Excellent" if score >= 85 else "Good" if score >= 70 else "Needs work" if score >= 50 else "Weak"
    tips.sort(key=lambda t: -t["points"])
    ordered_tips = [t["text"] for t in tips]

    return {
        "module": "resume", "resume_score": score, "grade": grade,
        "ats_readiness": score,
        "confidence": 90 if n_words >= 150 else 60,
        "checks": checks, "strengths": strengths, "tips": ordered_tips, "red_flags": red_flags,
        "stats": {"words": n_words, "bullets": bullets, "action_verbs": verbs,
                  "measurable_results": metrics, "sections_found": found},
    }
