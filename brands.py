"""Known brands + look-alike (typosquatting) detection."""
import re

KNOWN_BRANDS = [
    "google", "amazon", "microsoft", "tcs", "infosys", "wipro", "accenture", "cognizant", "deloitte",
    "flipkart", "zoho", "ibm", "meta", "apple", "capgemini", "hcl", "techmahindra", "adobe", "oracle",
    "paytm", "swiggy", "zomato", "naukri", "linkedin", "indeed", "internshala", "unstop", "goldmansachs",
    "jpmorgan", "hdfc", "icici", "airtel", "reliance", "intel", "nvidia", "samsung", "cisco", "salesforce",
    "walmart", "ey", "kpmg", "pwc", "mckinsey", "byjus", "ola", "uber", "tata", "mindtree", "ltimindtree",
]

# characters scammers swap in: amaz0n, g00gle, micr0soft, paytrn
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def normalize_label(label):
    s = label.lower().translate(_HOMOGLYPHS)
    s = s.replace("vv", "w").replace("rn", "m")
    return re.sub(r"[^a-z]", "", s)


def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_lookalike(label):
    """label = the main part of a domain (e.g. 'amaz0n-jobs' from amaz0n-jobs.xyz).

    Returns (brand, reason, strong) if the label imitates a known brand, else None.
    strong=True means a typo/look-alike-character imitation (very likely a fake);
    strong=False means the brand name is merely embedded (e.g. 'tcs-careers').
    The brand's own exact label (e.g. 'amazon') is never flagged.
    """
    raw = label.lower()
    if raw in KNOWN_BRANDS:
        return None
    norm = normalize_label(raw)
    for b in KNOWN_BRANDS:
        if norm == b:
            return b, "uses look-alike characters to imitate", True
        if len(b) >= 5 and edit_distance(norm, b) == 1:
            return b, "is one character away from", True
    parts = [normalize_label(p) for p in raw.split("-")]
    for b in KNOWN_BRANDS:
        if b in parts:
            return b, "contains the brand name but is not the official domain of", False
        if len(b) >= 5 and (norm.startswith(b) or norm.endswith(b)) and norm != b:
            return b, "embeds the brand name but is not the official domain of", False
    return None


def pretty(brand):
    """'tcs' -> 'TCS', 'amazon' -> 'Amazon'."""
    return brand.upper() if len(brand) <= 3 and brand != "ola" or brand in ("ibm", "hcl") else brand.title()
