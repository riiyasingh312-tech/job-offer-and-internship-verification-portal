import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "portal.db"))
MODEL_PATH = os.path.join(BASE_DIR, "ml", "message_model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "ml", "metrics.json")
DATA_PATH = os.path.join(BASE_DIR, "ml", "data", "messages.csv")

MAX_UPLOAD_MB = 5
MAX_TEXT_CHARS = 20000

# ---- history / abuse limits
HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", 50))      # per user; oldest auto-deleted after this
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", 20))
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 300

# ---- live internet checks (domain age, SSL certificate, DNS). Set LIVE_CHECKS=0 to turn off.
LIVE_CHECKS = os.environ.get("LIVE_CHECKS", "1") == "1"
LIVE_TIMEOUT = 3.0


def _load_secret():
    """Session-signing key: env var, else a key saved next to the app (created once)."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE_DIR, ".secret_key")
    try:
        if os.path.exists(path):
            return open(path).read().strip()
        key = secrets.token_hex(32)
        with open(path, "w") as f:
            f.write(key)
        return key
    except OSError:
        return secrets.token_hex(32)  # read-only folder: sessions reset on restart


SECRET_KEY = _load_secret()
