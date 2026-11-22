import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# SQLite for now (zero setup). Swap db.py for MySQL later - schema stays the same.
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "portal.db"))
MODEL_PATH = os.path.join(BASE_DIR, "ml", "message_model.joblib")
DATA_PATH = os.path.join(BASE_DIR, "ml", "data", "messages.csv")

MAX_UPLOAD_MB = 5
