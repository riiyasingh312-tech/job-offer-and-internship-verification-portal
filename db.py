"""Storage layer (SQLite): users + per-user verification history.

Same tables can be created in MySQL later; only this file changes.
"""
import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    module      TEXT NOT NULL,
    input_text  TEXT,
    score       INTEGER NOT NULL,
    level       TEXT NOT NULL,
    confidence  INTEGER,
    result_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ver_user ON verifications(user_id, id);
"""


def _connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db(db_path):
    with _connect(db_path) as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(verifications)")]
        if cols and "user_id" not in cols:          # old v1 database: keep it aside, start fresh
            conn.execute("ALTER TABLE verifications RENAME TO verifications_old_v1")
        conn.executescript(SCHEMA)


# ---------------- users ----------------
def create_user(db_path, name, email, password_hash):
    with _connect(db_path) as conn:
        cur = conn.execute("INSERT INTO users (name, email, password_hash, created_at) VALUES (?,?,?,?)",
                           (name, email, password_hash, _now()))
        return cur.lastrowid


def get_user_by_email(db_path, email):
    with _connect(db_path) as conn:
        r = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(r) if r else None


def get_user(db_path, user_id):
    with _connect(db_path) as conn:
        r = conn.execute("SELECT id, name, email, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(r) if r else None


# ---------------- history ----------------
def summary_of(result):
    """Works for risk results and resume results."""
    if result["module"] == "resume":
        return result["resume_score"], result["grade"]
    return result["risk_score"], result["risk_level"]


def save_check(db_path, user_id, input_text, result, limit):
    score, level = summary_of(result)
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO verifications (user_id, module, input_text, score, level, confidence, result_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (user_id, result["module"], (input_text or "")[:500], score, level,
             result.get("confidence"), json.dumps(result), _now()))
        new_id = cur.lastrowid
        # keep only the newest `limit` checks for this user (auto-delete oldest)
        conn.execute("DELETE FROM verifications WHERE user_id = ? AND id NOT IN "
                     "(SELECT id FROM verifications WHERE user_id = ? ORDER BY id DESC LIMIT ?)",
                     (user_id, user_id, limit))
        return new_id


def get_history(db_path, user_id, module=None, q=None, limit=100):
    sql = "SELECT id, module, input_text, score, level, confidence, created_at FROM verifications WHERE user_id = ?"
    args = [user_id]
    if module:
        sql += " AND module = ?"
        args.append(module)
    if q:
        sql += " AND input_text LIKE ?"
        args.append(f"%{q}%")
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with _connect(db_path) as conn:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def count_history(db_path, user_id):
    with _connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM verifications WHERE user_id = ?", (user_id,)).fetchone()[0]


def get_check(db_path, user_id, check_id):
    with _connect(db_path) as conn:
        r = conn.execute("SELECT result_json, created_at FROM verifications WHERE id = ? AND user_id = ?",
                         (check_id, user_id)).fetchone()
    if not r:
        return None
    out = json.loads(r["result_json"])
    out["id"], out["created_at"] = check_id, r["created_at"]
    return out


def delete_check(db_path, user_id, check_id):
    with _connect(db_path) as conn:
        return conn.execute("DELETE FROM verifications WHERE id = ? AND user_id = ?", (check_id, user_id)).rowcount > 0


def clear_history(db_path, user_id):
    with _connect(db_path) as conn:
        return conn.execute("DELETE FROM verifications WHERE user_id = ?", (user_id,)).rowcount
