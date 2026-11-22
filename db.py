"""Tiny storage layer for verification history (SQLite).

Same two tables / columns can be created in MySQL later; only this file changes.
"""
import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS verifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module      TEXT NOT NULL,
    input_text  TEXT,
    risk_score  INTEGER NOT NULL,
    risk_level  TEXT NOT NULL,
    flags_json  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""


def _connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)


def save_check(db_path, module, input_text, result):
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO verifications (module, input_text, risk_score, risk_level, flags_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                module,
                (input_text or "")[:500],
                result["risk_score"],
                result["risk_level"],
                json.dumps(result["flags"]),
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )
        return cur.lastrowid


def get_history(db_path, limit=20):
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM verifications ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["flags"] = json.loads(d.pop("flags_json"))
        out.append(d)
    return out
