"""Flask backend for OfferCheck: login, 5 verification modules, per-user history."""
import re
import time
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps

from flask import Flask, g, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import config
import db
from ml.train import get_metrics
from modules.company import analyze_company
from modules.message import analyze_message, get_model
from modules.offer_letter import analyze_offer_letter, extract_pdf_text
from modules.resume import analyze_resume
from modules.url_check import analyze_url

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def create_app(db_path=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.secret_key = config.SECRET_KEY
    app.config.update(
        MAX_CONTENT_LENGTH=config.MAX_UPLOAD_MB * 1024 * 1024,
        DB_PATH=db_path or config.DB_PATH,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",       # blocks cross-site form posts (CSRF)
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    )
    DB = app.config["DB_PATH"]
    db.init_db(DB)

    rate_hits = defaultdict(deque)       # user_id -> timestamps of recent checks
    login_fails = defaultdict(list)      # (ip,email) -> timestamps of failed logins

    # ------------------------------------------------------------ helpers
    def err(msg, code=400, **extra):
        return jsonify({"error": msg, **extra}), code

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = db.get_user(DB, session.get("uid")) if session.get("uid") else None
            if not user:
                session.clear()
                return err("Please log in first.", 401)
            g.user = user
            return fn(*a, **kw)
        return wrapper

    def rate_limited(uid):
        now = time.time()
        q = rate_hits[uid]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= config.RATE_LIMIT_PER_MIN:
            return int(60 - (now - q[0])) + 1
        q.append(now)
        return 0

    def json_body():
        return request.get_json(silent=True) or {}

    def clean_text(value, minimum, what):
        text = (value or "").strip()
        if len(text) < minimum:
            return None, err(f"'{what}' is required (at least {minimum} characters)")
        if len(text) > config.MAX_TEXT_CHARS:
            return None, err(f"'{what}' is too long (max {config.MAX_TEXT_CHARS} characters)")
        return text, None

    def respond(result, input_summary):
        result["id"] = db.save_check(DB, g.user["id"], input_summary, result, config.HISTORY_LIMIT)
        result["history_used"] = db.count_history(DB, g.user["id"])
        result["history_limit"] = config.HISTORY_LIMIT
        return jsonify(result)

    def guarded(fn):
        """login + rate-limit wrapper for the verify routes."""
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            wait = rate_limited(g.user["id"])
            if wait:
                return err(f"Too many checks. Please wait {wait} seconds and try again.", 429, retry_after=wait)
            return fn(*a, **kw)
        return wrapper

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                                  "style-src 'self'; script-src 'self'; frame-ancestors 'none'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------ pages
    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/api/health")
    def health():
        get_model()
        return jsonify({"status": "ok"})

    # ------------------------------------------------------------ auth
    @app.post("/api/auth/register")
    def register():
        d = json_body()
        name = (d.get("name") or "").strip()
        email = (d.get("email") or "").strip().lower()
        pw = d.get("password") or ""
        if not (2 <= len(name) <= 60):
            return err("Please enter your name (2-60 characters).")
        if not EMAIL_RE.match(email):
            return err("Please enter a valid email address.")
        if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
            return err("Password must be at least 8 characters and include a letter and a number.")
        if db.get_user_by_email(DB, email):
            return err("An account with this email already exists. Try logging in.", 409)
        uid = db.create_user(DB, name, email, generate_password_hash(pw))
        session.clear()
        session["uid"] = uid
        session.permanent = True
        return jsonify({"user": db.get_user(DB, uid)}), 201

    @app.post("/api/auth/login")
    def login():
        d = json_body()
        email = (d.get("email") or "").strip().lower()
        pw = d.get("password") or ""
        key = (request.remote_addr, email)
        now = time.time()
        login_fails[key] = [t for t in login_fails[key] if now - t < config.LOGIN_LOCK_SECONDS]
        if len(login_fails[key]) >= config.LOGIN_MAX_FAILS:
            wait = int(config.LOGIN_LOCK_SECONDS - (now - login_fails[key][0])) + 1
            return err(f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).", 429)
        user = db.get_user_by_email(DB, email)
        if not user or not check_password_hash(user["password_hash"], pw):
            login_fails[key].append(now)
            return err("Invalid email or password.", 401)
        login_fails.pop(key, None)
        session.clear()
        session["uid"] = user["id"]
        session.permanent = True
        return jsonify({"user": db.get_user(DB, user["id"])})

    @app.post("/api/auth/logout")
    def logout():
        session.clear()
        return jsonify({"ok": True})

    @app.get("/api/auth/me")
    def me():
        user = db.get_user(DB, session.get("uid")) if session.get("uid") else None
        return jsonify({"user": user})

    # ------------------------------------------------------------ verification
    @app.post("/api/verify/company")
    @guarded
    def verify_company():
        d = json_body()
        name = (d.get("name") or "").strip()
        if not name:
            return err("'name' is required")
        if any(len(str(d.get(k, ""))) > 300 for k in ("name", "website", "email", "cin")):
            return err("Inputs are too long")
        res = analyze_company(name, d.get("website", ""), d.get("email", ""), d.get("cin", ""))
        return respond(res, f"{name} | {d.get('website', '')} | {d.get('email', '')}")

    @app.post("/api/verify/message")
    @guarded
    def verify_message():
        text, bad = clean_text(json_body().get("text"), 10, "text")
        return bad or respond(analyze_message(text), text)

    @app.post("/api/verify/url")
    @guarded
    def verify_url():
        url = (json_body().get("url") or "").strip()
        if not url or len(url) > 2000:
            return err("'url' is required (max 2000 characters)")
        return respond(analyze_url(url), url)

    def text_from_request(field_label):
        """PDF upload (form field 'file') or JSON {"text": ...}. Returns (text, error_response)."""
        if "file" in request.files:
            f = request.files["file"]
            if not (f.filename or "").lower().endswith(".pdf"):
                return None, err("Only PDF files are supported")
            try:
                text = extract_pdf_text(f.stream)
            except Exception:
                return None, err("Could not read this PDF (is it corrupted?)", 422)
            if not text:
                return None, err("No readable text found in the PDF (scanned image PDFs aren't supported yet)", 422)
            return text[:config.MAX_TEXT_CHARS], None
        return clean_text(json_body().get("text"), 30, field_label)

    @app.post("/api/verify/offer-letter")
    @guarded
    def verify_offer_letter():
        text, bad = text_from_request("text")
        return bad or respond(analyze_offer_letter(text), text)

    @app.post("/api/verify/resume")
    @guarded
    def verify_resume():
        text, bad = text_from_request("text")
        return bad or respond(analyze_resume(text), text)

    # ------------------------------------------------------------ history
    @app.get("/api/history")
    @login_required
    def history():
        module = request.args.get("module") or None
        q = (request.args.get("q") or "").strip()[:100] or None
        items = db.get_history(DB, g.user["id"], module, q)
        return jsonify({"items": items, "used": db.count_history(DB, g.user["id"]), "limit": config.HISTORY_LIMIT})

    @app.get("/api/history/<int:check_id>")
    @login_required
    def history_item(check_id):
        item = db.get_check(DB, g.user["id"], check_id)
        return jsonify(item) if item else err("Not found", 404)

    @app.delete("/api/history/<int:check_id>")
    @login_required
    def history_delete(check_id):
        return jsonify({"deleted": db.delete_check(DB, g.user["id"], check_id)})

    @app.delete("/api/history")
    @login_required
    def history_clear():
        return jsonify({"deleted": db.clear_history(DB, g.user["id"])})

    # ------------------------------------------------------------ model accuracy
    @app.get("/api/model-info")
    def model_info():
        return jsonify(get_metrics())

    @app.errorhandler(413)
    def too_large(_):
        return err(f"File too large (max {config.MAX_UPLOAD_MB} MB)", 413)

    @app.errorhandler(404)
    def not_found(_):
        return err("Not found", 404)

    return app


if __name__ == "__main__":
    create_app().run(debug=False, port=5000)
