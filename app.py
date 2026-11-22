"""Flask backend for the Online Internship & Job Offer Verification Portal."""
from flask import Flask, jsonify, request

import config
import db
from modules.company import analyze_company
from modules.message import analyze_message, get_model
from modules.offer_letter import analyze_offer_letter, extract_pdf_text
from modules.url_check import analyze_url


def create_app(db_path=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024
    app.config["DB_PATH"] = db_path or config.DB_PATH
    db.init_db(app.config["DB_PATH"])

    # ---------- helpers ----------
    def bad_request(msg, code=400):
        return jsonify({"error": msg}), code

    def respond(result, input_summary):
        result["id"] = db.save_check(app.config["DB_PATH"], result["module"], input_summary, result)
        return jsonify(result)

    @app.after_request
    def add_cors(resp):  # lets the frontend (served from another port) call the API during development
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp

    # ---------- routes ----------
    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/api/health")
    def health():
        get_model()  # makes sure the ML model is loaded/trained
        return jsonify({"status": "ok"})

    @app.post("/api/verify/company")
    def verify_company():
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return bad_request("'name' is required")
        result = analyze_company(name, data.get("website", ""), data.get("email", ""))
        return respond(result, f"{name} | {data.get('website', '')} | {data.get('email', '')}")

    @app.post("/api/verify/message")
    def verify_message():
        data = request.get_json(silent=True) or {}
        text = (data.get("text") or "").strip()
        if len(text) < 10:
            return bad_request("'text' is required (at least 10 characters)")
        return respond(analyze_message(text), text)

    @app.post("/api/verify/url")
    def verify_url():
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return bad_request("'url' is required")
        return respond(analyze_url(url), url)

    @app.post("/api/verify/offer-letter")
    def verify_offer_letter():
        """Accepts a PDF upload (field name 'file') OR JSON {"text": "..."}."""
        text = ""
        if "file" in request.files:
            f = request.files["file"]
            if not f.filename.lower().endswith(".pdf"):
                return bad_request("Only PDF files are supported")
            try:
                text = extract_pdf_text(f.stream)
            except Exception:
                return bad_request("Could not read this PDF (is it a scanned image or corrupted?)", 422)
            if not text:
                return bad_request("No readable text found in the PDF (scanned image PDFs aren't supported yet)", 422)
        else:
            text = ((request.get_json(silent=True) or {}).get("text") or "").strip()
        if len(text) < 30:
            return bad_request("Provide a PDF file or 'text' with the offer letter content")
        return respond(analyze_offer_letter(text), text)

    @app.get("/api/history")
    def history():
        limit = min(request.args.get("limit", 20, type=int), 100)
        return jsonify(db.get_history(app.config["DB_PATH"], limit))

    @app.errorhandler(413)
    def too_large(_):
        return bad_request(f"File too large (max {config.MAX_UPLOAD_MB} MB)", 413)

    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=5000)
