import io
import os
import tempfile
import unittest
from unittest import mock

os.environ["LIVE_CHECKS"] = "0"      # tests must not touch the internet

import config  # noqa: E402
from app import create_app  # noqa: E402


def make_pdf_bytes(text):
    """Minimal text PDF without extra libraries."""
    lines = text.split("\n")
    stream = "BT /F1 11 Tf 50 780 Td 14 TL " + " ".join(
        f"({l.replace('(', '[').replace(')', ']')}) Tj T*" for l in lines) + " ET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = "%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n" + "".join(f"{o:010d} 00000 n \n" for o in offsets)
    out += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return out.encode("latin-1")


GOOD_LETTER = ("Ref No: ZH/HR/2026/118\nDate: 12/05/2026\nDear Riya Singh,\nWe are pleased to offer you the position of "
               "Python Developer Intern at Zoho Corporation, 4th Floor, IT Park, Chennai 603202.\nStipend: Rs 15000 per month.\n"
               "Your joining date is 1st July 2026.\nRegards,\nPriya Nair\nHR Manager\ncareers@zoho.com www.zoho.com")
SCAM_LETTER = ("Congratulations! You are selected for TCS. Dear Candidate, pay 2000 security deposit within 24 hours on Paytm "
               "and send your Aadhaar and bank details to hr.tcs.jobs@gmail.com. No interview needed!!!")
RESUME = ("Riya Singh\nriya.singh@gmail.com | +91 9876543210 | linkedin.com/in/riya | github.com/riya\nSummary\n"
          "BCA Honours student specializing in AI and Data Science.\nEducation\nBCA Honours, GEHU, CGPA 8.4\nSkills\n"
          "Python, SQL, Flask\nProjects\n- Built a verification portal using Flask, reaching 95% accuracy\n"
          "- Designed a REST API handling 500+ requests and reduced response time by 40%\n- Developed a classifier for 100+ users\n"
          "Internship\n- Analyzed 2000+ records and automated reporting\nCertifications\n- Operating Systems")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.app = create_app(db_path=self.tmp.name)
        self.client = self.app.test_client()
        self._limits = (config.HISTORY_LIMIT, config.RATE_LIMIT_PER_MIN)

    def tearDown(self):
        config.HISTORY_LIMIT, config.RATE_LIMIT_PER_MIN = self._limits
        os.unlink(self.tmp.name)

    def register(self, client=None, email="riya@example.com", name="Riya", pw="Passw0rdX"):
        return (client or self.client).post("/api/auth/register", json={"name": name, "email": email, "password": pw})


class AuthTests(Base):
    def test_verify_requires_login(self):
        self.assertEqual(self.client.post("/api/verify/url", json={"url": "https://zoho.com"}).status_code, 401)
        self.assertEqual(self.client.get("/api/history").status_code, 401)

    def test_register_login_logout(self):
        self.assertEqual(self.register().status_code, 201)
        self.assertEqual(self.client.get("/api/auth/me").get_json()["user"]["email"], "riya@example.com")
        self.client.post("/api/auth/logout")
        self.assertIsNone(self.client.get("/api/auth/me").get_json()["user"])
        ok = self.client.post("/api/auth/login", json={"email": "RIYA@example.com", "password": "Passw0rdX"})
        self.assertEqual(ok.status_code, 200)

    def test_register_validation(self):
        self.assertEqual(self.register(pw="short1").status_code, 400)
        self.assertEqual(self.register(pw="onlyletters").status_code, 400)
        self.assertEqual(self.register(email="not-an-email").status_code, 400)
        self.register()
        self.assertEqual(self.register().status_code, 409)

    def test_wrong_password_and_lockout(self):
        self.register()
        self.client.post("/api/auth/logout")
        for _ in range(config.LOGIN_MAX_FAILS):
            r = self.client.post("/api/auth/login", json={"email": "riya@example.com", "password": "wrong"})
            self.assertEqual(r.status_code, 401)
        locked = self.client.post("/api/auth/login", json={"email": "riya@example.com", "password": "Passw0rdX"})
        self.assertEqual(locked.status_code, 429)

    def test_password_is_hashed(self):
        self.register()
        import db
        user = db.get_user_by_email(self.tmp.name, "riya@example.com")
        self.assertNotIn("Passw0rdX", user["password_hash"])


class VerifyTests(Base):
    def setUp(self):
        super().setUp()
        self.register()

    def post(self, path, **kw):
        return self.client.post(path, **kw)

    def test_company(self):
        fake = self.post("/api/verify/company", json={"name": "Amazon Hiring", "website": "http://amazon-jobs.xyz", "email": "hr.amazon@gmail.com"}).get_json()
        good = self.post("/api/verify/company", json={"name": "Zoho Corporation", "website": "https://www.zoho.com", "email": "careers@zoho.com"}).get_json()
        self.assertEqual(fake["risk_level"], "High Risk / Likely Fake")
        self.assertEqual(good["risk_level"], "Likely Genuine")
        self.assertTrue(fake["tips"] and fake["next_steps"])
        self.assertTrue(50 <= fake["confidence"] <= 97)

    def test_company_lookalike_email_and_cin(self):
        r = self.post("/api/verify/company", json={"name": "Infosys Limited", "website": "https://www.infosys.com", "email": "hr@infosyss.com", "cin": "BAD"}).get_json()
        texts = " ".join(f["text"] for f in r["flags"])
        self.assertIn("one character away from Infosys", texts)
        self.assertIn("CIN", texts)

    def test_message(self):
        scam = self.post("/api/verify/message", json={"text": "You are selected! Pay 1500 registration fee on Paytm today, limited seats!!!"}).get_json()
        good = self.post("/api/verify/message", json={"text": "Your interview is scheduled on Tuesday at 11 AM. Please join via the link sent to your registered email."}).get_json()
        onboarding = self.post("/api/verify/message", json={"text": "Please submit your bank account details on the HR portal after accepting the offer so payroll can credit your stipend."}).get_json()
        self.assertEqual(scam["risk_level"], "High Risk / Likely Fake")
        self.assertEqual(good["risk_level"], "Likely Genuine")
        self.assertEqual(onboarding["risk_level"], "Likely Genuine")      # normal onboarding is not flagged as fake

    def test_url_lookalikes(self):
        r = self.post("/api/verify/url", json={"url": "http://amaz0n-jobs.xyz/login"}).get_json()
        self.assertGreaterEqual(r["risk_score"], 65)
        self.assertEqual(self.post("/api/verify/url", json={"url": "https://www.zoho.com"}).get_json()["risk_score"], 0)
        self.assertGreaterEqual(self.post("/api/verify/url", json={"url": "https://paytrn.com"}).get_json()["risk_score"], 45)

    def test_url_live_checks_use_domain_age(self):
        fake_live = {"resolves": True, "age_days": 5, "tls": {"valid": True, "age_days": 2, "expires_in_days": 80, "issuer": "X"}}
        with mock.patch("modules.live.run_live_checks", return_value=fake_live):
            r = self.post("/api/verify/url", json={"url": "https://some-new-company.com"}).get_json()
        self.assertIn("registered only 5 days ago", " ".join(f["text"] for f in r["flags"]))
        old = dict(fake_live, age_days=4000)
        with mock.patch("modules.live.run_live_checks", return_value=old):
            r2 = self.post("/api/verify/url", json={"url": "https://some-old-company.com"}).get_json()
        self.assertTrue(any("registered" in p for p in r2["passed"]))

    def test_offer_letter_text_and_pdf(self):
        good = self.post("/api/verify/offer-letter", json={"text": GOOD_LETTER}).get_json()
        self.assertEqual(good["risk_level"], "Likely Genuine", good["flags"])
        pdf = self.post("/api/verify/offer-letter", data={"file": (io.BytesIO(make_pdf_bytes(GOOD_LETTER)), "offer.pdf")}, content_type="multipart/form-data")
        self.assertEqual(pdf.status_code, 200, pdf.get_data(as_text=True))
        self.assertGreater(pdf.get_json()["details"]["characters_read"], 50)
        bad = self.post("/api/verify/offer-letter", json={"text": SCAM_LETTER}).get_json()
        self.assertEqual(bad["risk_level"], "High Risk / Likely Fake")

    def test_resume(self):
        r = self.post("/api/verify/resume", json={"text": RESUME}).get_json()
        self.assertEqual(r["module"], "resume")
        self.assertGreaterEqual(r["resume_score"], 60)
        weak = self.post("/api/verify/resume", json={"text": "I am a hard working student. My dob 01/01/2005. References available upon request."}).get_json()
        self.assertLess(weak["resume_score"], 30)
        self.assertTrue(weak["tips"] and weak["red_flags"])
        pdf = self.post("/api/verify/resume", data={"file": (io.BytesIO(make_pdf_bytes(RESUME)), "cv.pdf")}, content_type="multipart/form-data")
        self.assertEqual(pdf.status_code, 200)

    def test_validation_errors(self):
        self.assertEqual(self.post("/api/verify/company", json={}).status_code, 400)
        self.assertEqual(self.post("/api/verify/message", json={"text": "hi"}).status_code, 400)
        self.assertEqual(self.post("/api/verify/message", json={"text": "x" * (config.MAX_TEXT_CHARS + 1)}).status_code, 400)
        bad = self.post("/api/verify/offer-letter", data={"file": (io.BytesIO(b"x"), "a.txt")}, content_type="multipart/form-data")
        self.assertEqual(bad.status_code, 400)

    def test_rate_limit(self):
        config.RATE_LIMIT_PER_MIN = 3
        codes = [self.post("/api/verify/url", json={"url": "https://zoho.com"}).status_code for _ in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])


class HistoryTests(Base):
    def setUp(self):
        super().setUp()
        self.register()

    def check(self, url="https://zoho.com", client=None):
        return (client or self.client).post("/api/verify/url", json={"url": url}).get_json()

    def test_history_saved_and_viewable(self):
        r = self.check()
        h = self.client.get("/api/history").get_json()
        self.assertEqual(h["used"], 1)
        self.assertEqual(h["items"][0]["module"], "url")
        full = self.client.get(f"/api/history/{r['id']}").get_json()
        self.assertEqual(full["risk_score"], r["risk_score"])

    def test_filter_and_search(self):
        self.check("https://zoho.com")
        self.client.post("/api/verify/message", json={"text": "Your interview is on Tuesday at 11 AM via email invite."})
        self.assertEqual(len(self.client.get("/api/history?module=message").get_json()["items"]), 1)
        self.assertEqual(len(self.client.get("/api/history?q=zoho").get_json()["items"]), 1)

    def test_users_cannot_see_each_others_history(self):
        a = self.check()
        other = self.app.test_client()
        self.register(other, email="other@example.com", name="Other")
        self.assertEqual(other.get("/api/history").get_json()["items"], [])
        self.assertEqual(other.get(f"/api/history/{a['id']}").status_code, 404)
        self.assertFalse(other.delete(f"/api/history/{a['id']}").get_json()["deleted"])
        self.assertEqual(self.client.get("/api/history").get_json()["used"], 1)

    def test_delete_one_and_clear_all(self):
        a, b = self.check(), self.check("https://paytrn.com")
        self.assertTrue(self.client.delete(f"/api/history/{a['id']}").get_json()["deleted"])
        self.assertEqual(self.client.get("/api/history").get_json()["used"], 1)
        self.check()
        self.assertEqual(self.client.delete("/api/history").get_json()["deleted"], 2)
        self.assertEqual(self.client.get("/api/history").get_json()["items"], [])

    def test_limit_auto_deletes_oldest(self):
        config.HISTORY_LIMIT = 3
        ids = [self.check(f"https://site{i}.com")["id"] for i in range(5)]
        h = self.client.get("/api/history").get_json()
        self.assertEqual(h["used"], 3)
        self.assertEqual([i["id"] for i in h["items"]], ids[::-1][:3])


class MiscTests(Base):
    def test_model_info_and_frontend(self):
        info = self.client.get("/api/model-info").get_json()
        self.assertTrue(0 < info["accuracy"] <= 100 and info["test_samples"] > 0)
        for path in ("/", "/static/style.css", "/static/app.js"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertIn("OfferCheck", self.client.get("/").get_data(as_text=True))
        self.assertIn("default-src 'self'", self.client.get("/").headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
