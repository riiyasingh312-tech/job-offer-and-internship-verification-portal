import io
import os
import tempfile
import unittest

from app import create_app


def make_pdf_bytes(text):
    """Build a minimal text PDF without extra libraries."""
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


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.client = create_app(db_path=self.tmp.name).test_client()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_frontend_served(self):
        for path in ("/", "/static/style.css", "/static/app.js"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertIn("OfferCheck", self.client.get("/").get_data(as_text=True))

    def test_health(self):
        self.assertEqual(self.client.get("/api/health").get_json()["status"], "ok")

    def test_company_fake_vs_genuine(self):
        fake = self.client.post("/api/verify/company", json={
            "name": "Amazon Hiring", "website": "http://amazon-jobs.xyz", "email": "hr.amazon@gmail.com"}).get_json()
        good = self.client.post("/api/verify/company", json={
            "name": "Zoho Corporation", "website": "https://www.zoho.com", "email": "careers@zoho.com"}).get_json()
        self.assertEqual(fake["risk_level"], "High Risk / Likely Fake")
        self.assertEqual(good["risk_level"], "Likely Genuine")

    def test_message_scam_vs_genuine(self):
        scam = self.client.post("/api/verify/message", json={
            "text": "You are selected! Pay 1500 registration fee on Paytm today, limited seats!!!"}).get_json()
        good = self.client.post("/api/verify/message", json={
            "text": "Your interview is scheduled on Tuesday at 11 AM. Please join via the link sent to your registered email."}).get_json()
        self.assertEqual(scam["risk_level"], "High Risk / Likely Fake")
        self.assertEqual(good["risk_level"], "Likely Genuine")

    def test_url(self):
        r = self.client.post("/api/verify/url", json={"url": "http://job-verify-login.xyz/pay"}).get_json()
        self.assertGreaterEqual(r["risk_score"], 65)
        self.assertEqual(self.client.post("/api/verify/url", json={"url": "https://www.zoho.com"}).get_json()["risk_score"], 0)

    def test_offer_letter_text_and_pdf(self):
        letter = ("Date: 12/05/2026\nDear Riya,\nWe are pleased to offer you the position of Python Developer Intern "
                  "with a stipend of 15000 per month.\nYour joining date is 1st July.\nRegards,\nHR Manager\n"
                  "careers@zoho.com")
        r = self.client.post("/api/verify/offer-letter", json={"text": letter}).get_json()
        self.assertEqual(r["risk_level"], "Likely Genuine")
        pdf = self.client.post("/api/verify/offer-letter", data={"file": (io.BytesIO(make_pdf_bytes(letter)), "offer.pdf")},
                               content_type="multipart/form-data")
        self.assertEqual(pdf.status_code, 200, pdf.get_data(as_text=True))
        self.assertGreater(pdf.get_json()["details"]["characters_read"], 50)

    def test_scam_offer_letter(self):
        letter = ("Congratulations! You are selected for TCS. Pay 2000 security deposit within 24 hours on Paytm "
                  "and send your Aadhaar and bank details to hr.tcs.jobs@gmail.com. No interview needed!!!")
        r = self.client.post("/api/verify/offer-letter", json={"text": letter}).get_json()
        self.assertEqual(r["risk_level"], "High Risk / Likely Fake")

    def test_validation_errors(self):
        self.assertEqual(self.client.post("/api/verify/company", json={}).status_code, 400)
        self.assertEqual(self.client.post("/api/verify/message", json={"text": "hi"}).status_code, 400)
        bad = self.client.post("/api/verify/offer-letter", data={"file": (io.BytesIO(b"x"), "a.txt")},
                               content_type="multipart/form-data")
        self.assertEqual(bad.status_code, 400)

    def test_history_saved(self):
        self.client.post("/api/verify/url", json={"url": "https://www.zoho.com"})
        self.client.post("/api/verify/url", json={"url": "http://bad-login.xyz"})
        h = self.client.get("/api/history?limit=5").get_json()
        self.assertEqual(len(h), 2)
        self.assertEqual(h[0]["module"], "url")


if __name__ == "__main__":
    unittest.main()
