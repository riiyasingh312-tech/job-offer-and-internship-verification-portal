# OfferCheck v2 - Job Offer Verification Portal

## Run it (Windows)
Extract the zip, open the `portal` folder, double-click **run.bat**. The browser opens by itself.
Manual way: `pip install -r requirements.txt` then `python app.py`, then open http://127.0.0.1:5000

## What's new in v2
- **Login / register** (passwords hashed, 7-day session, login lock after 5 wrong attempts)
- **Private history per user** - view, delete one, clear all, auto-delete oldest after 50
- **Stricter checks**: brand look-alike domains (amaz0n, paytrn), disposable emails, CIN format,
  live domain-age + SSL certificate + DNS checks, link scanning inside messages/letters,
  pay-vs-role sanity check, Hinglish scam patterns
- **Confidence %** on every result + **model accuracy** page (tested on unseen messages)
- **Tips to improve** on every result, and a new **Resume checker** (ATS score, red flags, prioritised tips)
- Rate limit (20 checks/min per user), security headers, safe error messages

## Settings (environment variables, all optional)
`LIVE_CHECKS=0` turn off internet checks | `HISTORY_LIMIT=50` | `RATE_LIMIT_PER_MIN=20` | `SECRET_KEY=...`

## Structure
```
app.py            routes: auth, verify (5 modules), history, model-info
config.py         limits and settings          db.py   users + history (SQLite)
modules/          company, offer_letter, message, url_check, resume, brands, live, risk
ml/               train.py (trains + evaluates), data/messages.csv
static/           index.html, style.css, app.js
tests/            20 automatic tests:  python -m unittest tests.test_api
```

## Honest limits
- ML dataset is ~150 messages: replace ml/data/messages.csv with a large real dataset and run `python -m ml.train`.
- Live checks need internet; offline they are skipped (result says "Offline checks only").
- Company existence / CIN is checked by format only (verify on mca.gov.in).
- Scanned image PDFs are not supported. SQLite for now (MySQL planned).
