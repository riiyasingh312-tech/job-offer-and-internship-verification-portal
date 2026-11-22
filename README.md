# Job Offer Verification Portal - Backend (Flask)

## Run it
```bash
pip install -r requirements.txt
python app.py            # then open http://127.0.0.1:5000 in your browser
python -m unittest tests.test_api -v   # run tests
```
The ML model trains automatically on first run (or manually: `python -m ml.train`).

## API (all return the same shape)
| Method | Endpoint | Body |
|---|---|---|
| GET  | `/api/health` | - |
| POST | `/api/verify/company` | `{"name","website","email"}` |
| POST | `/api/verify/offer-letter` | PDF in form field `file` **or** `{"text": "..."}` |
| POST | `/api/verify/message` | `{"text": "..."}` |
| POST | `/api/verify/url` | `{"url": "..."}` |
| GET  | `/api/history?limit=20` | - |

Response:
```json
{"module":"message","risk_score":83,"risk_level":"High Risk / Likely Fake",
 "flags":["Asks for a fee/deposit - genuine employers never charge candidates"],
 "details":{"ml_scam_probability":0.65},"id":12}
```
Levels: **0-34 Likely Genuine - 35-64 Suspicious - 65-100 High Risk / Likely Fake**

## Structure
```
app.py            Flask routes (also serves the website)
static/           Frontend: index.html, style.css, app.js
config.py         paths / settings
db.py             history storage (SQLite now, MySQL later - only this file changes)
modules/          company.py, offer_letter.py, message.py, url_check.py, risk.py
ml/train.py       trains the classifier from ml/data/messages.csv
tests/            API tests
```

## Next steps
1. Replace `ml/data/messages.csv` (60 sample rows) with a real dataset, e.g. a Kaggle fake-job-postings dataset, then retrain.
2. Move `db.py` to MySQL.
