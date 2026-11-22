"""Train and EVALUATE the scam-message classifier.

Run:  python -m ml.train
Outputs: ml/message_model.joblib (the model) and ml/metrics.json (honest test-set accuracy).

To improve accuracy: add more rows to ml/data/messages.csv (columns: text,label; 1 = scam, 0 = genuine)
- ideally thousands from a real dataset such as a Kaggle fake-job-postings dataset - then run this again.
"""
import csv
import json
import os
import sys
from datetime import datetime, timezone

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config  # noqa: E402


def load_data(path=config.DATA_PATH):
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), sublinear_tf=True, min_df=1)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=3.0)),
    ])


def train(save_path=config.MODEL_PATH, verbose=True):
    texts, labels = load_data()

    # honest evaluation: train on 75%, test on the 25% the model has never seen
    X_tr, X_te, y_tr, y_te = train_test_split(texts, labels, test_size=0.25, stratify=labels, random_state=42)
    ev = build_pipeline().fit(X_tr, y_tr)
    pred = ev.predict(X_te)
    cv = cross_val_score(build_pipeline(), texts, labels, cv=5, scoring="accuracy")
    metrics = {
        "samples": len(texts), "train_samples": len(X_tr), "test_samples": len(X_te),
        "accuracy": round(accuracy_score(y_te, pred) * 100, 1),
        "precision": round(precision_score(y_te, pred) * 100, 1),
        "recall": round(recall_score(y_te, pred) * 100, 1),
        "f1": round(f1_score(y_te, pred) * 100, 1),
        "cv_accuracy": round(cv.mean() * 100, 1),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "Evaluated on a small held-out test set; accuracy on real-world messages will be lower. "
                "Add a larger dataset and retrain for a more reliable number.",
    }
    with open(config.METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    final = build_pipeline().fit(texts, labels)        # final model learns from everything
    joblib.dump(final, save_path)
    if verbose:
        print(json.dumps(metrics, indent=2))
    return final


def get_metrics():
    if not os.path.exists(config.METRICS_PATH):
        train(verbose=False)
    with open(config.METRICS_PATH) as f:
        return json.load(f)


if __name__ == "__main__":
    train()
