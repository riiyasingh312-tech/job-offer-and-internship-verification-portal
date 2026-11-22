"""Train the scam-message classifier.

Run:  python -m ml.train
Replace ml/data/messages.csv with a bigger dataset (e.g. a fake-job-postings
dataset from Kaggle) to improve accuracy - columns: text,label (1 = scam, 0 = genuine).
"""
import csv
import os
import sys

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
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
    model = build_pipeline()
    if verbose:
        scores = cross_val_score(build_pipeline(), texts, labels, cv=5, scoring="accuracy")
        print(f"Samples: {len(texts)} | 5-fold CV accuracy: {scores.mean():.2f} (+/- {scores.std():.2f})")
    model.fit(texts, labels)
    joblib.dump(model, save_path)
    if verbose:
        print(f"Model saved to {save_path}")
    return model


if __name__ == "__main__":
    train()
