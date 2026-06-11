"""Train and compare ML classifiers against the hand-written rules.

Run: venv\\Scripts\\python.exe evaluation\\train.py
Outputs: console comparison table, evaluation/model_comparison.csv,
         evaluation/roc_curve.png, and models/model.joblib (gitignored).
"""
import argparse
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

import features
import scoring
from attachments import extract_attachments
from evaluation.download_corpus import read_zip
from parse import parse_email

MAX_TFIDF = 1000
N_RULES = len(scoring.RULE_IDS)
MODEL_PATH = os.path.join(ROOT, "models", "model.joblib")


def build_dataset(corpus_dir, use_rule_features=True):
    """Parse+score every corpus message; return (struct_rows, texts, labels)."""
    struct_rows, texts, labels = [], [], []
    for label_name, y in (("phish", 1), ("ham", 0)):
        zip_path = os.path.join(corpus_dir, f"{label_name}.zip")
        if not os.path.exists(zip_path):
            continue
        for _name, raw in read_zip(zip_path):
            try:
                email_data = parse_email(raw)
                atts = extract_attachments(raw)
                sr = scoring.score_email(email_data, atts)
            except Exception:
                continue
            struct_rows.append(features.numeric_features(email_data, atts, sr, use_rule_features))
            texts.append(features.email_text(email_data))
            labels.append(y)
    return struct_rows, texts, labels


def evaluate_predictions(y_true, y_pred):
    yt, yp = np.asarray(y_true), np.asarray(y_pred)
    tp = int(np.sum((yt == 1) & (yp == 1)))
    fp = int(np.sum((yt == 0) & (yp == 1)))
    fn = int(np.sum((yt == 1) & (yp == 0)))
    tn = int(np.sum((yt == 0) & (yp == 0)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def _heuristic_score_column(struct_rows):
    """heuristic_score is the last structural feature (see features.STRUCT_NAMES)."""
    return np.asarray(struct_rows, dtype=float)[:, -1]


def train_and_compare(struct_rows, texts, y, seed=42):
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.2, random_state=seed, stratify=y)
    y = np.asarray(y)
    struct = np.asarray(struct_rows, dtype=float)
    texts = list(texts)

    vec = TfidfVectorizer(max_features=MAX_TFIDF).fit([texts[i] for i in tr])
    X_full = features.assemble_matrix(struct, texts, vec)          # rule + struct + tfidf
    X_text = X_full[:, N_RULES:]                                   # struct + tfidf only

    results, curves, candidates = [], [], []

    # 1) rules-only baseline: threshold the heuristic score
    hscore = _heuristic_score_column(struct)
    rules_pred = (hscore[te] >= scoring.SUSPICIOUS_THRESHOLD).astype(int)
    results.append({"config": "rules_only", **evaluate_predictions(y[te], rules_pred),
                    "roc_auc": float("nan")})

    def run(name, model, X, use_rule_features):
        model.fit(X[tr], y[tr])
        prob = model.predict_proba(X[te])[:, 1]
        pred = (prob >= 0.5).astype(int)
        auc = roc_auc_score(y[te], prob)
        results.append({"config": name, **evaluate_predictions(y[te], pred), "roc_auc": auc})
        fpr_c, tpr_c, _ = roc_curve(y[te], prob)
        curves.append((name, fpr_c, tpr_c, auc))
        candidates.append({"config": name, "auc": auc, "model": model,
                           "vectorizer": vec, "use_rule_features": use_rule_features})

    run("logreg_text", LogisticRegression(max_iter=1000), X_text, False)
    run("logreg_hybrid", LogisticRegression(max_iter=1000), X_full, True)
    # HistGradientBoosting needs a dense array.
    run("histgbm_hybrid", HistGradientBoostingClassifier(random_state=seed),
        X_full.toarray(), True)

    best = max(candidates, key=lambda c: c["auc"])
    bundle = {"model": best["model"], "vectorizer": best["vectorizer"],
              "use_rule_features": best["use_rule_features"],
              "struct_names": features.STRUCT_NAMES, "config": best["config"]}
    return results, bundle, curves


def save_roc(curves, out_path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6.5, 6))
    for name, fpr_c, tpr_c, auc in curves:
        ax.plot(fpr_c, tpr_c, label=f"{name} (AUC={auc:.3f})")
    ax.plot([0, 1], [0, 1], "--", color="gray", label="chance")
    ax.set_xlabel("false-positive rate")
    ax.set_ylabel("true-positive rate (recall)")
    ax.set_title("ROC: ML models on held-out test set")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)


def main(argv=None):
    p = argparse.ArgumentParser(description="Train and compare ML vs rules")
    p.add_argument("--corpus", default=os.path.join(ROOT, "corpus"))
    args = p.parse_args(argv)

    struct, texts, y = build_dataset(args.corpus)
    if not y or len(set(y)) < 2:
        print("Need both classes. Run: python evaluation/download_corpus.py")
        return 1

    results, bundle, curves = train_and_compare(struct, texts, y)
    out_dir = os.path.join(ROOT, "evaluation")
    save_roc(curves, os.path.join(out_dir, "roc_curve.png"))
    with open(os.path.join(out_dir, "model_comparison.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["config", "precision", "recall", "f1", "fpr", "roc_auc"])
        w.writeheader()
        w.writerows(results)

    os.makedirs(os.path.join(ROOT, "models"), exist_ok=True)
    joblib.dump(bundle, MODEL_PATH)

    n = len(y)
    print(f"dataset: {n} emails ({sum(y)} phish / {n - sum(y)} ham), "
          f"held-out test = {round(n * 0.2)}")
    print(f"{'config':<16} {'prec':>7} {'recall':>7} {'f1':>7} {'fpr':>7} {'auc':>7}")
    for r in results:
        auc = "  n/a" if r["roc_auc"] != r["roc_auc"] else f"{r['roc_auc']:.3f}"
        print(f"{r['config']:<16} {r['precision']:>7.3f} {r['recall']:>7.3f} "
              f"{r['f1']:>7.3f} {r['fpr']:>7.3f} {auc:>7}")
    print(f"\nbest model: {bundle['config']} -> saved to {MODEL_PATH}")
    print(f"wrote roc_curve.png, model_comparison.csv to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
