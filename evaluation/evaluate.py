"""Run the offline detector over the labeled corpus and report metrics.

Usage: venv\\Scripts\\python.exe evaluation\\evaluate.py
Outputs: console summary, evaluation/results.csv, evaluation/*.png (all gitignored).
"""
import argparse
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)  # allow running as a script from repo root

import scoring
from attachments import extract_attachments
from evaluation.download_corpus import read_zip
from parse import parse_email


def score_bytes(raw):
    """Score one raw email offline; returns a row dict and never raises."""
    try:
        email_data = parse_email(raw)
        atts = extract_attachments(raw)
        result = scoring.score_email(email_data, atts)
        return {"score": result["score"],
                "rule_ids": [f["rule_id"] for f in result["findings"]],
                "error": ""}
    except Exception as exc:
        return {"score": None, "rule_ids": [],
                "error": f"{type(exc).__name__}: {exc}"}


def score_file(path):
    """Score one .eml file on disk; returns a row dict and never raises."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        return {"score": None, "rule_ids": [], "error": f"{type(exc).__name__}: {exc}"}
    return score_bytes(raw)


def evaluate_corpus(corpus_dir):
    """Score every message in corpus/{phish,ham}.zip; returns list of row dicts.

    Messages stay in memory throughout - phishing samples are never written
    to disk unencrypted (antivirus would quarantine them).
    """
    rows = []
    for label in ("phish", "ham"):
        zip_path = os.path.join(corpus_dir, f"{label}.zip")
        if not os.path.exists(zip_path):
            continue
        for name, raw in read_zip(zip_path):
            row = score_bytes(raw)
            row.update({"file": f"{label}/{name}", "label": label})
            rows.append(row)
    return rows


def metrics_at(rows, threshold):
    """Confusion matrix and derived metrics, flagging at score >= threshold."""
    scored = [r for r in rows if r["error"] == ""]
    tp = sum(1 for r in scored if r["label"] == "phish" and r["score"] >= threshold)
    fn = sum(1 for r in scored if r["label"] == "phish" and r["score"] < threshold)
    fp = sum(1 for r in scored if r["label"] == "ham" and r["score"] >= threshold)
    tn = sum(1 for r in scored if r["label"] == "ham" and r["score"] < threshold)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def threshold_sweep(rows, thresholds=range(5, 100, 5)):
    return [metrics_at(rows, t) for t in thresholds]


def per_rule_stats(rows):
    """rule_id -> fraction of each class it fires on (high ham_rate = noisy rule)."""
    scored = [r for r in rows if r["error"] == ""]
    n_phish = sum(1 for r in scored if r["label"] == "phish") or 1
    n_ham = sum(1 for r in scored if r["label"] == "ham") or 1
    counts = {}
    for r in scored:
        for rid in set(r["rule_ids"]):
            counts.setdefault(rid, {"phish": 0, "ham": 0})[r["label"]] += 1
    return {rid: {"phish_rate": c["phish"] / n_phish, "ham_rate": c["ham"] / n_ham}
            for rid, c in sorted(counts.items())}


def save_results_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file", "label", "score", "rule_ids", "error"])
        w.writeheader()
        for r in rows:
            w.writerow({**r, "rule_ids": ";".join(r["rule_ids"])})


def save_charts(rows, sweep, out_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    scored = [r for r in rows if r["error"] == ""]
    phish = [r["score"] for r in scored if r["label"] == "phish"]
    ham = [r["score"] for r in scored if r["label"] == "ham"]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bins = range(0, 105, 5)
    ax.hist(ham, bins=bins, alpha=0.6, label=f"legitimate (n={len(ham)})", color="#2a9d8f")
    ax.hist(phish, bins=bins, alpha=0.6, label=f"phishing (n={len(phish)})", color="#e63946")
    ax.set_xlabel("heuristic score")
    ax.set_ylabel("emails")
    ax.set_title("Score distribution by class")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "score_distribution.png"), dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    xs = [m["threshold"] for m in sweep]
    ax.plot(xs, [m["precision"] for m in sweep], marker="o", label="precision")
    ax.plot(xs, [m["recall"] for m in sweep], marker="o", label="recall")
    ax.plot(xs, [m["fpr"] for m in sweep], marker="o", label="false-positive rate")
    ax.set_xlabel("flag threshold (score >=)")
    ax.set_ylim(0, 1.05)
    ax.set_title("Detection metrics vs threshold")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "threshold_sweep.png"), dpi=150)
    plt.close(fig)


def main(argv=None):
    p = argparse.ArgumentParser(description="Evaluate detector on the labeled corpus")
    p.add_argument("--corpus", default=os.path.join(ROOT, "corpus"))
    args = p.parse_args(argv)

    rows = evaluate_corpus(args.corpus)
    if not rows:
        print("No corpus found. Run: python evaluation/download_corpus.py")
        return 1

    errors = sum(1 for r in rows if r["error"])
    sweep = threshold_sweep(rows)
    out_dir = os.path.join(ROOT, "evaluation")
    save_results_csv(rows, os.path.join(out_dir, "results.csv"))
    save_charts(rows, sweep, out_dir)

    print(f"emails: {len(rows)} (parse errors: {errors})")
    print(f"{'thr':>4} {'prec':>7} {'recall':>7} {'f1':>7} {'fpr':>7}")
    for m in sweep:
        print(f"{m['threshold']:>4} {m['precision']:>7.3f} {m['recall']:>7.3f} "
              f"{m['f1']:>7.3f} {m['fpr']:>7.3f}")

    print("\nOperating points (current verdict thresholds):")
    for t in (scoring.SUSPICIOUS_THRESHOLD, scoring.MALICIOUS_THRESHOLD):
        m = metrics_at(rows, t)
        print(f"  flag at >= {t}: precision {m['precision']:.3f}, "
              f"recall {m['recall']:.3f}, FP rate {m['fpr']:.3f}")

    print("\nPer-rule fire rates:")
    print(f"  {'rule':<24} {'phish':>8} {'ham':>8}")
    for rid, s in per_rule_stats(rows).items():
        print(f"  {rid:<24} {s['phish_rate']:>7.1%} {s['ham_rate']:>7.1%}")

    print(f"\nWrote results.csv, score_distribution.png, threshold_sweep.png to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
