"""Aggregate validation against the full modern phishing corpus.

CASE_STUDIES.md gives per-email detail for a handful of samples; this script
answers the statistical question — how much modern phish does each detector
actually catch? — across every sample in corpus/live.zip (see
download_live.py --all).

Honesty note baked into the output: phishing_pot is phish-only, so this
measures RECALL ONLY. It says nothing about false positives on modern
legitimate mail — that needs a modern ham source and is tracked as future
work. Precision claims come from the historical corpus (RESULTS.md).

Usage: venv\\Scripts\\python.exe evaluation\\validate_modern.py [target]
       (target defaults to corpus/live.zip; folder of .eml also works)
"""
import argparse
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)  # allow running as a script from repo root

import ml
from evaluation.case_study import AUTH_RULE_IDS, build_case, load_samples

DEFAULT_TARGET = os.path.join(ROOT, "corpus", "live.zip")
DEFAULT_OUT = os.path.join(ROOT, "evaluation", "MODERN_VALIDATION.md")


def summarize(cases):
    """Aggregate detection stats over build_case() dicts."""
    scored = [c for c in cases if c["error"] == ""]
    n = len(scored)
    with_ml = [c for c in scored if c["ml_prob"] is not None]

    rules_suspicious = sum(1 for c in scored if c["verdict"] != "CLEAN")
    rules_malicious = sum(1 for c in scored if c["verdict"] == "MALICIOUS")
    ml_flagged = sum(1 for c in with_ml if c["ml_prob"] >= 0.5)
    combined = sum(1 for c in scored
                   if c["verdict"] != "CLEAN"
                   or (c["ml_prob"] is not None and c["ml_prob"] >= 0.5))
    auth_fired = sum(1 for c in scored
                     if any(f["rule_id"] in AUTH_RULE_IDS for f in c["findings"]))

    rule_counts = Counter(f["rule_id"] for c in scored for f in c["findings"])

    return {
        "total": len(cases),
        "errors": len(cases) - n,
        "scored": n,
        "rules_suspicious": rules_suspicious,
        "rules_malicious": rules_malicious,
        "ml_scored": len(with_ml),
        "ml_flagged": ml_flagged,
        "combined": combined,
        "auth_fired": auth_fired,
        "rule_counts": rule_counts,
    }


def _pct(part, whole):
    return f"{100 * part / whole:.1f}%" if whole else "–"


def render(stats):
    """MODERN_VALIDATION.md content from summarize() output."""
    n = stats["scored"]
    lines = [
        "# Modern-corpus validation (recall only)",
        "",
        f"Every detector run against **{n} modern phishing samples** from "
        "[phishing_pot](https://github.com/rf-peixoto/phishing_pot) "
        f"(honeypot-collected, recipients anonymized by the maintainers); "
        f"{stats['errors']} of {stats['total']} samples failed to parse and are excluded.",
        "",
        "> **This measures recall only.** The corpus contains no legitimate "
        "mail, so nothing here speaks to false positives on modern ham — "
        "precision figures come from the historical corpus "
        "([RESULTS.md](RESULTS.md)), and a modern-ham evaluation is future work.",
        "",
        "| Detector | Flagged | Recall |",
        "|---|---:|---:|",
        f"| Rules, SUSPICIOUS operating point (score ≥ 20) "
        f"| {stats['rules_suspicious']}/{n} | {_pct(stats['rules_suspicious'], n)} |",
        f"| Rules, MALICIOUS operating point (score ≥ 50) "
        f"| {stats['rules_malicious']}/{n} | {_pct(stats['rules_malicious'], n)} |",
        f"| ML, p ≥ 0.5 | {stats['ml_flagged']}/{stats['ml_scored']} "
        f"| {_pct(stats['ml_flagged'], stats['ml_scored'])} |",
        f"| Rules OR ML (triage union) | {stats['combined']}/{n} "
        f"| {_pct(stats['combined'], n)} |",
        "",
        f"Authentication rules (SPF/DKIM/DMARC) fired on "
        f"**{stats['auth_fired']}/{n}** samples "
        f"({_pct(stats['auth_fired'], n)}) — on the 2003-era corpus they fired "
        "on almost none, which is why modern validation exists at all.",
        "",
        "## Per-rule fire rates on modern phish",
        "",
        "| Rule | Fired | Rate |",
        "|---|---:|---:|",
    ]
    for rule_id, count in stats["rule_counts"].most_common():
        lines.append(f"| `{rule_id}` | {count} | {_pct(count, n)} |")
    lines += [
        "",
        "Reproduce: `python evaluation/download_live.py --all` then "
        "`python evaluation/validate_modern.py`.",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description="Aggregate validation on modern samples")
    p.add_argument("target", nargs="?", default=DEFAULT_TARGET,
                   help="corpus zip or folder of .eml (default: corpus/live.zip)")
    p.add_argument("--out", default=DEFAULT_OUT, help="output markdown path")
    args = p.parse_args(argv)

    ml_bundle = ml.load_bundle()
    if ml_bundle is None:
        print("No trained model in models/ — reporting rules only.")

    cases = []
    for i, (name, raw) in enumerate(load_samples(args.target), 1):
        cases.append(build_case(name, raw, ml_bundle=ml_bundle))
        if i % 250 == 0:
            print(f"  scored {i} samples...")
    if not cases:
        print(f"No samples found in {args.target}")
        return 1

    stats = summarize(cases)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render(stats))

    n = stats["scored"]
    print(f"\n{n} scored ({stats['errors']} parse errors)")
    print(f"rules >= SUSPICIOUS: {stats['rules_suspicious']}/{n}")
    print(f"rules >= MALICIOUS:  {stats['rules_malicious']}/{n}")
    print(f"ML p >= 0.5:         {stats['ml_flagged']}/{stats['ml_scored']}")
    print(f"rules OR ML:        {stats['combined']}/{n}")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
