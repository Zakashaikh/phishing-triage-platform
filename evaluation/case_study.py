"""Generate a case-study writeup from modern phishing samples.

The main corpus (evaluation/RESULTS.md) is historical: its ham is from ~2003
and most of its phish predates SPF/DKIM/DMARC, so the authentication rules
barely fire there. This script closes that gap: point it at a folder (or
AES-encrypted zip) of *modern* .eml samples — e.g. exported from a spam
folder — and it writes evaluation/CASE_STUDIES.md showing, per email, the
verdict and exactly which rules fired, with auth-rule fire rates up front.

Recipient addresses are redacted and URLs defanged, so the output is safe
to commit even when the samples come from a personal mailbox.

Usage: venv\\Scripts\\python.exe evaluation\\case_study.py corpus\\live
       venv\\Scripts\\python.exe evaluation\\case_study.py corpus\\live.zip
"""
import argparse
import email
import os
import re
import sys
from email.utils import getaddresses

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)  # allow running as a script from repo root

import ml
import scoring
from attachments import extract_attachments
from evaluation.download_corpus import read_zip
from parse import parse_email

AUTH_RULE_IDS = ("spf_fail", "dkim_fail", "dmarc_fail")
DEFAULT_OUT = os.path.join(ROOT, "evaluation", "CASE_STUDIES.md")


def build_case(name, raw, ml_bundle=None):
    """Score one raw email; returns a case dict and never raises."""
    try:
        email_data = parse_email(raw)
        atts = extract_attachments(raw)
        result = scoring.score_email(email_data, atts)
        prob = (ml.predict_proba(ml_bundle, email_data, atts, result)
                if ml_bundle is not None else None)
        return {"name": name,
                "ml_prob": prob,
                "from_": email_data["from_"],
                "subject": email_data["subject"],
                "score": result["score"],
                "verdict": result["verdict"],
                "auth": {"spf": email_data["spf"], "dkim": email_data["dkim"],
                         "dmarc": email_data["dmarc"]},
                "findings": result["findings"],
                "urls": [u["url"] for u in email_data["urls"]][:5],
                "recipients": _recipients(raw),
                "error": ""}
    except Exception as exc:
        return {"name": name, "from_": "", "subject": "", "score": None,
                "verdict": "ERROR", "auth": {}, "findings": [], "urls": [],
                "recipients": [], "ml_prob": None,
                "error": f"{type(exc).__name__}: {exc}"}


def _recipients(raw):
    """Addresses from To/Cc/Delivered-To — redacted later in the writeup."""
    msg = email.message_from_bytes(raw)
    headers = []
    for h in ("To", "Cc", "Delivered-To", "X-Original-To"):
        headers += [(h, v) for v in (msg.get_all(h) or [])]
    return sorted({addr.lower() for _, v in headers
                   for _, addr in getaddresses([v]) if "@" in addr})


def redact(text, addresses):
    """Replace each address with [redacted], case-insensitively."""
    for addr in addresses:
        text = re.sub(re.escape(addr), "[redacted]", text, flags=re.IGNORECASE)
    return text


def defang(url):
    """hxxp://evil[.]example — safe to paste anywhere, never clickable."""
    scheme, _, rest = url.partition("://")
    host, sep, path = rest.partition("/")
    return scheme.replace("http", "hxxp") + "://" + host.replace(".", "[.]") + sep + path


def render_markdown(cases):
    """Full CASE_STUDIES.md content: summary table, auth stats, per-case detail."""
    scored = [c for c in cases if c["error"] == ""]
    auth_hits = sum(1 for c in scored
                    if any(f["rule_id"] in AUTH_RULE_IDS for f in c["findings"]))
    with_ml = any(c["ml_prob"] is not None for c in scored)

    lines = ["# Case studies — modern samples", ""]
    lines.append(f"{len(cases)} sample(s) analysed with the offline heuristic "
                 "detector (no VirusTotal). Unlike the historical evaluation "
                 "corpus (see RESULTS.md), these are modern messages that carry "
                 "`Authentication-Results` headers.")
    lines.append("")
    lines.append(f"**Authentication rules (SPF/DKIM/DMARC) fired on "
                 f"{auth_hits}/{len(scored)} scored samples** — on the 2003-era "
                 "corpus they fired on almost none, which is why they are "
                 "validated here separately.")
    if with_ml:
        rule_flags = sum(1 for c in scored if c["verdict"] != "CLEAN")
        ml_flags = sum(1 for c in scored
                       if c["ml_prob"] is not None and c["ml_prob"] >= 0.5)
        lines.append("")
        lines.append(f"**Rules flagged {rule_flags}/{len(scored)}** at the tuned "
                     f"high-precision operating point; **ML flagged "
                     f"{ml_flags}/{len(scored)}** at p ≥ 0.5.")

    ml_head = " ML p(phish) |" if with_ml else ""
    ml_sep = "-------------|" if with_ml else ""
    lines += ["", f"| File | Verdict | Score | SPF | DKIM | DMARC |{ml_head} Rules fired |",
              f"|------|---------|-------|-----|------|-------|{ml_sep}-------------|"]
    for c in cases:
        if c["error"]:
            dashes = "– | " * (7 if with_ml else 6)
            lines.append(f"| {c['name']} | ERROR | {dashes}{c['error']} |")
            continue
        a = c["auth"]
        ml_cell = (f" {c['ml_prob']:.3f} |"
                   if with_ml and c["ml_prob"] is not None else (" – |" if with_ml else ""))
        lines.append(f"| {c['name']} | {c['verdict']} | {c['score']} "
                     f"| {a['spf']} | {a['dkim']} | {a['dmarc']} |{ml_cell} "
                     f"{len(c['findings'])} |")

    for c in cases:
        if c["error"]:
            continue
        lines += ["", f"## {c['name']} — {c['verdict']} ({c['score']})", "",
                  f"- **From:** {c['from_']}",
                  f"- **Subject:** {c['subject']}"]
        if c["urls"]:
            lines.append("- **URLs (defanged):** " +
                         ", ".join(f"`{defang(u)}`" for u in c["urls"]))
        if c["findings"]:
            lines += ["", "| Rule | Points | Detail | ATT&CK |",
                      "|------|--------|--------|--------|"]
            for f in c["findings"]:
                lines.append(f"| `{f['rule_id']}` | {f['points']} "
                             f"| {f['detail']} | {f['mitre']} |")

    md = "\n".join(lines) + "\n"
    all_recipients = sorted({r for c in cases for r in c["recipients"]})
    return redact(md, all_recipients)


def load_samples(target):
    """Yield (name, raw_bytes) from a folder of .eml files or a corpus zip."""
    if os.path.isdir(target):
        for name in sorted(os.listdir(target)):
            if name.lower().endswith(".eml"):
                with open(os.path.join(target, name), "rb") as f:
                    yield name, f.read()
    elif os.path.isfile(target):
        yield from read_zip(target)
    else:
        raise FileNotFoundError(target)


def main(argv=None):
    p = argparse.ArgumentParser(description="Write CASE_STUDIES.md from modern .eml samples")
    p.add_argument("target", help="folder of .eml files, or an AES corpus zip")
    p.add_argument("--out", default=DEFAULT_OUT, help="output markdown path")
    p.add_argument("--ml", action="store_true",
                   help="also score each sample with the trained ML model")
    args = p.parse_args(argv)

    ml_bundle = ml.load_bundle() if args.ml else None
    if args.ml and ml_bundle is None:
        print("--ml requested but no trained model found in models/.")
        return 2

    cases = [build_case(name, raw, ml_bundle=ml_bundle)
             for name, raw in load_samples(args.target)]
    if not cases:
        print(f"No samples found in {args.target}")
        return 1

    md = render_markdown(cases)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(md)
    errors = sum(1 for c in cases if c["error"])
    print(f"Wrote {args.out}: {len(cases)} case(s), {errors} error(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
