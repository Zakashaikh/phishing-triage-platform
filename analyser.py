import argparse
import csv
import os
import sys

import enrichment
import parse
import report as report_mod
import scoring
from attachments import extract_attachments


def analyse_file(filepath, use_api=True, output_dir=None, json_only=False):
    """Analyse one .eml; write its JSON report; return a summary row."""
    email_data = parse.parse_email(filepath)
    atts = extract_attachments(filepath)
    score_result = scoring.score_email(email_data, atts)

    if use_api and enrichment.vt_available():
        url_results = [enrichment.check_url(u["url"]) for u in email_data["urls"]]
        ip_results = [enrichment.check_ip(ip) for ip in email_data["ips"]]
        file_results = [enrichment.check_file_hash(a["sha256"]) for a in atts]
    else:
        reason = "disabled (--no-api)" if not use_api else "no API key"
        url_results = [{"url": u["url"], "skipped": True, "reason": reason} for u in email_data["urls"]]
        ip_results = [{"ip": ip, "skipped": True, "reason": reason} for ip in email_data["ips"]]
        file_results = [{"sha256": a["sha256"], "skipped": True, "reason": reason} for a in atts]

    fv = scoring.final_verdict(score_result, url_results, ip_results, file_results)
    rep = report_mod.build_report(email_data, atts, score_result, fv,
                                  url_results, ip_results, file_results)
    if not json_only:
        report_mod.print_report(rep)

    out_dir = output_dir or os.path.dirname(os.path.abspath(filepath))
    base = os.path.splitext(os.path.basename(filepath))[0]
    report_path = os.path.join(out_dir, base + "_report.json")
    report_mod.save_report(report_path, rep)
    if not json_only:
        print(f"Report saved to {report_path}")

    return {"file": os.path.basename(filepath), "score": rep["score"],
            "verdict": fv, "error": ""}


def analyse_folder(folder, use_api=True, output_dir=None, json_only=False):
    """Analyse every .eml in a folder; write summary.csv; never abort on one bad email."""
    names = sorted(f for f in os.listdir(folder) if f.lower().endswith(".eml"))
    if not names:
        print(f"No .eml files found in {folder}")
        return []

    rows = []
    for name in names:
        try:
            rows.append(analyse_file(os.path.join(folder, name), use_api=use_api,
                                     output_dir=output_dir, json_only=json_only))
        except Exception as exc:
            rows.append({"file": name, "score": "", "verdict": "ERROR", "error": str(exc)})

    out_dir = output_dir or folder
    summary_path = os.path.join(out_dir, "summary.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "score", "verdict", "error"])
        writer.writeheader()
        writer.writerows(rows)

    errors = sum(1 for r in rows if r["verdict"] == "ERROR")
    print(f"\nAnalysed {len(rows)} email(s) ({errors} error(s)). Summary: {summary_path}")
    return rows


def main(argv=None):
    p = argparse.ArgumentParser(description="Phishing email analyser")
    p.add_argument("target", help=".eml file or folder of .eml files")
    p.add_argument("--no-api", action="store_true", help="skip VirusTotal lookups")
    p.add_argument("--json-only", action="store_true", help="suppress console report")
    p.add_argument("--output", help="directory for JSON reports and summary.csv")
    p.add_argument("--ml", action="store_true", help="also score with the trained ML model")
    args = p.parse_args(argv)

    if args.ml:
        print("ML mode is not available yet: no trained model in models/. Coming in Milestone 3.")
        return 2
    if args.output:
        os.makedirs(args.output, exist_ok=True)

    kwargs = dict(use_api=not args.no_api, output_dir=args.output, json_only=args.json_only)
    if os.path.isdir(args.target):
        analyse_folder(args.target, **kwargs)
    elif os.path.isfile(args.target):
        analyse_file(args.target, **kwargs)
    else:
        print(f"Not found: {args.target}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
