import argparse
import csv
import os
import sys

import enrichment
import iocs
import ml
import parse
import report as report_mod
import scoring
from attachments import extract_attachments


def analyse_email(source, use_api=True, ml_bundle=None):
    """Run the full pipeline on an .eml path or raw bytes; returns the report dict.

    Shared by the CLI (analyse_file) and the web dashboard (webapp/app.py).
    """
    email_data = parse.parse_email(source)
    atts = extract_attachments(source)
    score_result = scoring.score_email(email_data, atts)

    if use_api and enrichment.vt_available():
        url_results = [enrichment.check_url(u["url"]) for u in email_data["urls"]]
        ip_results = [enrichment.check_ip(ip) for ip in email_data["ips"]]
        file_results = [enrichment.check_file_hash(a["sha256"]) for a in atts]
    else:
        reason = "disabled (offline mode)" if not use_api else "no API key"
        url_results = [{"url": u["url"], "skipped": True, "reason": reason} for u in email_data["urls"]]
        ip_results = [{"ip": ip, "skipped": True, "reason": reason} for ip in email_data["ips"]]
        file_results = [{"sha256": a["sha256"], "skipped": True, "reason": reason} for a in atts]

    fv = scoring.final_verdict(score_result, url_results, ip_results, file_results)

    ml_info = None
    if ml_bundle is not None:
        prob = ml.predict_proba(ml_bundle, email_data, atts, score_result)
        combined = ml.combined_verdict(score_result["verdict"], prob)
        fv = scoring.final_verdict({"verdict": combined}, url_results, ip_results, file_results)
        ml_info = {"probability": prob, "verdict": ml.ml_verdict(prob),
                   "config": ml_bundle["config"]}

    return report_mod.build_report(email_data, atts, score_result, fv,
                                   url_results, ip_results, file_results, ml=ml_info)


def analyse_file(filepath, use_api=True, output_dir=None, json_only=False, ml_bundle=None,
                 ioc_sink=None):
    """Analyse one .eml; write its JSON report; return a summary row."""
    rep = analyse_email(filepath, use_api=use_api, ml_bundle=ml_bundle)
    if ioc_sink is not None:
        ioc_sink.extend(iocs.extract_iocs(rep, source=os.path.basename(filepath)))
    if not json_only:
        report_mod.print_report(rep)

    out_dir = output_dir or os.path.dirname(os.path.abspath(filepath))
    base = os.path.splitext(os.path.basename(filepath))[0]
    report_path = os.path.join(out_dir, base + "_report.json")
    report_mod.save_report(report_path, rep)
    if not json_only:
        print(f"Report saved to {report_path}")

    return {"file": os.path.basename(filepath), "score": rep["score"],
            "verdict": rep["final_verdict"], "error": ""}


def analyse_folder(folder, use_api=True, output_dir=None, json_only=False, ml_bundle=None,
                   ioc_sink=None):
    """Analyse every .eml in a folder; write summary.csv; never abort on one bad email."""
    names = sorted(f for f in os.listdir(folder) if f.lower().endswith(".eml"))
    if not names:
        print(f"No .eml files found in {folder}")
        return []

    rows = []
    for name in names:
        try:
            rows.append(analyse_file(os.path.join(folder, name), use_api=use_api,
                                     output_dir=output_dir, json_only=json_only,
                                     ml_bundle=ml_bundle, ioc_sink=ioc_sink))
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
    p.add_argument("--extract-iocs", action="store_true",
                   help="write blocklist-ready iocs.csv from SUSPICIOUS/MALICIOUS emails")
    args = p.parse_args(argv)

    ml_bundle = None
    if args.ml:
        ml_bundle = ml.load_bundle()
        if ml_bundle is None:
            print("--ml requested but no trained model found in models/. "
                  "Run: python evaluation/train.py")
            return 2
    if args.output:
        os.makedirs(args.output, exist_ok=True)

    ioc_sink = [] if args.extract_iocs else None
    kwargs = dict(use_api=not args.no_api, output_dir=args.output,
                  json_only=args.json_only, ml_bundle=ml_bundle, ioc_sink=ioc_sink)
    if os.path.isdir(args.target):
        analyse_folder(args.target, **kwargs)
        default_out = args.target
    elif os.path.isfile(args.target):
        analyse_file(args.target, **kwargs)
        default_out = os.path.dirname(os.path.abspath(args.target))
    else:
        print(f"Not found: {args.target}")
        return 1

    if ioc_sink is not None:
        ioc_path = os.path.join(args.output or default_out, "iocs.csv")
        count = iocs.write_iocs_csv(ioc_path, ioc_sink)
        print(f"Extracted {count} unique IOC(s) -> {ioc_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
