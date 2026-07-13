import json


def defang(ioc):
    """Make an IOC safe to share: hxxp scheme, bracketed dots."""
    return ioc.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def build_report(email_data, attachments, score_result, final_verdict_value,
                 url_results, ip_results, file_results, ml=None):
    """Assemble the JSON-serializable report dict (schema documented in README)."""
    email_keys = ("from_", "from_display", "from_domain", "reply_to", "reply_to_domain",
                  "return_path", "return_path_domain", "subject", "date",
                  "spf", "dkim", "dmarc", "has_html")
    email_out = {k: email_data[k] for k in email_keys}
    if email_data.get("auth_source") == "verified":
        email_out["auth_source"] = "verified"
        email_out["auth_reported"] = email_data["auth_reported"]
        email_out["auth_details"] = email_data["auth_details"]
    return {
        "email": email_out,
        "urls": [u["url"] for u in email_data["urls"]],
        "ips": email_data["ips"],
        "parse_errors": email_data["parse_errors"],
        "attachments": attachments,
        "findings": score_result["findings"],
        "score": score_result["score"],
        "heuristic_verdict": score_result["verdict"],
        "final_verdict": final_verdict_value,
        "enrichment": {"urls": url_results, "ips": ip_results, "files": file_results},
        "ml": ml,
        "body_preview": email_data["body_text"][:2000],
    }


def save_report(filepath, report):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def print_report(report):
    e = report["email"]
    print("\n" + "=" * 60)
    print("PHISHING EMAIL ANALYSIS REPORT")
    print("=" * 60)
    print(f"FROM:     {e['from_']}")
    print(f"REPLY-TO: {e['reply_to'] or '-'}")
    print(f"SUBJECT:  {e['subject']}")
    if e.get("auth_source") == "verified":
        print(f"SPF: {e['spf']}   DKIM: {e['dkim']}   DMARC: {e['dmarc']}   (verified via DNS/crypto)")
        r = e["auth_reported"]
        print(f"  header-reported: spf={r['spf']} dkim={r['dkim']} dmarc={r['dmarc']}")
    else:
        print(f"SPF: {e['spf']}   DKIM: {e['dkim']}   DMARC: {e['dmarc']}")

    print(f"\nSCORE: {report['score']}/100  ({report['heuristic_verdict']})")
    print("\n--- FINDINGS ---")
    if report["findings"]:
        for f in report["findings"]:
            print(f"  +{f['points']:<3} {f['rule_id']:<22} {f['detail']} [{f['mitre']}]")
    else:
        print("  none")

    print("\n--- URLS ---")
    for url in report["urls"] or []:
        print(f"  {defang(url)}")
    if not report["urls"]:
        print("  none")

    print("\n--- IPS ---")
    for ip in report["ips"] or []:
        print(f"  {defang(ip)}")
    if not report["ips"]:
        print("  none")

    print("\n--- ATTACHMENTS ---")
    for a in report["attachments"] or []:
        flags = []
        if a["is_dangerous_ext"]:
            flags.append("DANGEROUS-EXT")
        if a["is_macro_doc"]:
            flags.append("MACRO")
        flag_text = f" [{', '.join(flags)}]" if flags else ""
        print(f"  {a['filename']} ({a['size']} bytes, sha256 {a['sha256'][:16]}...){flag_text}")
    if not report["attachments"]:
        print("  none")

    print("\n--- VIRUSTOTAL ---")
    rows = (report["enrichment"]["urls"] + report["enrichment"]["ips"]
            + report["enrichment"]["files"])
    for r in rows:
        ioc = r.get("url") or r.get("ip") or r.get("sha256") or "?"
        if r.get("skipped"):
            print(f"  {defang(ioc)}: skipped ({r['reason']})")
        else:
            print(f"  {defang(ioc)}: malicious={r.get('malicious')}")
    if not rows:
        print("  no lookups")

    if report["parse_errors"]:
        print("\n--- PARSE WARNINGS ---")
        for w in report["parse_errors"]:
            print(f"  {w}")

    if report.get("ml"):
        m = report["ml"]
        print("\n--- MACHINE LEARNING ---")
        print(f"  model: {m['config']}")
        print(f"  phishing probability: {m['probability']:.3f}  -> {m['verdict']}")
        if m.get("explain"):
            print("  why (ablation attribution; +pushes toward phish):")
            for c in m["explain"]:
                print(f"    {c['delta']:+.3f}  {c['feature']}")

    print(f"\nFINAL VERDICT: {report['final_verdict']}")
    print("=" * 60)
