import json

ERROR_VALS = [0, "unknown", "timeout", "connection_error", "rate_limited"]

def generate_report(headers, url_results, ip_results):
    print("\n" + "="*60)
    print("PHISHING EMAIL ANALYSIS REPORT")
    print("="*60)
    print(f"\nFROM:  {headers['from']}")
    print(f"REPLY-TO: {headers['reply_to']}")
    print(f"SUBJECT: {headers['subject']}")
    print(f"\nSPF: {headers['spf']}")
    print(f"DKIM: {headers['dkim']}")
    print(f"DMARC: {headers['dmarc']}")

    print("\n--- URL ANALYSIS ---")
    if url_results:
        for result in url_results:
            m = result["malicious"]
            verdict = "MALICIOUS" if isinstance(m, int) and m > 0 else "UNKNOWN" if m in ERROR_VALS[1:] else "CLEAN"
            print(f"    URL: {result['url']}")
            print(f"    Malicious: {m} engines")
            print(f"    Verdict: {verdict}\n")
    else:
        print("  No URLs found in email body")

    print("--- IP ANALYSIS ---")
    if ip_results:
        for result in ip_results:
            m = result["malicious"]
            verdict = "MALICIOUS" if isinstance(m, int) and m > 0 else "UNKNOWN" if m in ERROR_VALS[1:] else "CLEAN"
            print(f"   IP: {result['ip']}")
            print(f"   Malicious: {m} engines")
            print(f"   Verdict: {verdict}\n")
    else:
        print(" NO IPs found in email headers")

    print("--- FINAL VERDICT ---")
    any_malicious = any(r["malicious"] not in ERROR_VALS for r in url_results + ip_results)
    spf_fail = headers["spf"] in ["fail", "softfail"]
    dkim_fail = headers["dkim"] == "fail"

    if any_malicious:
        print(" *** MALICIOUS - block and escalate immediately ***")
    elif spf_fail or dkim_fail:
        print(" *** SUSPICIOUS - authentication failures detected ***")
    else:
        print(" CLEAN - no threats detected")

    print("="*60)


def save_report(filepath, headers, url_results, ip_results):
    report = {
        "email": {
            "from": headers["from"],
            "reply_to": headers["reply_to"],
            "subject": headers["subject"],
            "date": headers["date"],
            "spf": headers["spf"],
            "dkim": headers["dkim"],
            "dmarc": headers["dmarc"],
        },
        "urls": url_results,
        "ips": ip_results,
        "verdict": _get_verdict(url_results, ip_results, headers)
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=4)
    print(f" Report saved to {filepath}")


def _get_verdict(url_results, ip_results, headers):
    any_malicious = any(r["malicious"] not in ERROR_VALS for r in url_results + ip_results)
    if any_malicious:
        return "MALICIOUS"
    elif headers["spf"] in ["fail", "softfail"] or headers["dkim"] == "fail":
        return "SUSPICIOUS"
    return "CLEAN"
