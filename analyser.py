import sys, os
from parse import parse_email
from enrichment import check_url, check_ip
from report import generate_report, save_report

def analyse(filepath):
    print(f"\nAnalyzing: {filepath}")

    headers = parse_email(filepath)
    url_results = [check_url(url) for url in headers["urls"]]
    ip_results = [check_ip(ip) for ip in headers["ips"]]

    generate_report(headers, url_results, ip_results)

    report_path = filepath.replace(".eml", "_report.json")
    save_report(report_path, headers, url_results, ip_results)

def analyse_folder(folder_path):
    emails = [f for f in os.listdir(folder_path) if f.endswith(".eml")]

    if not emails:
        print(f"No .eml files found in {folder_path}")
        return

    print(f"\nFound {len(emails)} email(s) to analyse...")

    results = []
    for email_file in emails:
        full_path = os.path.join(folder_path, email_file)
        analyse(full_path)
        results.append(email_file)

    print(f"\n{'='*60}")
    print(f"BULK SCAN COMPLETE - {len(results)} email(s) analysed")
    print(f"Reports saved alongside each .eml file")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyser.py sample.eml")
        print("       python analyser.py /path/to/folder/")
    else:
        target = sys.argv[1]
        if os.path.isdir(target):
            analyse_folder(target)
        else:
            analyse(target)
