"""Turn analysis reports into an actionable IOC list.

A verdict alone doesn't feed the next SOC step; blocklists and watchlists do.
extract_iocs pulls URLs, domains, IPs, attachment hashes, and sender/reply-to
addresses out of a report — but only when the email scored SUSPICIOUS or
MALICIOUS: harvesting IOCs from clean mail would poison a blocklist with
legitimate domains.

Each row carries both the raw value (for machine ingestion — a firewall needs
the real domain) and a defanged copy (safe to paste into tickets and chat).
"""
import csv
from email.utils import parseaddr
from urllib.parse import urlparse

from report import defang

EXTRACT_VERDICTS = ("SUSPICIOUS", "MALICIOUS")
CSV_FIELDS = ("type", "value", "defanged", "source", "verdict")


def extract_iocs(report, source=""):
    """Return IOC rows from one report dict; [] for CLEAN/ERROR emails."""
    verdict = report["final_verdict"]
    if verdict not in EXTRACT_VERDICTS:
        return []

    rows = []

    def add(ioc_type, value):
        if value:
            rows.append({"type": ioc_type, "value": value, "defanged": defang(value),
                         "source": source, "verdict": verdict})

    for url in report["urls"]:
        add("url", url)
        try:
            add("domain", (urlparse(url).hostname or "").lower())
        except ValueError:
            pass
    for ip in report["ips"]:
        add("ip", ip)
    for att in report["attachments"]:
        add("sha256", att["sha256"])
    add("sender", parseaddr(report["email"]["from_"])[1])
    add("reply_to", parseaddr(report["email"]["reply_to"])[1])
    return rows


def write_iocs_csv(path, rows):
    """Write deduplicated IOC rows (first sighting wins); returns count written."""
    seen = {}
    for r in rows:
        seen.setdefault((r["type"], r["value"]), r)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(seen.values())
    return len(seen)
