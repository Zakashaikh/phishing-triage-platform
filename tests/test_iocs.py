import csv
import os

import analyser
import iocs

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def report_for(name):
    return analyser.analyse_email(os.path.join(FIXTURES, name), use_api=False)


# --- extract_iocs -----------------------------------------------------------

def test_extract_from_malicious_email():
    rows = iocs.extract_iocs(report_for("spoofed.eml"), source="spoofed.eml")
    by_type = {}
    for r in rows:
        by_type.setdefault(r["type"], []).append(r["value"])
    assert "http://paypal-secure.top/verify" in by_type["url"]
    assert "paypal-secure.top" in by_type["domain"]
    assert "support@gmail.com" in by_type["sender"]
    assert "refunds@mail.ru" in by_type["reply_to"]
    assert all(r["source"] == "spoofed.eml" for r in rows)
    assert all(r["verdict"] == "MALICIOUS" for r in rows)


def test_extract_includes_attachment_hash():
    rows = iocs.extract_iocs(report_for("attachment.eml"), source="attachment.eml")
    sha_rows = [r for r in rows if r["type"] == "sha256"]
    assert len(sha_rows) == 1
    assert len(sha_rows[0]["value"]) == 64


def test_clean_email_yields_no_iocs():
    # blocklisting IOCs from clean mail would poison a watchlist
    assert iocs.extract_iocs(report_for("clean.eml"), source="clean.eml") == []


def test_values_are_defanged_in_the_defanged_column():
    rows = iocs.extract_iocs(report_for("spoofed.eml"), source="spoofed.eml")
    url = next(r for r in rows if r["type"] == "url")
    assert url["defanged"] == "hxxp://paypal-secure[.]top/verify"
    # raw value stays intact for machine ingestion (blocklists need real IOCs)
    assert url["value"].startswith("http://")


# --- write_iocs_csv ---------------------------------------------------------

def test_write_iocs_csv_dedupes(tmp_path):
    rows = iocs.extract_iocs(report_for("spoofed.eml"), source="a.eml")
    rows += iocs.extract_iocs(report_for("spoofed.eml"), source="b.eml")
    path = str(tmp_path / "iocs.csv")
    written = iocs.write_iocs_csv(path, rows)
    with open(path, newline="", encoding="utf-8") as f:
        recs = list(csv.DictReader(f))
    assert written == len(recs)
    keys = [(r["type"], r["value"]) for r in recs]
    assert len(keys) == len(set(keys))  # no duplicate IOCs
    assert recs[0]["source"] == "a.eml"  # first sighting wins


# --- CLI integration --------------------------------------------------------

def test_cli_extract_iocs_folder(tmp_path):
    out = str(tmp_path)
    rc = analyser.main([FIXTURES, "--no-api", "--json-only",
                        "--output", out, "--extract-iocs"])
    assert rc == 0
    with open(os.path.join(out, "iocs.csv"), newline="", encoding="utf-8") as f:
        recs = list(csv.DictReader(f))
    values = [r["value"] for r in recs]
    assert "paypa1.com" in values            # from lookalike.eml (MALICIOUS)
    assert "paypal-secure.top" in values     # from spoofed.eml (MALICIOUS)
    assert "https://example.com/notes" not in values  # clean.eml excluded


def test_cli_extract_iocs_single_file(tmp_path):
    out = str(tmp_path)
    rc = analyser.main([os.path.join(FIXTURES, "spoofed.eml"), "--no-api",
                        "--json-only", "--output", out, "--extract-iocs"])
    assert rc == 0
    assert os.path.exists(os.path.join(out, "iocs.csv"))
