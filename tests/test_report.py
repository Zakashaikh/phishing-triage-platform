import json

import report


def test_defang():
    assert report.defang("https://paypal.com/a.php") == "hxxps://paypal[.]com/a[.]php"
    assert report.defang("http://1.2.3.4/x") == "hxxp://1[.]2[.]3[.]4/x"
    assert report.defang("8.8.8.8") == "8[.]8[.]8[.]8"


def _email_data():
    return {
        "from_": "A <a@example.com>", "from_display": "A", "from_domain": "example.com",
        "reply_to": "", "reply_to_domain": "", "return_path": "", "return_path_domain": "",
        "subject": "s", "date": "d", "received": [], "spf": "pass", "dkim": "pass",
        "dmarc": "pass", "urls": [{"url": "https://example.com/x", "domain": "example.com", "anchor_text": None}],
        "ips": ["8.8.8.8"], "body_text": "b", "has_html": False, "parse_errors": [],
    }


def test_build_report_schema():
    score_result = {"score": 0, "verdict": "CLEAN", "findings": []}
    rep = report.build_report(_email_data(), [], score_result, "CLEAN",
                              [{"url": "https://example.com/x", "skipped": True, "reason": "no API key"}], [], [])
    assert rep["score"] == 0
    assert rep["heuristic_verdict"] == "CLEAN"
    assert rep["final_verdict"] == "CLEAN"
    assert rep["urls"] == ["https://example.com/x"]
    assert rep["enrichment"]["urls"][0]["skipped"] is True
    json.dumps(rep)  # must be JSON-serializable


def test_save_report(tmp_path):
    rep = {"score": 1}
    path = tmp_path / "r.json"
    report.save_report(str(path), rep)
    assert json.loads(path.read_text()) == {"score": 1}


def test_print_report_smoke(capsys):
    score_result = {"score": 30, "verdict": "SUSPICIOUS",
                    "findings": [{"rule_id": "spf_fail", "points": 15, "detail": "SPF check failed", "mitre": "T1672"},
                                 {"rule_id": "reply_to_mismatch", "points": 20, "detail": "x", "mitre": "T1566.002"}]}
    rep = report.build_report(_email_data(), [], score_result, "SUSPICIOUS", [], [], [])
    report.print_report(rep)
    out = capsys.readouterr().out
    assert "SCORE: 30/100" in out
    assert "spf_fail" in out and "T1672" in out
    assert "FINAL VERDICT: SUSPICIOUS" in out
    assert "hxxps://example[.]com/x" in out  # console IOCs defanged
    assert "https://example.com/x" not in out
