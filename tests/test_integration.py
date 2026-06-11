"""End-to-end pipeline runs over fixtures, offline (--no-api equivalent)."""
import json
from pathlib import Path

import analyser

FIXTURES = Path(__file__).parent / "fixtures"

EXPECTED = {
    "clean.eml": "CLEAN",
    "spoofed.eml": "MALICIOUS",
    "lookalike.eml": "MALICIOUS",   # lookalike 25 + link mismatch 25 = 50
    "attachment.eml": "SUSPICIOUS",  # dangerous attachment 30
}


def test_fixture_verdicts(tmp_path):
    for name, expected in EXPECTED.items():
        row = analyser.analyse_file(str(FIXTURES / name), use_api=False,
                                    output_dir=str(tmp_path), json_only=True)
        assert row["verdict"] == expected, f"{name}: got {row['verdict']}, want {expected}"


def test_report_explains_spoofed(tmp_path):
    analyser.analyse_file(str(FIXTURES / "spoofed.eml"), use_api=False,
                          output_dir=str(tmp_path), json_only=True)
    rep = json.loads((tmp_path / "spoofed_report.json").read_text())
    rule_ids = {f["rule_id"] for f in rep["findings"]}
    assert {"spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch",
            "return_path_mismatch", "brand_freemail", "suspicious_tld",
            "urgency_language"} <= rule_ids
    assert all(f["mitre"] for f in rep["findings"])
