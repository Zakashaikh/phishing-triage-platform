import csv
import json
import shutil
from pathlib import Path

import analyser

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyse_file_offline(tmp_path):
    row = analyser.analyse_file(str(FIXTURES / "spoofed.eml"), use_api=False,
                                output_dir=str(tmp_path), json_only=True)
    assert row["verdict"] == "MALICIOUS"
    rep = json.loads((tmp_path / "spoofed_report.json").read_text())
    assert rep["final_verdict"] == "MALICIOUS"
    assert rep["enrichment"]["urls"][0]["skipped"] is True


def test_analyse_clean_file(tmp_path):
    row = analyser.analyse_file(str(FIXTURES / "clean.eml"), use_api=False,
                                output_dir=str(tmp_path), json_only=True)
    assert row["verdict"] == "CLEAN"
    assert row["score"] == 0


def test_folder_mode_writes_summary(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    for name in ("clean.eml", "spoofed.eml", "lookalike.eml"):
        shutil.copy(FIXTURES / name, inbox / name)
    (inbox / "broken.eml").write_bytes(b"")  # empty file must not abort the run

    rows = analyser.analyse_folder(str(inbox), use_api=False, output_dir=None, json_only=True)
    assert len(rows) == 4
    with open(inbox / "summary.csv", newline="", encoding="utf-8") as f:
        names = {r["file"]: r["verdict"] for r in csv.DictReader(f)}
    assert names["clean.eml"] == "CLEAN"
    assert names["spoofed.eml"] == "MALICIOUS"
    assert names["lookalike.eml"] == "MALICIOUS"


def test_main_ml_flag_polite_error(capsys):
    rc = analyser.main(["sample.eml", "--ml"])
    assert rc == 2
    assert "Milestone 3" in capsys.readouterr().out


def test_main_missing_target(capsys):
    assert analyser.main(["no_such_file.eml"]) == 1
