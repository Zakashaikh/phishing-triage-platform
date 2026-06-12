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


def test_analyse_email_accepts_raw_bytes():
    raw = (FIXTURES / "spoofed.eml").read_bytes()
    rep = analyser.analyse_email(raw, use_api=False)
    assert rep["final_verdict"] == "MALICIOUS"
    assert rep["enrichment"]["urls"][0]["skipped"] is True
    assert "suspended" in rep["body_preview"]


def test_main_missing_target(capsys):
    assert analyser.main(["no_such_file.eml"]) == 1


def test_analyse_file_with_ml_bundle(tmp_path):
    import joblib
    from evaluation import download_corpus as dc
    from evaluation import train

    phish = [(FIXTURES / n).read_bytes() for n in ("spoofed.eml", "lookalike.eml")]
    ham = [(FIXTURES / n).read_bytes() for n in ("clean.eml", "encoded_subject.eml")]
    dc.write_zip(phish * 6, str(tmp_path / "phish.zip"), "phish", dc.PASSWORD)
    dc.write_zip(ham * 6, str(tmp_path / "ham.zip"), "ham")
    struct, texts, y = train.build_dataset(str(tmp_path))
    _, bundle, _ = train.train_and_compare(struct, texts, y, seed=0)
    model_path = tmp_path / "model.joblib"
    joblib.dump(bundle, model_path)

    import ml
    analyser.analyse_file(str(FIXTURES / "spoofed.eml"), use_api=False,
                          output_dir=str(tmp_path), json_only=True,
                          ml_bundle=ml.load_bundle(str(model_path)))
    import json
    rep = json.loads((tmp_path / "spoofed_report.json").read_text())
    assert rep["ml"] is not None
    assert 0.0 <= rep["ml"]["probability"] <= 1.0
    assert rep["ml"]["verdict"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}


def test_main_ml_without_model_is_polite(capsys, monkeypatch):
    import ml
    monkeypatch.setattr(ml, "load_bundle", lambda *a, **k: None)
    rc = analyser.main([str(FIXTURES / "clean.eml"), "--ml", "--no-api"])
    assert rc == 2
    assert "no trained model" in capsys.readouterr().out.lower()
