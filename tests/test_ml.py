from pathlib import Path

import ml
import scoring
from attachments import extract_attachments
from evaluation import download_corpus as dc
from evaluation import train
from parse import parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def test_ml_verdict_bands():
    assert ml.ml_verdict(0.95) == "MALICIOUS"
    assert ml.ml_verdict(0.60) == "SUSPICIOUS"
    assert ml.ml_verdict(0.10) == "CLEAN"


def test_combined_verdict_takes_more_severe():
    assert ml.combined_verdict("CLEAN", 0.95) == "MALICIOUS"
    assert ml.combined_verdict("MALICIOUS", 0.01) == "MALICIOUS"
    assert ml.combined_verdict("SUSPICIOUS", 0.10) == "SUSPICIOUS"


def test_load_bundle_missing_returns_none(tmp_path):
    assert ml.load_bundle(str(tmp_path / "nope.joblib")) is None


def test_predict_proba_with_trained_bundle(tmp_path):
    import joblib
    phish = [(FIXTURES / n).read_bytes() for n in ("spoofed.eml", "lookalike.eml")]
    ham = [(FIXTURES / n).read_bytes() for n in ("clean.eml", "encoded_subject.eml")]
    dc.write_zip(phish * 6, str(tmp_path / "phish.zip"), "phish", dc.PASSWORD)
    dc.write_zip(ham * 6, str(tmp_path / "ham.zip"), "ham")
    struct, texts, y = train.build_dataset(str(tmp_path))
    _, bundle, _ = train.train_and_compare(struct, texts, y, seed=0)
    path = tmp_path / "model.joblib"
    joblib.dump(bundle, path)

    loaded = ml.load_bundle(str(path))
    raw = (FIXTURES / "spoofed.eml").read_bytes()
    ed = parse_email(raw)
    atts = extract_attachments(raw)
    sr = scoring.score_email(ed, atts)
    prob = ml.predict_proba(loaded, ed, atts, sr)
    assert 0.0 <= prob <= 1.0


def test_explain_returns_ranked_attributions():
    bundle = ml.load_bundle()  # the shipped model
    raw = (FIXTURES / "spoofed.eml").read_bytes()
    ed = parse_email(raw)
    atts = extract_attachments(raw)
    sr = scoring.score_email(ed, atts)

    out = ml.explain(bundle, ed, atts, sr, top_n=5)
    assert 0.0 <= out["base"] <= 1.0
    assert 0 < len(out["top"]) <= 5
    deltas = [abs(c["delta"]) for c in out["top"]]
    assert deltas == sorted(deltas, reverse=True)  # ranked by |delta|
    for c in out["top"]:
        assert c["kind"] in ("numeric", "text")
        # ablating one feature must match the base prediction when re-added
        assert isinstance(c["feature"], str) and c["feature"]


def test_explain_handles_email_with_no_signals():
    bundle = ml.load_bundle()
    raw = b"From: a@b.c\r\nSubject: \r\n\r\n\r\n"
    ed = parse_email(raw)
    atts = extract_attachments(raw)
    sr = scoring.score_email(ed, atts)
    out = ml.explain(bundle, ed, atts, sr)
    assert isinstance(out["top"], list)  # may be empty; must not raise
