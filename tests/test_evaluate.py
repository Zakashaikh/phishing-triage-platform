from pathlib import Path

from evaluation import evaluate

FIXTURES = Path(__file__).parent / "fixtures"


def _row(label, score, rules=(), error=""):
    return {"file": "x", "label": label, "score": score,
            "rule_ids": list(rules), "error": error}


def test_metrics_at_known_values():
    rows = [_row("phish", 80), _row("phish", 10), _row("ham", 60), _row("ham", 5)]
    m = evaluate.metrics_at(rows, 50)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["fpr"] == 0.5
    assert m["f1"] == 0.5


def test_metrics_ignore_errored_rows():
    rows = [_row("phish", 80), _row("phish", None, error="boom")]
    m = evaluate.metrics_at(rows, 50)
    assert m["tp"] == 1 and m["fn"] == 0


def test_metrics_empty_classes_do_not_divide_by_zero():
    m = evaluate.metrics_at([], 50)
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["fpr"] == 0.0


def test_per_rule_stats():
    rows = [
        _row("phish", 50, ["spf_fail", "urgency_language"]),
        _row("phish", 0),
        _row("ham", 0, ["spf_fail"]),
    ]
    s = evaluate.per_rule_stats(rows)
    assert s["spf_fail"]["phish_rate"] == 0.5
    assert s["spf_fail"]["ham_rate"] == 1.0
    assert s["urgency_language"]["ham_rate"] == 0.0


def test_evaluate_corpus_reads_zips(tmp_path):
    from evaluation import download_corpus as dc
    spoofed = (FIXTURES / "spoofed.eml").read_bytes()
    clean = (FIXTURES / "clean.eml").read_bytes()
    dc.write_zip([spoofed], str(tmp_path / "phish.zip"), "phish", dc.PASSWORD)
    dc.write_zip([clean], str(tmp_path / "ham.zip"), "ham")

    rows = evaluate.evaluate_corpus(str(tmp_path))
    by_label = {r["label"]: r for r in rows}
    assert len(rows) == 2
    assert by_label["phish"]["score"] >= 50
    assert by_label["ham"]["score"] == 0


def test_score_file_on_fixtures():
    clean = evaluate.score_file(str(FIXTURES / "clean.eml"))
    spoofed = evaluate.score_file(str(FIXTURES / "spoofed.eml"))
    assert clean["error"] == "" and clean["score"] == 0
    assert spoofed["error"] == "" and spoofed["score"] >= 50
    assert "spf_fail" in spoofed["rule_ids"]


def test_score_file_never_raises_on_garbage(tmp_path):
    bad = tmp_path / "junk.eml"
    bad.write_bytes(bytes(range(256)) * 4)
    r = evaluate.score_file(str(bad))
    assert "score" in r  # may score or may error, but must return a row


def test_threshold_sweep_shape():
    rows = [_row("phish", 80), _row("ham", 5)]
    sweep = evaluate.threshold_sweep(rows)
    assert [m["threshold"] for m in sweep] == list(range(5, 100, 5))
