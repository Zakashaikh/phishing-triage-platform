from pathlib import Path

from evaluation import download_corpus as dc
from evaluation import train

FIXTURES = Path(__file__).parent / "fixtures"


def _make_corpus(tmp_path):
    phish = [(FIXTURES / n).read_bytes() for n in ("spoofed.eml", "lookalike.eml")]
    ham = [(FIXTURES / n).read_bytes() for n in ("clean.eml", "encoded_subject.eml")]
    # duplicate to give the stratified split enough rows per class
    dc.write_zip(phish * 6, str(tmp_path / "phish.zip"), "phish", dc.PASSWORD)
    dc.write_zip(ham * 6, str(tmp_path / "ham.zip"), "ham")


def test_evaluate_predictions_math():
    m = train.evaluate_predictions([1, 1, 0, 0], [1, 0, 1, 0])
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["fpr"] == 0.5
    assert m["f1"] == 0.5


def test_build_dataset_shapes(tmp_path):
    _make_corpus(tmp_path)
    struct, texts, y = train.build_dataset(str(tmp_path))
    import scoring
    assert len(struct) == len(texts) == len(y) == 24
    assert len(struct[0]) == len(scoring.RULE_IDS) + len(train.features.STRUCT_NAMES)
    assert set(y) == {0, 1}


def test_train_and_compare_returns_configs_and_bundle(tmp_path):
    _make_corpus(tmp_path)
    struct, texts, y = train.build_dataset(str(tmp_path))
    results, bundle, curves = train.train_and_compare(struct, texts, y, seed=0)
    names = {r["config"] for r in results}
    assert {"rules_only", "logreg_text", "logreg_hybrid", "histgbm_hybrid"} <= names
    for r in results:
        for k in ("precision", "recall", "f1", "fpr"):
            assert 0.0 <= r[k] <= 1.0
    assert bundle["model"] is not None
    assert bundle["vectorizer"] is not None
    assert "use_rule_features" in bundle


def test_bundle_roundtrips_and_predicts(tmp_path):
    import joblib
    _make_corpus(tmp_path)
    struct, texts, y = train.build_dataset(str(tmp_path))
    _, bundle, _ = train.train_and_compare(struct, texts, y, seed=0)
    path = tmp_path / "model.joblib"
    joblib.dump(bundle, path)
    loaded = joblib.load(path)
    X = train.features.assemble_matrix(struct[:1], texts[:1], loaded["vectorizer"])
    if not loaded["use_rule_features"]:
        import scoring
        X = X[:, len(scoring.RULE_IDS):]
    prob = loaded["model"].predict_proba(X)[0][1]
    assert 0.0 <= prob <= 1.0
