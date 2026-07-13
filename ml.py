"""Predict-time ML scoring: load the trained bundle and score one email."""
import os

import joblib
import numpy as np

import features
import scoring

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "model.joblib")
_SEVERITY = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
_BY_SEVERITY = {v: k for k, v in _SEVERITY.items()}


def load_bundle(path=MODEL_PATH):
    """Return the model bundle dict, or None if no model has been trained."""
    if not os.path.exists(path):
        return None
    return joblib.load(path)


def predict_proba(bundle, email_data, attachments, score_result):
    """Phishing probability in [0,1] for one analysed email."""
    struct = [features.numeric_features(email_data, attachments, score_result,
                                        bundle["use_rule_features"])]
    text = [features.email_text(email_data)]
    X = features.assemble_matrix(struct, text, bundle["vectorizer"])
    # Densify: HistGradientBoosting rejects sparse input, and one row is cheap.
    return float(bundle["model"].predict_proba(X.toarray())[0][1])


def explain(bundle, email_data, attachments, score_result, top_n=5, max_terms=40):
    """Per-email attribution by single-feature ablation.

    For every active feature (numeric block + the email's own TF-IDF terms,
    capped at the max_terms heaviest), re-predict with that one feature
    zeroed; the probability drop is its contribution. Occlusion attribution,
    not Shapley values — cheap, model-agnostic, dependency-free, and honest
    about what it is. All ablated rows go through predict_proba as ONE batch.

    Returns {'base': p, 'top': [{'feature', 'kind', 'delta'}, ...]} with
    positive delta = the signal pushes the verdict toward phishing.
    """
    struct = [features.numeric_features(email_data, attachments, score_result,
                                        bundle["use_rule_features"])]
    text = [features.email_text(email_data)]
    X = features.assemble_matrix(struct, text, bundle["vectorizer"]).toarray()

    names = features.feature_names(bundle["use_rule_features"])
    offset = len(names)
    numeric_cols = [(j, names[j], "numeric") for j in range(offset) if X[0, j] != 0.0]
    text_cols = sorted((j for j in range(offset, X.shape[1]) if X[0, j] != 0.0),
                       key=lambda j: -abs(X[0, j]))[:max_terms]
    vocab = bundle["vectorizer"].get_feature_names_out()
    candidates = numeric_cols + [(j, f"term '{vocab[j - offset]}'", "text")
                                 for j in text_cols]

    base = float(bundle["model"].predict_proba(X)[0][1])
    if not candidates:
        return {"base": base, "top": []}

    ablated = np.repeat(X, len(candidates), axis=0)
    for row, (j, _, _) in enumerate(candidates):
        ablated[row, j] = 0.0
    probs = bundle["model"].predict_proba(ablated)[:, 1]

    contribs = [{"feature": name, "kind": kind, "delta": round(base - float(p), 4)}
                for (j, name, kind), p in zip(candidates, probs)]
    contribs.sort(key=lambda c: -abs(c["delta"]))
    return {"base": base, "top": contribs[:top_n]}


def ml_verdict(prob):
    if prob >= 0.80:
        return "MALICIOUS"
    if prob >= 0.50:
        return "SUSPICIOUS"
    return "CLEAN"


def combined_verdict(heuristic_verdict, prob):
    severity = max(_SEVERITY[heuristic_verdict], _SEVERITY[ml_verdict(prob)])
    return _BY_SEVERITY[severity]
