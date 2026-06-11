"""Predict-time ML scoring: load the trained bundle and score one email."""
import os

import joblib

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


def ml_verdict(prob):
    if prob >= 0.80:
        return "MALICIOUS"
    if prob >= 0.50:
        return "SUSPICIOUS"
    return "CLEAN"


def combined_verdict(heuristic_verdict, prob):
    severity = max(_SEVERITY[heuristic_verdict], _SEVERITY[ml_verdict(prob)])
    return _BY_SEVERITY[severity]
