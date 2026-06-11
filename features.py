"""Turn an analysed email into a numeric feature vector for ML.

Feature layout (left to right):
  [optional] one column per scoring.RULE_IDS rule = that rule's points (0 if it
             did not fire) -- including these makes a model "hybrid" (it can use
             the hand-written rules as inputs);
  structural block: url_count, body_len, has_html, subject_len,
                    attachment_count, heuristic_score;
  [appended by assemble_matrix] TF-IDF columns over subject+body.
"""
from scipy.sparse import csr_matrix, hstack

import scoring

STRUCT_NAMES = ["url_count", "body_len", "has_html", "subject_len",
                "attachment_count", "heuristic_score"]


def _rule_points(score_result):
    """Map findings -> points per RULE_IDS column (0 where a rule did not fire)."""
    fired = {f["rule_id"]: f["points"] for f in score_result["findings"]}
    return [float(fired.get(rid, 0)) for rid in scoring.RULE_IDS]


def _structural(email_data, attachments, score_result):
    return [
        float(len(email_data["urls"])),
        float(len(email_data["body_text"])),
        1.0 if email_data["has_html"] else 0.0,
        float(len(email_data["subject"])),
        float(len(attachments)),
        float(score_result["score"]),
    ]


def numeric_features(email_data, attachments, score_result, use_rule_features=True):
    """Dense numeric features for one email (excludes TF-IDF, added later)."""
    head = _rule_points(score_result) if use_rule_features else []
    return head + _structural(email_data, attachments, score_result)


def feature_names(use_rule_features=True):
    head = list(scoring.RULE_IDS) if use_rule_features else []
    return head + STRUCT_NAMES


def email_text(email_data):
    return f"{email_data['subject']} {email_data['body_text']}".lower().strip()


def assemble_matrix(struct_rows, texts, vectorizer):
    """CSR matrix: dense structural rows on the left, TF-IDF columns on the right."""
    left = csr_matrix(struct_rows, dtype=float)
    right = vectorizer.transform(texts)
    return hstack([left, right]).tocsr()
