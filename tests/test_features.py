import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

import features
import scoring


def _email(**over):
    base = {
        "from_": "a@x.com", "from_display": "A", "from_domain": "x.com",
        "reply_to": "", "reply_to_domain": "", "return_path": "", "return_path_domain": "",
        "subject": "Verify your account", "date": "", "received": [],
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": [], "ips": [], "body_text": "hello world", "has_html": False,
        "parse_errors": [],
    }
    base.update(over)
    return base


def test_numeric_features_length_with_and_without_rules():
    e = _email()
    sr = scoring.score_email(e, [])
    full = features.numeric_features(e, [], sr, use_rule_features=True)
    text_only = features.numeric_features(e, [], sr, use_rule_features=False)
    assert len(full) == len(scoring.RULE_IDS) + 6
    assert len(text_only) == 6
    assert len(features.feature_names(True)) == len(full)
    assert len(features.feature_names(False)) == len(text_only)


def test_rule_points_land_in_correct_columns():
    e = _email(spf="fail", urls=[{"url": "http://1.2.3.4/x", "domain": "1.2.3.4", "anchor_text": None}])
    sr = scoring.score_email(e, [])
    vec = features.numeric_features(e, [], sr, use_rule_features=True)
    spf_col = scoring.RULE_IDS.index("spf_fail")
    ip_col = scoring.RULE_IDS.index("raw_ip_url")
    assert vec[spf_col] == scoring.WEIGHTS["spf_fail"]
    assert vec[ip_col] == scoring.WEIGHTS["raw_ip_url"]
    assert vec[scoring.RULE_IDS.index("dkim_fail")] == 0


def test_structural_block_values():
    e = _email(has_html=True, subject="abc",
               urls=[{"url": "http://a.com", "domain": "a.com", "anchor_text": None}],
               body_text="x" * 50)
    sr = scoring.score_email(e, [])
    vec = features.numeric_features(e, [], sr, use_rule_features=False)
    # order: url_count, body_len, has_html, subject_len, attachment_count, heuristic_score
    assert vec[0] == 1            # url_count
    assert vec[1] == 50           # body_len
    assert vec[2] == 1            # has_html -> 1.0
    assert vec[3] == 3            # subject_len
    assert vec[4] == 0            # attachment_count
    assert vec[5] == sr["score"]  # heuristic_score


def test_email_text_concatenates_subject_and_body():
    e = _email(subject="Hello", body_text="World")
    assert features.email_text(e) == "hello world"


def test_assemble_matrix_shape():
    texts = ["verify your account now", "team lunch tomorrow"]
    struct = [[1.0, 2.0], [3.0, 4.0]]
    vec = TfidfVectorizer().fit(texts)
    X = features.assemble_matrix(struct, texts, vec)
    assert X.shape[0] == 2
    assert X.shape[1] == 2 + len(vec.get_feature_names_out())
    # structural columns preserved as the first two
    assert np.allclose(X.toarray()[:, :2], np.array(struct))
