import scoring


def make_email(**overrides):
    base = {
        "from_": "Alice <alice@example.com>",
        "from_display": "Alice",
        "from_domain": "example.com",
        "reply_to": "",
        "reply_to_domain": "",
        "return_path": "",
        "return_path_domain": "",
        "subject": "hello",
        "date": "",
        "received": [],
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "urls": [],
        "ips": [],
        "body_text": "regular text",
        "has_html": False,
        "parse_errors": [],
    }
    base.update(overrides)
    return base


def url(u, domain, anchor=None):
    return {"url": u, "domain": domain, "anchor_text": anchor}


def fired(rule, email_data, attachments=()):
    return rule(email_data, list(attachments))


def test_levenshtein():
    assert scoring._levenshtein("paypal", "paypa1") == 1
    assert scoring._levenshtein("paypal", "paypal") == 0
    assert scoring._levenshtein("abc", "xyz") == 3


def test_spf_fail_and_softfail_weights():
    assert fired(scoring.rule_spf_fail, make_email(spf="fail"))["points"] == 15
    assert fired(scoring.rule_spf_fail, make_email(spf="softfail"))["points"] == 10
    assert fired(scoring.rule_spf_fail, make_email(spf="pass")) is None


def test_dkim_and_dmarc_fail():
    assert fired(scoring.rule_dkim_fail, make_email(dkim="fail"))["points"] == 15
    assert fired(scoring.rule_dkim_fail, make_email(dkim="none")) is None
    assert fired(scoring.rule_dmarc_fail, make_email(dmarc="fail"))["points"] == 15
    assert fired(scoring.rule_dmarc_fail, make_email(dmarc="pass")) is None


def test_reply_to_mismatch():
    e = make_email(reply_to_domain="mail.ru")
    f = fired(scoring.rule_reply_to_mismatch, e)
    assert f["points"] == 20 and "mail.ru" in f["detail"]
    assert fired(scoring.rule_reply_to_mismatch, make_email(reply_to_domain="example.com")) is None
    assert fired(scoring.rule_reply_to_mismatch, make_email()) is None  # empty Reply-To


def test_return_path_mismatch():
    assert fired(scoring.rule_return_path_mismatch, make_email(return_path_domain="mail.ru"))["points"] == 10
    assert fired(scoring.rule_return_path_mismatch, make_email(return_path_domain="example.com")) is None
