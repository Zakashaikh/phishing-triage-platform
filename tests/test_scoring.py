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


def test_brand_freemail():
    e = make_email(from_display="PayPal Support", from_domain="gmail.com")
    f = fired(scoring.rule_brand_freemail, e)
    assert f["points"] == 25 and "paypal" in f["detail"].lower()
    assert fired(scoring.rule_brand_freemail, make_email(from_display="PayPal", from_domain="paypal.com")) is None
    assert fired(scoring.rule_brand_freemail, make_email(from_display="Mum", from_domain="gmail.com")) is None


def test_link_text_mismatch():
    e = make_email(urls=[url("http://evil.com/x", "evil.com", anchor="paypal.com")])
    assert fired(scoring.rule_link_text_mismatch, e)["points"] == 25
    # www-prefix and subdomains of the same site must NOT fire
    same = make_email(urls=[url("https://www.paypal.com/x", "www.paypal.com", anchor="paypal.com")])
    assert fired(scoring.rule_link_text_mismatch, same) is None
    plain = make_email(urls=[url("http://evil.com/x", "evil.com", anchor="click here")])
    assert fired(scoring.rule_link_text_mismatch, plain) is None


def test_lookalike_domain():
    e = make_email(urls=[url("http://paypa1.com/login", "paypa1.com")])
    f = fired(scoring.rule_lookalike_domain, e)
    assert f["points"] == 25 and "paypal.com" in f["detail"]
    assert fired(scoring.rule_lookalike_domain, make_email(urls=[url("https://paypal.com/x", "paypal.com")])) is None
    assert fired(scoring.rule_lookalike_domain, make_email(from_domain="paypa1.com")) is not None


def test_punycode_domain():
    e = make_email(urls=[url("http://xn--pypal-4ve.com/x", "xn--pypal-4ve.com")])
    assert fired(scoring.rule_punycode_domain, e)["points"] == 15
    assert fired(scoring.rule_punycode_domain, make_email()) is None


def test_raw_ip_url():
    e = make_email(urls=[url("http://203.0.113.9/login", "203.0.113.9")])
    assert fired(scoring.rule_raw_ip_url, e)["points"] == 20
    assert fired(scoring.rule_raw_ip_url, make_email(urls=[url("http://a.com/x", "a.com")])) is None


def test_url_shortener():
    e = make_email(urls=[url("https://bit.ly/abc", "bit.ly")])
    assert fired(scoring.rule_url_shortener, e)["points"] == 10
    assert fired(scoring.rule_url_shortener, make_email(urls=[url("https://a.com/x", "a.com")])) is None


def test_suspicious_tld():
    e = make_email(urls=[url("http://login.paypal-secure.top/v", "login.paypal-secure.top")])
    assert fired(scoring.rule_suspicious_tld, e)["points"] == 10
    assert fired(scoring.rule_suspicious_tld, make_email(urls=[url("https://a.com/x", "a.com")])) is None


def test_urgency_language_capped():
    e = make_email(subject="URGENT action", body_text="verify your account immediately or it will expire, act now, click here")
    f = fired(scoring.rule_urgency_language, e)
    assert f["points"] == 15  # >=3 hits capped at 15
    one = make_email(body_text="please confirm your address")
    assert fired(scoring.rule_urgency_language, one)["points"] == 5
    assert fired(scoring.rule_urgency_language, make_email()) is None
