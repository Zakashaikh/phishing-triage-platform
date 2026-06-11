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
    assert f["points"] == 5 and "mail.ru" in f["detail"]  # tuned down (noisy on ham)
    assert fired(scoring.rule_reply_to_mismatch, make_email(reply_to_domain="example.com")) is None
    assert fired(scoring.rule_reply_to_mismatch, make_email()) is None  # empty Reply-To


def test_return_path_mismatch():
    # Still fires (informational) but tuned to 0 points: anti-signal on the corpus.
    assert fired(scoring.rule_return_path_mismatch, make_email(return_path_domain="mail.ru"))["points"] == 0
    assert fired(scoring.rule_return_path_mismatch, make_email(return_path_domain="example.com")) is None


def test_brand_freemail():
    e = make_email(from_display="PayPal Support", from_domain="gmail.com")
    f = fired(scoring.rule_brand_freemail, e)
    assert f["points"] == 25 and "paypal" in f["detail"].lower()
    assert fired(scoring.rule_brand_freemail, make_email(from_display="PayPal", from_domain="paypal.com")) is None
    assert fired(scoring.rule_brand_freemail, make_email(from_display="Mum", from_domain="gmail.com")) is None


def test_link_text_mismatch():
    e = make_email(urls=[url("http://evil.com/x", "evil.com", anchor="paypal.com")])
    assert fired(scoring.rule_link_text_mismatch, e)["points"] == 30  # tuned up (clean signal)
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
    assert f["points"] == 21  # >=3 hits capped at 21 (tuned up: strong signal)
    one = make_email(body_text="please confirm your address")
    assert fired(scoring.rule_urgency_language, one)["points"] == 7
    assert fired(scoring.rule_urgency_language, make_email()) is None


def att(filename="a.exe", dangerous=True, macro=False):
    return {"filename": filename, "content_type": "application/octet-stream",
            "size": 1, "sha256": "0" * 64,
            "is_dangerous_ext": dangerous, "is_macro_doc": macro}


def test_attachment_rules():
    e = make_email()
    assert fired(scoring.rule_dangerous_attachment, e, [att()])["points"] == 30
    assert fired(scoring.rule_dangerous_attachment, e, [att(dangerous=False)]) is None
    assert fired(scoring.rule_macro_attachment, e, [att("m.docm", dangerous=False, macro=True)])["points"] == 25
    assert fired(scoring.rule_macro_attachment, e, []) is None


def test_score_email_clean():
    r = scoring.score_email(make_email(), [])
    assert r == {"score": 0, "verdict": "CLEAN", "findings": []}


def test_score_email_aggregates_and_caps():
    e = make_email(spf="fail", dkim="fail", dmarc="fail",
                   reply_to_domain="mail.ru", return_path_domain="mail.ru",
                   from_display="PayPal Support", from_domain="gmail.com",
                   subject="URGENT suspended", body_text="verify your account immediately")
    r = scoring.score_email(e, [att()])
    assert r["score"] == 100  # raw sum exceeds 100, capped
    assert r["verdict"] == "MALICIOUS"
    assert {f["rule_id"] for f in r["findings"]} >= {"spf_fail", "dkim_fail", "reply_to_mismatch", "brand_freemail", "dangerous_attachment"}


def test_score_email_suspicious_band():
    # spf_fail (15) + url_shortener (10) = 25, within [20, 50) -> SUSPICIOUS
    e = make_email(spf="fail", urls=[url("https://bit.ly/x", "bit.ly")])
    r = scoring.score_email(e, [])
    assert r["score"] == 25 and r["verdict"] == "SUSPICIOUS"


def test_final_verdict_vt_override():
    clean = scoring.score_email(make_email(), [])
    assert scoring.final_verdict(clean, [{"url": "x", "malicious": 3}], [], []) == "MALICIOUS"
    assert scoring.final_verdict(clean, [{"url": "x", "malicious": 0}], [], []) == "CLEAN"
    assert scoring.final_verdict(clean, [{"url": "x", "skipped": True, "reason": "no API key"}], [], []) == "CLEAN"
    assert scoring.final_verdict(clean, [{"url": "x", "malicious": "rate_limited"}], [], []) == "CLEAN"
