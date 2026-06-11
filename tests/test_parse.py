from pathlib import Path

from parse import parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_email_basics():
    d = parse_email(str(FIXTURES / "clean.eml"))
    assert d["from_domain"] == "example.com"
    assert d["from_display"] == "Alice Doe"
    assert d["spf"] == "pass"
    assert d["dkim"] == "pass"
    assert d["dmarc"] == "pass"
    assert d["has_html"] is False
    assert d["parse_errors"] == []


def test_url_trailing_punctuation_stripped():
    d = parse_email(str(FIXTURES / "clean.eml"))
    assert [u["url"] for u in d["urls"]] == ["https://example.com/notes"]
    assert d["urls"][0]["domain"] == "example.com"


def test_private_ips_filtered():
    d = parse_email(str(FIXTURES / "clean.eml"))
    assert d["ips"] == ["8.8.8.8"]  # 10.0.0.1 dropped


def test_rfc2047_subject_decoded():
    d = parse_email(str(FIXTURES / "encoded_subject.eml"))
    assert d["subject"] == "Urgent: Verify account"


def test_reply_to_and_return_path_domains():
    d = parse_email(str(FIXTURES / "spoofed.eml"))
    assert d["from_domain"] == "gmail.com"
    assert d["reply_to_domain"] == "mail.ru"
    assert d["return_path_domain"] == "mail.ru"
    assert d["spf"] == "fail"


def test_html_anchor_text_extracted():
    d = parse_email(str(FIXTURES / "lookalike.eml"))
    assert d["has_html"] is True
    entry = next(u for u in d["urls"] if u["url"] == "http://paypa1.com/login")
    assert entry["anchor_text"] == "paypal.com"


def test_headers_only_email_does_not_crash():
    d = parse_email(str(FIXTURES / "headers_only.eml"))
    assert d["body_text"] == ""
    assert d["urls"] == []
