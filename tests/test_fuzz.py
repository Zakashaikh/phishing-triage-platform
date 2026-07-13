"""Property-based fuzzing: the pipeline consumes hostile input by design,
so the parser and scorer must never crash, whatever bytes arrive.

hypothesis generates adversarial inputs (random bytes, malformed MIME,
hostile header values); every test asserts only that the pipeline returns
a well-formed result instead of raising.
"""
from hypothesis import given, settings, strategies as st

import scoring
from attachments import extract_attachments
from parse import parse_email

# Keep CI fast but meaningful; local runs can raise this via --hypothesis-seed.
FUZZ = settings(max_examples=200, deadline=None)

header_text = st.text(
    alphabet=st.characters(min_codepoint=1, max_codepoint=0x2FFF), max_size=80
).map(lambda s: s.replace("\r", " ").replace("\n", " "))


@FUZZ
@given(st.binary(max_size=4096))
def test_parse_never_raises_on_arbitrary_bytes(raw):
    data = parse_email(raw)
    assert isinstance(data, dict)
    assert isinstance(data["urls"], list)


@FUZZ
@given(st.binary(max_size=4096))
def test_attachments_never_raise_on_arbitrary_bytes(raw):
    assert isinstance(extract_attachments(raw), list)


@FUZZ
@given(charset=header_text, body=st.binary(max_size=1024))
def test_parse_survives_hostile_charset_declarations(charset, body):
    raw = (
        b"From: a@example.com\r\nSubject: x\r\n"
        b'Content-Type: text/plain; charset="' + charset.encode("utf-8", "ignore") + b'"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n" + body
    )
    data = parse_email(raw)
    assert isinstance(data["body_text"], str)


@FUZZ
@given(subject=header_text, from_=header_text, url_path=header_text)
def test_full_scoring_pipeline_never_raises(subject, from_, url_path):
    raw = (
        f"From: {from_}\r\nSubject: {subject}\r\n"
        f"Authentication-Results: mx; dkim=fail; dmarc=fail\r\n\r\n"
        f"urgent, verify your account: http://example.top/{url_path}\r\n"
    ).encode("utf-8", "ignore")
    data = parse_email(raw)
    atts = extract_attachments(raw)
    result = scoring.score_email(data, atts)
    assert 0 <= result["score"] <= 100
    assert result["verdict"] in ("CLEAN", "SUSPICIOUS", "MALICIOUS")
