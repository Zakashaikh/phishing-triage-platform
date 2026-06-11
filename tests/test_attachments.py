import hashlib
from pathlib import Path

from attachments import extract_attachments

FIXTURES = Path(__file__).parent / "fixtures"


def test_extracts_attachment_metadata():
    atts = extract_attachments(str(FIXTURES / "attachment.eml"))
    assert len(atts) == 1
    a = atts[0]
    assert a["filename"] == "invoice.pdf.exe"
    assert a["content_type"] == "application/octet-stream"
    assert a["size"] == len(b"MZfakeexe")
    assert a["sha256"] == hashlib.sha256(b"MZfakeexe").hexdigest()
    assert a["is_dangerous_ext"] is True
    assert a["is_macro_doc"] is False


def test_no_attachments_in_plain_email():
    assert extract_attachments(str(FIXTURES / "clean.eml")) == []
