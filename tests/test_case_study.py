import os

import pyzipper
import pytest

from evaluation import case_study

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


# --- build_case -----------------------------------------------------------

def test_build_case_spoofed_fires_auth_rules():
    case = case_study.build_case("spoofed.eml", read_fixture("spoofed.eml"))
    assert case["error"] == ""
    assert case["auth"] == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    rule_ids = [f["rule_id"] for f in case["findings"]]
    assert "spf_fail" in rule_ids
    assert "dkim_fail" in rule_ids
    assert "dmarc_fail" in rule_ids
    assert case["score"] > 0
    assert case["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_build_case_clean_email():
    case = case_study.build_case("clean.eml", read_fixture("clean.eml"))
    assert case["error"] == ""
    assert case["name"] == "clean.eml"
    assert set(case["auth"]) == {"spf", "dkim", "dmarc"}


def test_build_case_never_raises():
    case = case_study.build_case("bad.eml", None)  # type: ignore[arg-type]
    assert case["error"] != ""
    assert case["verdict"] == "ERROR"


def test_build_case_collects_recipients():
    case = case_study.build_case("spoofed.eml", read_fixture("spoofed.eml"))
    assert "bob@corp.com" in case["recipients"]


# --- redaction and defanging ----------------------------------------------

def test_redact_replaces_addresses_case_insensitively():
    text = "Delivered to Bob@Corp.com and cc alice@corp.com."
    out = case_study.redact(text, ["bob@corp.com"])
    assert "bob@corp.com" not in out.lower()
    assert "alice@corp.com" in out
    assert "[redacted]" in out


def test_defang_url():
    assert case_study.defang("http://paypal-secure.top/verify") == \
        "hxxp://paypal-secure[.]top/verify"
    assert case_study.defang("https://evil.example.com/a.php?x=1") == \
        "hxxps://evil[.]example[.]com/a.php?x=1"


# --- markdown rendering ----------------------------------------------------

def make_cases():
    return [case_study.build_case("spoofed.eml", read_fixture("spoofed.eml")),
            case_study.build_case("clean.eml", read_fixture("clean.eml"))]


def test_render_markdown_summary_and_defanged_urls():
    md = case_study.render_markdown(make_cases())
    assert "# Case studies" in md
    assert "| File | Verdict | Score | SPF | DKIM | DMARC |" in md
    # URLs must be defanged, never clickable
    assert "http://paypal-secure.top" not in md
    assert "hxxp://paypal-secure[.]top" in md
    # auth fire-rate line (the era-gap evidence)
    assert "authentication rules" in md.lower()


def test_render_markdown_redacts_recipients():
    md = case_study.render_markdown(make_cases())
    assert "bob@corp.com" not in md


def test_render_markdown_per_case_findings():
    md = case_study.render_markdown(make_cases())
    assert "spf_fail" in md
    assert "T1672" in md  # MITRE ids preserved


# --- sample loading ---------------------------------------------------------

def test_load_samples_from_folder(tmp_path):
    (tmp_path / "a.eml").write_bytes(read_fixture("clean.eml"))
    (tmp_path / "b.eml").write_bytes(read_fixture("spoofed.eml"))
    (tmp_path / "ignore.txt").write_bytes(b"nope")
    samples = list(case_study.load_samples(str(tmp_path)))
    assert [name for name, _ in samples] == ["a.eml", "b.eml"]


def test_load_samples_from_encrypted_zip(tmp_path):
    zip_path = tmp_path / "live.zip"
    with pyzipper.AESZipFile(str(zip_path), "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("modern.eml", read_fixture("spoofed.eml"))
    samples = list(case_study.load_samples(str(zip_path)))
    assert samples[0][0] == "modern.eml"
    assert b"Received-SPF" in samples[0][1]


def test_load_samples_missing_target():
    with pytest.raises(FileNotFoundError):
        list(case_study.load_samples("no-such-place"))


# --- main -------------------------------------------------------------------

def test_main_writes_case_studies_md(tmp_path):
    samples = tmp_path / "live"
    samples.mkdir()
    (samples / "spoofed.eml").write_bytes(read_fixture("spoofed.eml"))
    out = tmp_path / "CASE_STUDIES.md"
    rc = case_study.main([str(samples), "--out", str(out)])
    assert rc == 0
    md = out.read_text(encoding="utf-8")
    assert "spoofed.eml" in md
    assert "bob@corp.com" not in md


def test_main_no_samples_returns_error(tmp_path):
    empty = tmp_path / "live"
    empty.mkdir()
    rc = case_study.main([str(empty)])
    assert rc == 1
