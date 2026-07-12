from pathlib import Path

import dns.resolver
import pytest

import auth
import parse
import scoring
from analyser import analyse_email

FIXTURES = Path(__file__).parent / "fixtures"

SIGNED = (
    b"From: Alice <alice@example.com>\r\n"
    b"Return-Path: <bounce@example.com>\r\n"
    b"Received: from mail.example.com (mail.example.com [92.118.36.199]) by mx\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; bh=x; b=y\r\n"
    b"Authentication-Results: mx; dkim=pass; dmarc=pass\r\n"
    b"Subject: hello\r\n\r\nbody\r\n"
)

UNSIGNED = (
    b"From: Mallory <mallory@evil.test>\r\n"
    b"Received: from spoof (spoof [92.118.36.199]) by mx\r\n"
    b"Authentication-Results: mx; dkim=pass; dmarc=pass\r\n"
    b"Subject: pay now\r\n\r\nbody\r\n"
)


# --- pure helpers ---

def test_org_domain_handles_two_part_tlds():
    assert auth.org_domain("mail.paypal.co.uk") == "paypal.co.uk"
    assert auth.org_domain("a.b.example.com") == "example.com"
    assert auth.org_domain("example.com") == "example.com"
    assert auth.org_domain("") == ""


def test_last_hop_ip_skips_private_and_reserved():
    headers = [
        "from inner (inner [10.0.0.1]) by a",          # private
        "from doc (doc [203.0.113.9]) by b",            # TEST-NET, not global
        "from real (real [92.118.36.199]) by c",
    ]
    assert auth.last_hop_ip(headers) == "92.118.36.199"
    assert auth.last_hop_ip([]) is None


def test_helo_name_from_topmost_received():
    assert auth.helo_name(["from mail.example.com (x [1.2.3.4]) by mx"]) == "mail.example.com"
    assert auth.helo_name([]) == ""


# --- DKIM ---

def test_dkim_none_when_no_signature():
    result, domain = auth._verify_dkim(UNSIGNED)
    assert result == "none"
    assert domain == ""


def test_dkim_pass_and_domain_extraction(monkeypatch):
    monkeypatch.setattr(auth.dkim, "verify", lambda raw: True)
    result, domain = auth._verify_dkim(SIGNED)
    assert result == "pass"
    assert domain == "example.com"


def test_dkim_unknown_on_dns_failure(monkeypatch):
    def boom(raw):
        raise OSError("no DNS")
    monkeypatch.setattr(auth.dkim, "verify", boom)
    result, _ = auth._verify_dkim(SIGNED)
    assert result == "unknown"


# --- SPF ---

def test_spf_maps_errors_to_unknown(monkeypatch):
    monkeypatch.setattr(auth.pyspf, "check2",
                        lambda i, s, h, timeout: ("temperror", "dns timeout"))
    assert auth._check_spf("92.118.36.199", "a@example.com", "mail.example.com") == "unknown"
    monkeypatch.setattr(auth.pyspf, "check2",
                        lambda i, s, h, timeout: ("pass", "ok"))
    assert auth._check_spf("92.118.36.199", "a@example.com", "mail.example.com") == "pass"


# --- DMARC ---

def test_dmarc_pass_needs_aligned_dkim(monkeypatch):
    monkeypatch.setattr(auth, "_dmarc_record", lambda d: "v=DMARC1; p=reject")
    assert auth._verify_dmarc("example.com", "pass", "mail.example.com", "fail", "") == "pass"
    assert auth._verify_dmarc("example.com", "pass", "evil.test", "fail", "") == "fail"
    assert auth._verify_dmarc("example.com", "fail", "example.com", "pass", "example.com") == "pass"


def test_dmarc_none_when_no_record(monkeypatch):
    def nx(domain):
        raise dns.resolver.NXDOMAIN
    monkeypatch.setattr(auth, "_dmarc_record", nx)
    assert auth._verify_dmarc("example.com", "pass", "example.com", "none", "") == "none"


# --- end to end ---

def _fake_verified(monkeypatch, dkim_result):
    monkeypatch.setattr(auth.dkim, "verify", lambda raw: dkim_result)
    monkeypatch.setattr(auth.pyspf, "check2", lambda i, s, h, timeout: ("fail", ""))
    monkeypatch.setattr(auth, "_dmarc_record", lambda d: "v=DMARC1; p=none")


def test_verified_results_override_reported_headers(monkeypatch):
    _fake_verified(monkeypatch, dkim_result=False)  # signature present but invalid
    email_data = parse.parse_email(SIGNED)
    assert email_data["dkim"] == "pass"  # what the header claims
    auth.apply_verification(email_data, auth.verify_auth(SIGNED, email_data))
    assert email_data["dkim"] == "fail"           # what crypto says
    assert email_data["auth_reported"]["dkim"] == "pass"
    assert email_data["auth_source"] == "verified"


def test_forged_header_rule_fires(monkeypatch):
    _fake_verified(monkeypatch, dkim_result=False)
    rep = analyse_email(SIGNED, use_api=False, verify_auth=True)
    rule_ids = [f["rule_id"] for f in rep["findings"]]
    assert "auth_header_forged" in rule_ids
    assert rep["email"]["auth_source"] == "verified"
    assert rep["email"]["auth_reported"]["dkim"] == "pass"


def test_forged_rule_silent_without_verification():
    rep = analyse_email(SIGNED, use_api=False)
    assert "auth_header_forged" not in [f["rule_id"] for f in rep["findings"]]
    assert "auth_source" not in rep["email"]


def test_unknown_results_keep_reported_values(monkeypatch):
    monkeypatch.setattr(auth.dkim, "verify",
                        lambda raw: (_ for _ in ()).throw(OSError("offline")))
    monkeypatch.setattr(auth.pyspf, "check2",
                        lambda i, s, h, timeout: ("temperror", ""))
    monkeypatch.setattr(auth, "_dmarc_record",
                        lambda d: (_ for _ in ()).throw(OSError("offline")))
    email_data = parse.parse_email(SIGNED)
    auth.apply_verification(email_data, auth.verify_auth(SIGNED, email_data))
    # everything degraded to unknown -> reported header values survive
    assert email_data["dkim"] == "pass"
    assert email_data["spf"] == "none"


def test_forged_rule_not_an_ml_feature_column():
    assert "auth_header_forged" not in scoring.RULE_IDS
    assert len(scoring.RULE_IDS) == 15
