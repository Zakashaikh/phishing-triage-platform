import requests

import siem
from analyser import analyse_email

RAW = (
    b"From: security@paypa1-verify.com\r\n"
    b"Subject: Urgent: verify your account\r\n\r\n"
    b"click here http://bit.ly/x immediately\r\n"
)


def _report():
    return analyse_email(RAW, use_api=False)


def test_hec_config_requires_both_values(monkeypatch):
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    assert siem.hec_config() is None
    monkeypatch.setenv("SPLUNK_HEC_URL", "https://splunk:8088")
    assert siem.hec_config() is None  # token still missing
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "abc")
    assert siem.hec_config() == ("https://splunk:8088", "abc", True)
    monkeypatch.setenv("SPLUNK_HEC_VERIFY", "0")
    assert siem.hec_config()[2] is False


def test_build_event_is_searchable_and_raw():
    ev = siem.build_event(_report(), source="mail1.eml")
    assert ev["sourcetype"] == "phishing:triage"
    assert ev["source"] == "mail1.eml"
    body = ev["event"]
    assert body["verdict"] in ("CLEAN", "SUSPICIOUS", "MALICIOUS")
    assert body["from_domain"] == "paypa1-verify.com"
    assert "urgency_language" in body["rules_fired"]
    # IOCs go to the SIEM raw, not defanged - correlation needs real values
    assert body["urls"] == ["http://bit.ly/x"]


def test_send_event_success_and_http_error(monkeypatch):
    calls = {}

    class Resp:
        status_code = 200

    def fake_post(url, json=None, timeout=None, verify=None, headers=None):
        calls.update(url=url, verify=verify, auth=headers["Authorization"])
        return Resp()

    monkeypatch.setattr(siem.requests, "post", fake_post)
    out = siem.send_event(("https://splunk:8088/", "tok", False), {"event": {}})
    assert out == {"sent": True, "detail": "ok"}
    assert calls["url"] == "https://splunk:8088/services/collector/event"
    assert calls["verify"] is False
    assert calls["auth"] == "Splunk tok"

    Resp.status_code = 403
    out = siem.send_event(("https://splunk:8088", "tok", True), {"event": {}})
    assert out == {"sent": False, "detail": "HTTP 403"}


def test_send_event_never_raises_when_offline(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("no route")

    monkeypatch.setattr(siem.requests, "post", boom)
    out = siem.ship(("https://splunk:8088", "tok", True), _report())
    assert out["sent"] is False
    assert out["detail"] == "ConnectionError"
