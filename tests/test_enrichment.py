import requests

import enrichment


class FakeResponse:
    def __init__(self, status_code, payload=None, bad_json=False):
        self.status_code = status_code
        self._payload = payload or {}
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


VT_OK = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}}


def test_skipped_when_no_key(monkeypatch):
    monkeypatch.setattr(enrichment, "VT_KEY", None)
    r = enrichment.check_url("http://x.com")
    assert r == {"url": "http://x.com", "skipped": True, "reason": "no API key"}
    assert enrichment.vt_available() is False


def test_check_url_success(monkeypatch):
    monkeypatch.setattr(enrichment, "VT_KEY", "k")
    monkeypatch.setattr(enrichment.requests, "get", lambda *a, **kw: FakeResponse(200, VT_OK))
    r = enrichment.check_url("http://x.com")
    assert r["malicious"] == 3 and r["suspicious"] == 1


def test_check_url_rate_limited(monkeypatch):
    monkeypatch.setattr(enrichment, "VT_KEY", "k")
    monkeypatch.setattr(enrichment.requests, "get", lambda *a, **kw: FakeResponse(429))
    assert enrichment.check_url("http://x.com")["malicious"] == "rate_limited"


def test_check_url_bad_json_and_exceptions(monkeypatch):
    monkeypatch.setattr(enrichment, "VT_KEY", "k")
    monkeypatch.setattr(enrichment.requests, "get", lambda *a, **kw: FakeResponse(200, bad_json=True))
    assert enrichment.check_url("http://x.com")["malicious"] == "bad_json"

    def boom(*a, **kw):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(enrichment.requests, "get", boom)
    assert enrichment.check_url("http://x.com")["malicious"] == "ConnectionError"


def test_check_ip_skips_private(monkeypatch):
    monkeypatch.setattr(enrichment, "VT_KEY", "k")
    r = enrichment.check_ip("10.0.0.1")
    assert r["skipped"] is True and r["reason"] == "private/reserved"


def test_check_file_hash_success(monkeypatch):
    monkeypatch.setattr(enrichment, "VT_KEY", "k")
    monkeypatch.setattr(enrichment.requests, "get", lambda *a, **kw: FakeResponse(200, VT_OK))
    assert enrichment.check_file_hash("a" * 64)["malicious"] == 3
