import io
import json
from pathlib import Path

import pytest

from webapp.app import create_app

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_index_serves_upload_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Phishing" in r.data
    assert b"upload" in r.data.lower() or b"drop" in r.data.lower()


def test_analyse_requires_a_file(client):
    r = client.post("/analyse", data={})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_analyse_spoofed_fixture_offline(client):
    raw = (FIXTURES / "spoofed.eml").read_bytes()
    r = client.post("/analyse", data={
        "email": (io.BytesIO(raw), "spoofed.eml"),
    }, content_type="multipart/form-data")
    assert r.status_code == 200
    rep = r.get_json()
    assert rep["final_verdict"] == "MALICIOUS"
    assert rep["enrichment"]["urls"][0]["skipped"] is True  # offline by default
    assert rep["score"] >= 50
    json.dumps(rep)  # JSON-serializable end to end


def test_analyse_clean_fixture(client):
    raw = (FIXTURES / "clean.eml").read_bytes()
    r = client.post("/analyse", data={
        "email": (io.BytesIO(raw), "clean.eml"),
    }, content_type="multipart/form-data")
    assert r.status_code == 200
    assert r.get_json()["heuristic_verdict"] == "CLEAN"


def test_oversized_upload_returns_413_json():
    app = create_app(max_content_length=1024)  # tiny cap for the test
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post("/analyse", data={
        "email": (io.BytesIO(b"x" * 4096), "big.eml"),
    }, content_type="multipart/form-data")
    assert r.status_code == 413
    assert "error" in r.get_json()
