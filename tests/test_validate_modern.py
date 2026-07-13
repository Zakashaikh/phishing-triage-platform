import io
import tarfile

from evaluation.download_live import tarball_samples
from evaluation.validate_modern import render, summarize


def _case(verdict="CLEAN", ml_prob=None, findings=(), error=""):
    return {"verdict": verdict, "ml_prob": ml_prob,
            "findings": list(findings), "error": error}


def _finding(rule_id):
    return {"rule_id": rule_id, "points": 10, "detail": "", "mitre": "T1566"}


def test_summarize_counts_operating_points():
    cases = [
        _case("MALICIOUS", 0.99, [_finding("spf_fail"), _finding("urgency_language")]),
        _case("SUSPICIOUS", 0.80, [_finding("link_text_mismatch")]),
        _case("CLEAN", 0.70),          # only ML catches it
        _case("CLEAN", 0.10),          # both miss
        _case(error="boom"),           # excluded from rates
    ]
    s = summarize(cases)
    assert s["total"] == 5 and s["errors"] == 1 and s["scored"] == 4
    assert s["rules_suspicious"] == 2
    assert s["rules_malicious"] == 1
    assert s["ml_flagged"] == 3
    assert s["combined"] == 3        # union: first three
    assert s["auth_fired"] == 1      # spf_fail only
    assert s["rule_counts"]["spf_fail"] == 1


def test_summarize_handles_rules_only_runs():
    s = summarize([_case("MALICIOUS", None, [_finding("raw_ip_url")])])
    assert s["ml_scored"] == 0 and s["ml_flagged"] == 0
    assert s["combined"] == 1


def test_render_states_recall_only_caveat():
    md = render(summarize([_case("MALICIOUS", 0.99, [_finding("dkim_fail")])]))
    assert "recall only" in md.lower()
    assert "`dkim_fail`" in md
    assert "1/1" in md


def test_tarball_samples_extracts_eml_in_order():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, payload in [("repo-abc/email/sample-2.eml", b"second"),
                              ("repo-abc/email/sample-1.eml", b"first"),
                              ("repo-abc/README.md", b"not an email")]:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    out = list(tarball_samples(buf.getvalue()))
    assert out == [b"first", b"second"]
