"""Ship triage verdicts to a SIEM via the Splunk HTTP Event Collector.

One event per analysed email, flat enough to search on directly:
`sourcetype=phishing:triage verdict=MALICIOUS` just works. IOCs are sent
raw (not defanged) — a SIEM needs the real values to correlate against
proxy and DNS logs; defanging is for humans and reports.

Configuration comes from the environment (.env is loaded by enrichment):
  SPLUNK_HEC_URL     e.g. https://localhost:8088
  SPLUNK_HEC_TOKEN   the HEC token
  SPLUNK_HEC_VERIFY  set to 0 to accept self-signed TLS (local Splunk boxes)

Failures never abort triage: send_event reports what happened and the
pipeline moves on — losing one SIEM event must not lose the analysis.
"""
import os

import requests

SOURCETYPE = "phishing:triage"
TIMEOUT = 10


def hec_config():
    """(url, token, verify_tls) from the environment, or None if unset."""
    url = os.environ.get("SPLUNK_HEC_URL", "").strip()
    token = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
    if not url or not token:
        return None
    verify = os.environ.get("SPLUNK_HEC_VERIFY", "1").strip() not in ("0", "false", "no")
    return url, token, verify


def build_event(report, source=""):
    """One HEC payload for one analysed email."""
    e = report["email"]
    ml_info = report.get("ml") or {}
    return {
        "sourcetype": SOURCETYPE,
        "source": source or "phishing-triage-platform",
        "event": {
            "verdict": report["final_verdict"],
            "heuristic_verdict": report["heuristic_verdict"],
            "score": report["score"],
            "ml_probability": ml_info.get("probability"),
            "from": e["from_"],
            "from_domain": e["from_domain"],
            "reply_to_domain": e["reply_to_domain"],
            "subject": e["subject"],
            "spf": e["spf"], "dkim": e["dkim"], "dmarc": e["dmarc"],
            "auth_source": e.get("auth_source", "reported-headers"),
            "rules_fired": [f["rule_id"] for f in report["findings"]],
            "mitre": sorted({f["mitre"] for f in report["findings"]}),
            "urls": report["urls"],
            "ips": report["ips"],
            "attachment_sha256": [a["sha256"] for a in report["attachments"]],
        },
    }


def send_event(config, payload):
    """POST one event; returns {'sent': bool, 'detail': str}, never raises."""
    url, token, verify = config
    endpoint = url.rstrip("/") + "/services/collector/event"
    try:
        r = requests.post(endpoint, json=payload, timeout=TIMEOUT, verify=verify,
                          headers={"Authorization": f"Splunk {token}"})
    except requests.RequestException as exc:
        return {"sent": False, "detail": type(exc).__name__}
    if r.status_code == 200:
        return {"sent": True, "detail": "ok"}
    return {"sent": False, "detail": f"HTTP {r.status_code}"}


def ship(config, report, source=""):
    """Build and send one verdict; convenience wrapper for the pipeline."""
    return send_event(config, build_event(report, source=source))
