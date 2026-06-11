import base64
import ipaddress
import os

import requests
from dotenv import load_dotenv

load_dotenv()
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"


def vt_available():
    return bool(VT_KEY)


def check_url(url):
    if not VT_KEY:
        return {"url": url, "skipped": True, "reason": "no API key"}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    stats, status = _vt_get(f"urls/{url_id}")
    if stats is None:
        return {"url": url, "malicious": status, "suspicious": status}
    return {"url": url, "malicious": stats["malicious"], "suspicious": stats.get("suspicious", 0)}


def check_ip(ip):
    try:
        if not ipaddress.ip_address(ip).is_global:
            return {"ip": ip, "skipped": True, "reason": "private/reserved"}
    except ValueError:
        return {"ip": ip, "skipped": True, "reason": "invalid"}
    if not VT_KEY:
        return {"ip": ip, "skipped": True, "reason": "no API key"}
    stats, status = _vt_get(f"ip_addresses/{ip}")
    if stats is None:
        return {"ip": ip, "malicious": status}
    return {"ip": ip, "malicious": stats["malicious"]}


def check_file_hash(sha256):
    if not VT_KEY:
        return {"sha256": sha256, "skipped": True, "reason": "no API key"}
    stats, status = _vt_get(f"files/{sha256}")
    if stats is None:
        return {"sha256": sha256, "malicious": status}
    return {"sha256": sha256, "malicious": stats["malicious"]}


def _vt_get(path):
    """GET a VT endpoint; return (stats, 'ok') or (None, error_label)."""
    try:
        r = requests.get(f"{VT_BASE}/{path}", headers={"x-apikey": VT_KEY}, timeout=10)
    except requests.RequestException as exc:
        return None, type(exc).__name__
    if r.status_code == 429:
        return None, "rate_limited"
    if r.status_code == 404:
        return None, "not_found"
    if r.status_code != 200:
        return None, f"http_{r.status_code}"
    try:
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except ValueError:
        return None, "bad_json"
    if not isinstance(stats.get("malicious"), int):
        return None, "bad_schema"
    return stats, "ok"
