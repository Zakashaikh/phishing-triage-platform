"""Compute SPF/DKIM/DMARC instead of trusting the message's own headers.

parse.py reads authentication results out of `Received-SPF` and
`Authentication-Results` — headers that travel *inside* the message, which
means a sender can forge them. This module verifies instead:

- DKIM: cryptographic signature check (public key fetched from DNS at
  ``<selector>._domainkey.<d=domain>``).
- SPF: the sender domain's published policy evaluated against the IP that
  handed the message to the receiving MTA (taken from the Received chain).
- DMARC: the From domain's ``_dmarc`` policy fetched from DNS, with relaxed
  identifier alignment against the DKIM d= domain and SPF envelope domain.

Every check needs live DNS, so verification is opt-in (``--verify-auth``)
and every failure mode degrades to ``"unknown"`` rather than raising —
the offline pipeline must keep working from a plane.
"""
import ipaddress
import re
from email.utils import parseaddr

import dkim
import dns.resolver
import spf as pyspf

import parse

# Received: from mail.example.com (unknown [203.0.113.9]) by ...
_BRACKET_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
_ANY_IP = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_HELO = re.compile(r"^from\s+(\S+)", re.IGNORECASE)
_DKIM_DOMAIN = re.compile(r"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)

# Minimal two-part public suffixes for relaxed alignment. A full public
# suffix list is overkill here; these cover the corpus and UK/AU brands.
_TWO_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "com.au", "net.au",
    "co.jp", "com.br", "com.mx", "co.nz", "com.sg", "com.hk",
}

DNS_LIFETIME = 5.0  # seconds per lookup; slow DNS must not stall triage


def org_domain(domain):
    """Relaxed-alignment organizational domain: 'a.b.example.co.uk' -> 'example.co.uk'."""
    parts = (domain or "").lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def last_hop_ip(received_headers):
    """Public IP that delivered the message to the receiving MTA.

    Walks the Received chain top (most recent) down and returns the first
    public IP, preferring the bracketed form the receiving MTA recorded.
    An attacker can forge *earlier* Received lines but not the topmost one,
    which the recipient's own server wrote.
    """
    for header in received_headers or []:
        candidates = _BRACKET_IP.findall(header) + _ANY_IP.findall(header)
        for raw in candidates:
            try:
                if ipaddress.ip_address(raw).is_global:
                    return raw
            except ValueError:
                continue
    return None


def helo_name(received_headers):
    for header in received_headers or []:
        m = _HELO.match(header.strip())
        if m:
            return m.group(1)
    return ""


def _verify_dkim(raw):
    """('pass'|'fail'|'none'|'unknown', d= domain or '')."""
    msg = parse.load_message(raw)
    sig = msg.get("DKIM-Signature", "")
    if not sig:
        return "none", ""
    m = _DKIM_DOMAIN.search(sig)
    domain = m.group(1).lower() if m else ""
    try:
        return ("pass" if dkim.verify(raw) else "fail"), domain
    except Exception:  # DNS failure, malformed key, unsupported algorithm
        return "unknown", domain


def _check_spf(ip, sender, helo):
    """('pass'|'fail'|'softfail'|'neutral'|'none'|'unknown')."""
    try:
        result, _ = pyspf.check2(i=ip, s=sender, h=helo or sender.split("@")[-1],
                                 timeout=DNS_LIFETIME)
    except Exception:
        return "unknown"
    return result if result in ("pass", "fail", "softfail", "neutral", "none") else "unknown"


def _dmarc_record(domain):
    """DMARC policy TXT for a domain, or '' if none published. Raises on DNS trouble."""
    answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DNS_LIFETIME)
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt.lower().startswith("v=dmarc1"):
            return txt
    return ""


def _verify_dmarc(from_domain, dkim_result, dkim_domain, spf_result, spf_domain):
    """Relaxed alignment: a DMARC pass needs an aligned DKIM or SPF pass."""
    if not from_domain:
        return "unknown"
    record = ""
    try:
        record = _dmarc_record(from_domain)
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        return "unknown"
    if not record:
        try:  # policy may live at the organizational domain
            org = org_domain(from_domain)
            record = _dmarc_record(org) if org != from_domain else ""
        except Exception:
            return "none"
    if not record:
        return "none"

    org_from = org_domain(from_domain)
    dkim_aligned = dkim_result == "pass" and org_domain(dkim_domain) == org_from
    spf_aligned = spf_result == "pass" and org_domain(spf_domain) == org_from
    return "pass" if (dkim_aligned or spf_aligned) else "fail"


def verify_auth(source, email_data):
    """Verified {'spf','dkim','dmarc','dkim_domain','spf_ip'} for one email.

    `source` is the .eml path or raw bytes (DKIM needs the exact wire bytes);
    `email_data` is parse.parse_email's output for the same message.
    """
    raw = source if isinstance(source, bytes) else open(source, "rb").read()

    dkim_result, dkim_domain = _verify_dkim(raw)

    sender = parseaddr(email_data["return_path"] or email_data["from_"])[1]
    spf_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    ip = last_hop_ip(email_data["received"])
    if ip and sender and spf_domain:
        spf_result = _check_spf(ip, sender, helo_name(email_data["received"]))
    else:
        spf_result = "unknown"  # nothing trustworthy to evaluate against

    dmarc_result = _verify_dmarc(email_data["from_domain"], dkim_result,
                                 dkim_domain, spf_result, spf_domain)

    return {"spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result,
            "dkim_domain": dkim_domain, "spf_ip": ip}


def apply_verification(email_data, verified):
    """Overlay verified results onto email_data, keeping the reported values.

    Verified values win wherever the check produced a definitive answer;
    'unknown' (DNS unavailable, etc.) falls back to the reported header so
    offline behaviour is unchanged. The originals are preserved under
    'auth_reported' so scoring can spot forged Authentication-Results.
    """
    email_data["auth_reported"] = {k: email_data[k] for k in ("spf", "dkim", "dmarc")}
    for key in ("spf", "dkim", "dmarc"):
        if verified[key] != "unknown":
            email_data[key] = verified[key]
    email_data["auth_source"] = "verified"
    email_data["auth_details"] = {"dkim_domain": verified["dkim_domain"],
                                  "spf_ip": verified["spf_ip"]}
    return email_data
