import email
import ipaddress
import re
from email.header import decode_header, make_header
from email.utils import parseaddr
from urllib.parse import urlparse

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
ANCHOR_RE = re.compile(
    r'<a\b[^>]*href=[\'"]?(https?://[^\s\'"<>]+)[\'"]?[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
TAG_RE = re.compile(r"<[^>]+>")
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
TRAILING_PUNCT = ".,;:!?)]}>'\""


def load_message(source):
    """Build a Message from a filesystem path (str) or raw bytes."""
    if isinstance(source, bytes):
        return email.message_from_bytes(source)
    with open(source, "rb") as f:
        return email.message_from_bytes(f.read())


def parse_email(source):
    """Parse an .eml (path or bytes) into the EmailData dict (see spec)."""
    errors = []
    msg = load_message(source)

    data = {
        "from_": _decode(msg.get("From", "")),
        "reply_to": _decode(msg.get("Reply-To", "")),
        "return_path": _decode(msg.get("Return-Path", "")),
        "subject": _decode(msg.get("Subject", "")),
        "date": msg.get("Date", ""),
        "received": msg.get_all("Received") or [],
        "spf": _match(msg.get("Received-SPF", ""), r"(pass|softfail|fail|neutral|none)"),
        "dkim": _match(msg.get("Authentication-Results", ""), r"dkim=(pass|fail|none)"),
        "dmarc": _match(msg.get("Authentication-Results", ""), r"dmarc=(pass|fail|none)"),
        "parse_errors": errors,
    }
    data["from_display"] = parseaddr(data["from_"])[0]
    data["from_domain"] = _domain_of(data["from_"])
    data["reply_to_domain"] = _domain_of(data["reply_to"])
    data["return_path_domain"] = _domain_of(data["return_path"])

    text, htmls = _walk_bodies(msg, errors)
    data["has_html"] = bool(htmls)

    anchors = {}
    for html in htmls:
        for href, inner in ANCHOR_RE.findall(html):
            anchors[_clean_url(href)] = TAG_RE.sub(" ", inner).strip()
        text += " " + TAG_RE.sub(" ", html)

    entries = {}
    candidates = [(_clean_url(u), None) for u in URL_RE.findall(text)]
    candidates += list(anchors.items())
    for url, anchor in candidates:
        if not url:
            continue
        if url not in entries:
            entries[url] = {"url": url, "domain": _hostname(url), "anchor_text": anchor}
        elif anchor and not entries[url]["anchor_text"]:
            entries[url]["anchor_text"] = anchor
    data["urls"] = list(entries.values())

    data["body_text"] = text[:5000]
    data["ips"] = _public_ips(" ".join(data["received"]))
    return data


def _decode(value):
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _match(text, pattern):
    m = re.search(pattern, text or "", re.IGNORECASE)
    return m.group(1).lower() if m else "none"


def _domain_of(address_header):
    addr = parseaddr(address_header or "")[1]
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _clean_url(url):
    return url.rstrip(TRAILING_PUNCT)


def _hostname(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _walk_bodies(msg, errors):
    text, htmls = "", []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        if part.get_content_disposition() == "attachment":
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception as exc:
            errors.append(f"body decode failed: {exc}")
            continue
        if payload is None:
            continue
        decoded = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if ctype == "text/plain":
            text += decoded
        else:
            htmls.append(decoded)
    return text, htmls


def _public_ips(text):
    out = []
    for raw in set(IP_RE.findall(text)):
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if ip.is_global:
            out.append(raw)
    return sorted(out)
