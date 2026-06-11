import email
import re

def parse_email(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_bytes(f.read())

    headers = {
        "from":         msg.get("From", ""),
        "reply_to":     msg.get("Reply-To", ""),
        "return_path":  msg.get("Return-Path", ""),
        "subject":      msg.get("Subject", ""),
        "date":         msg.get("Date", ""),
        "received":     msg.get_all("Received", []),
        "auth_results": msg.get("Authentication-Results", ""),
        "spf":          _extract(msg.get("Received-SPF", ""), r"(pass|fail|softfail|neutral|none)"),
        "dkim":         _extract(msg.get("Authentication-Results", ""), r"dkim=(pass|fail|none)"),
        "dmarc":        _extract(msg.get("Authentication-Results", ""), r"dmarc=(pass|fail|none)"),
    }

    body = _get_body(msg)
    headers["urls"] = _extract_urls(body)
    headers["ips"] = _extract_ips(" ".join(msg.get_all("Received", [])))
    headers["body"] = body[:500]

    return headers


def _get_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
            elif part.get_content_type() == "text/html":
                html = part.get_payload(decode=True).decode(errors="ignore")
                body += _extract_text_from_html(html)
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")
    return body

def _extract_text_from_html(html):
    links = re.findall(r'href=[\'"]?(https?://[^\s\'"<>]+)', html)
    text = re.sub(r'<[^>]+>', ' ', html)
    return text + " " + " ".join(links)

def _extract(text, pattern):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else "None"

def _extract_urls(text):
    return list(set(re.findall(r'https?://[^\s<>"]+', text)))

def _extract_ips(text):
    return list(set(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)))
