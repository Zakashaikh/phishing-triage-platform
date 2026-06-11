import re

# --- tunable constants (weights revisited with Milestone 2 evaluation data) ---
WEIGHTS = {
    "spf_fail": 15, "spf_softfail": 10, "dkim_fail": 15, "dmarc_fail": 15,
    "reply_to_mismatch": 20, "return_path_mismatch": 10, "brand_freemail": 25,
    "link_text_mismatch": 25, "lookalike_domain": 25, "punycode_domain": 15,
    "raw_ip_url": 20, "url_shortener": 10, "suspicious_tld": 10,
    "urgency_language": 5, "urgency_cap": 15,
    "dangerous_attachment": 30, "macro_attachment": 25,
}
MALICIOUS_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 25

BRAND_DOMAINS = {
    "paypal.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "google.com", "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", "hsbc.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com", "irs.gov",
    "adobe.com", "dropbox.com", "docusign.com", "outlook.com", "office.com",
}
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "mail.ru", "protonmail.com", "icloud.com",
}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly",
}
SUSPICIOUS_TLDS = {"zip", "top", "xyz", "icu", "click", "loan", "work", "tk", "ml", "cf", "gq"}
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "unusual activity", "confirm your", "expire", "click here",
    "limited time", "final notice", "security alert",
]

_DOMAIN_IN_TEXT = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)
_IP_HOST = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _finding(rule_id, points, detail, mitre):
    return {"rule_id": rule_id, "points": points, "detail": detail, "mitre": mitre}


def _levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _sld(domain):
    """Second-level label: 'mail.paypa1.com' -> 'paypa1'."""
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


def _strip_www(domain):
    return domain[4:] if domain.startswith("www.") else domain


# --- rules 1-5: authentication and header consistency ---

def rule_spf_fail(e, atts):
    if e["spf"] == "fail":
        return _finding("spf_fail", WEIGHTS["spf_fail"], "SPF check failed", "T1672")
    if e["spf"] == "softfail":
        return _finding("spf_fail", WEIGHTS["spf_softfail"], "SPF soft-failed", "T1672")
    return None


def rule_dkim_fail(e, atts):
    if e["dkim"] == "fail":
        return _finding("dkim_fail", WEIGHTS["dkim_fail"], "DKIM signature failed", "T1672")
    return None


def rule_dmarc_fail(e, atts):
    if e["dmarc"] == "fail":
        return _finding("dmarc_fail", WEIGHTS["dmarc_fail"], "DMARC check failed", "T1672")
    return None


def rule_reply_to_mismatch(e, atts):
    if e["reply_to_domain"] and e["from_domain"] and e["reply_to_domain"] != e["from_domain"]:
        return _finding(
            "reply_to_mismatch", WEIGHTS["reply_to_mismatch"],
            f"From domain {e['from_domain']} but Reply-To domain {e['reply_to_domain']}",
            "T1566.002",
        )
    return None


def rule_return_path_mismatch(e, atts):
    if e["return_path_domain"] and e["from_domain"] and e["return_path_domain"] != e["from_domain"]:
        return _finding(
            "return_path_mismatch", WEIGHTS["return_path_mismatch"],
            f"From domain {e['from_domain']} but Return-Path domain {e['return_path_domain']}",
            "T1566.002",
        )
    return None


# --- rules 6-13: content and URL deception ---

def rule_brand_freemail(e, atts):
    if e["from_domain"] not in FREEMAIL_DOMAINS:
        return None
    display = (e["from_display"] or "").lower()
    for brand in BRAND_DOMAINS:
        name = _sld(brand)
        if name in display and brand != e["from_domain"]:
            return _finding(
                "brand_freemail", WEIGHTS["brand_freemail"],
                f"Display name mentions '{name}' but sender is freemail {e['from_domain']}",
                "T1656",
            )
    return None


def rule_link_text_mismatch(e, atts):
    for u in e["urls"]:
        anchor = (u.get("anchor_text") or "").lower()
        m = _DOMAIN_IN_TEXT.search(anchor)
        if not m:
            continue
        text_d = _strip_www(m.group(1).lower())
        href_d = _strip_www(u["domain"])
        if not text_d or not href_d:
            continue
        if text_d != href_d and not href_d.endswith("." + text_d) and not text_d.endswith("." + href_d):
            return _finding(
                "link_text_mismatch", WEIGHTS["link_text_mismatch"],
                f"Link text shows {text_d} but points to {href_d}",
                "T1566.002",
            )
    return None


def rule_lookalike_domain(e, atts):
    candidates = {e["from_domain"]} | {u["domain"] for u in e["urls"]}
    for domain in sorted(filter(None, candidates)):
        sld = _sld(domain)
        for brand in sorted(BRAND_DOMAINS):
            brand_sld = _sld(brand)
            if len(brand_sld) < 5:  # short names (ups, dhl, irs...) are edit-distance noise
                continue
            if domain == brand or domain.endswith("." + brand):
                continue
            if 1 <= _levenshtein(sld, brand_sld) <= 2:
                return _finding(
                    "lookalike_domain", WEIGHTS["lookalike_domain"],
                    f"Domain {domain} looks like {brand}",
                    "T1583.001",
                )
    return None


def rule_punycode_domain(e, atts):
    candidates = [e["from_domain"]] + [u["domain"] for u in e["urls"]]
    for domain in candidates:
        if "xn--" in (domain or ""):
            return _finding(
                "punycode_domain", WEIGHTS["punycode_domain"],
                f"Punycode/IDN domain: {domain}", "T1583.001",
            )
    return None


def rule_raw_ip_url(e, atts):
    for u in e["urls"]:
        if _IP_HOST.match(u["domain"] or ""):
            return _finding(
                "raw_ip_url", WEIGHTS["raw_ip_url"],
                f"URL host is a literal IP: {u['domain']}", "T1566.002",
            )
    return None


def rule_url_shortener(e, atts):
    for u in e["urls"]:
        if _strip_www(u["domain"] or "") in SHORTENER_DOMAINS:
            return _finding(
                "url_shortener", WEIGHTS["url_shortener"],
                f"Shortened URL hides destination: {u['domain']}", "T1566.002",
            )
    return None


def rule_suspicious_tld(e, atts):
    for u in e["urls"]:
        tld = (u["domain"] or "").rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            return _finding(
                "suspicious_tld", WEIGHTS["suspicious_tld"],
                f"High-abuse TLD .{tld} in {u['domain']}", "T1583.001",
            )
    return None


def rule_urgency_language(e, atts):
    text = f"{e['subject']} {e['body_text']}".lower()
    hits = [k for k in URGENCY_KEYWORDS if k in text]
    if not hits:
        return None
    points = min(WEIGHTS["urgency_cap"], WEIGHTS["urgency_language"] * len(hits))
    return _finding(
        "urgency_language", points,
        f"Urgency/credential language: {', '.join(hits[:3])}", "T1656",
    )
