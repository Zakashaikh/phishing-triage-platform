import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url(url):
    headers = {"x-apikey": VT_KEY}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"url": url, "malicious": stats["malicious"], "suspicious": stats["suspicious"]}
        elif r.status_code == 429:
            print(f" [WARNING] VirusTotal rate limit hit - try again in 60 seconds")
            return {"url": url, "malicious": "rate_limited", "suspicious": "rate_limited"}
        else:
            print(f" [WARNING] VirusTotal returned status {r.status_code} for URL")
            return {"url": url, "malicious": "unknown", "suspicious": "unknown"}
    except requests.exceptions.Timeout:
        print(f" [ERROR] Request timed out for URL: {url}")
        return {"url": url, "malicious": "timeout", "suspicious": "timeout"}
    except requests.exceptions.ConnectionError:
        print(f" [ERROR] No internet connection or VirusTotal is down")
        return {"url": url, "malicious": "connection_error", "suspicious": "connection_error"}


def check_ip(ip):
    headers = {"x-apikey": VT_KEY}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"ip": ip, "malicious": stats["malicious"]}
        elif r.status_code == 429:
            print(f" [WARNING] VirusTotal rate limit hit for IP: {ip}")
            return {"ip": ip, "malicious": "rate_limited"}
        else:
            print(f" [WARNING] VirusTotal returned status {r.status_code} for IP")
            return {"ip": ip, "malicious": "unknown"}
    except requests.exceptions.Timeout:
        print(f" [ERROR] Request timed out for IP: {ip}")
        return {"ip": ip, "malicious": "timeout"}
    except requests.exceptions.ConnectionError:
        print(f" [ERROR] No internet connection or VirusTotal is down")
        return {"ip": ip, "malicious": "connection_error"}
