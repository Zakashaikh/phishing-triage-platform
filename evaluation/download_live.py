"""Download modern phishing samples into corpus/live.zip (gitignored).

Source: the phishing_pot project (https://github.com/rf-peixoto/phishing_pot)
— genuine phishing emails collected by honeypots, published for detection
research, with recipients anonymized to phishing@pot by the maintainers.
Unlike the historical evaluation corpus, these carry modern
Authentication-Results headers, so they exercise the SPF/DKIM/DMARC rules.

Same handling as download_corpus.py: samples are fetched into memory and
written straight into an AES-encrypted zip (password: infected) so raw
phishing content never touches disk where antivirus would quarantine it.

Usage: venv\\Scripts\\python.exe evaluation\\download_live.py [--count 30]
Then:  venv\\Scripts\\python.exe evaluation\\case_study.py corpus\\live.zip
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)  # allow running as a script from repo root

from evaluation.download_corpus import PASSWORD, download_bytes, write_zip

REPO = "rf-peixoto/phishing_pot"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"
RAW_URL = f"https://raw.githubusercontent.com/{REPO}/main/"
LIVE_ZIP = os.path.join(ROOT, "corpus", "live.zip")


def _sample_number(path):
    m = re.search(r"(\d+)\.eml$", path)
    return int(m.group(1)) if m else -1


def list_sample_paths():
    """Return all email/*.eml paths, sorted numerically (highest = newest)."""
    data = download_bytes(TREE_URL)
    if data is None:
        return []
    tree = json.loads(data).get("tree", [])
    paths = [p["path"] for p in tree
             if p["path"].startswith("email/") and p["path"].endswith(".eml")]
    return sorted(paths, key=_sample_number)


def fetch_samples(paths):
    """Download each sample into memory; yields raw bytes, skips failures."""
    for i, path in enumerate(paths, 1):
        raw = download_bytes(RAW_URL + path)
        if raw is not None:
            print(f"  [{i}/{len(paths)}] {os.path.basename(path)} ({len(raw)} bytes)")
            yield raw


def main(argv=None):
    p = argparse.ArgumentParser(description="Download modern phish into corpus/live.zip")
    p.add_argument("--count", type=int, default=30, help="how many samples (newest first)")
    p.add_argument("--force", action="store_true", help="rebuild even if live.zip exists")
    args = p.parse_args(argv)

    if os.path.exists(LIVE_ZIP) and not args.force:
        print(f"{LIVE_ZIP} already exists (use --force to rebuild).")
        return 0

    print(f"Listing samples in {REPO}...")
    paths = list_sample_paths()
    if not paths:
        print("Could not list samples (offline or API limit?). Nothing written.")
        return 1
    newest = paths[-args.count:]
    print(f"{len(paths)} samples available; fetching the {len(newest)} newest.")

    os.makedirs(os.path.dirname(LIVE_ZIP), exist_ok=True)
    count = write_zip(list(fetch_samples(newest)), LIVE_ZIP, "live", password=PASSWORD)
    print(f"Wrote {count} sample(s) -> {LIVE_ZIP} (AES, password 'infected')")
    return 0 if count else 1


if __name__ == "__main__":
    sys.exit(main())
