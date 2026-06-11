"""Download public corpora into corpus/ (gitignored).

Produces:
  corpus/phish.zip  - Nazario phishing corpus, AES-encrypted (password: infected)
  corpus/ham.zip    - SpamAssassin easy/hard ham (legitimate mail), plain zip

Real phishing samples trip antivirus if written to disk raw (Windows Defender
quarantines them), so the phish corpus is handled in memory only and stored
encrypted with the industry-standard sample password. Idempotent: skips work
if both zips exist (use --force to rebuild).
"""
import argparse
import io
import os
import re
import tarfile

import pyzipper
import requests

# Industry-standard password for malware-sample archives. Not a secret -
# it exists so antivirus cannot scan (and quarantine) the research data.
PASSWORD = b"infected"

# Each source: (name, [mirror URLs tried in order]).
# Nazario corpus mboxes; yearly files have no extension but are mbox format.
PHISH_SOURCES = [
    ("phishing3.mbox", ["https://monkey.org/~jose/phishing/phishing3.mbox"]),
    ("phishing-2022", ["https://monkey.org/~jose/phishing/phishing-2022"]),
    ("phishing-2023", ["https://monkey.org/~jose/phishing/phishing-2023"]),
]
HAM_SOURCES = [
    ("20030228_easy_ham.tar.bz2",
     ["https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"]),
    ("20030228_easy_ham_2.tar.bz2",
     ["https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2"]),
    ("20030228_hard_ham.tar.bz2",
     ["https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2"]),
]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_MBOX_SEP = re.compile(rb"(?:^|\n)From [^\n]*\n")


def download_bytes(url, timeout=120):
    """Fetch url fully into memory; returns bytes or None."""
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            print(f"  [skip] {url} -> HTTP {r.status_code}")
            return None
        return r.content
    except requests.RequestException as exc:
        print(f"  [skip] {url} -> {type(exc).__name__}")
        return None


def split_mbox_bytes(data):
    """Split raw mbox bytes into individual message byte strings."""
    return [part for part in _MBOX_SEP.split(data) if part.strip()]


def tarball_messages(data):
    """Yield raw message bytes from SpamAssassin tar.bz2 bytes (skips 'cmds')."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tar:
        for member in tar.getmembers():
            name = os.path.basename(member.name)
            if not member.isfile() or name == "cmds":
                continue
            fobj = tar.extractfile(member)
            if fobj is not None:
                yield fobj.read()


def write_zip(messages, zip_path, prefix, password=None):
    """Write messages as <prefix>_<NNNNN>.eml zip entries; AES if password set."""
    if password:
        zf = pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES)
        zf.setpassword(password)
    else:
        zf = pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_DEFLATED)
    with zf:
        for i, raw in enumerate(messages):
            zf.writestr(f"{prefix}_{i:05}.eml", raw)
    return len(messages)


def read_zip(zip_path, password=PASSWORD):
    """Yield (entry_name, raw_bytes) from a corpus zip (encrypted or plain)."""
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.setpassword(password)
        for name in sorted(zf.namelist()):
            yield name, zf.read(name)


def _collect(sources, extract):
    """Download each source (first working mirror) and extract its messages."""
    messages = []
    for name, urls in sources:
        print(f"Downloading {name}...")
        for url in urls:
            data = download_bytes(url)
            if data is not None:
                msgs = list(extract(data))
                print(f"  {name}: {len(msgs)} messages")
                messages.extend(msgs)
                break
    return messages


def main(argv=None):
    p = argparse.ArgumentParser(description="Download evaluation corpora")
    p.add_argument("--force", action="store_true", help="rebuild even if zips exist")
    args = p.parse_args(argv)

    corpus = os.path.join(ROOT, "corpus")
    os.makedirs(corpus, exist_ok=True)
    phish_zip = os.path.join(corpus, "phish.zip")
    ham_zip = os.path.join(corpus, "ham.zip")

    if not args.force and os.path.exists(phish_zip) and os.path.exists(ham_zip):
        print("corpus/ already populated; use --force to rebuild")
        return 0

    phish_total = write_zip(_collect(PHISH_SOURCES, split_mbox_bytes),
                            phish_zip, "phish", PASSWORD)
    ham_total = write_zip(_collect(HAM_SOURCES, tarball_messages), ham_zip, "ham")

    print(f"phish: {phish_total} messages -> {phish_zip}")
    print(f"ham:   {ham_total} messages -> {ham_zip}")
    if phish_total == 0 or ham_total == 0:
        print("ERROR: a class is empty. Check the mirrors and re-run.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
