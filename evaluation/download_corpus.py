"""Download public corpora into corpus/ (gitignored).

Produces:
  corpus/phish/*.eml  - Nazario phishing corpus
  corpus/ham/*.eml    - SpamAssassin easy/hard ham (legitimate mail)

Idempotent: skips work if corpus/ is already populated (use --force to redo).
If every mirror for a class is unreachable, place the archive files manually
in corpus/downloads/ and re-run.
"""
import argparse
import mailbox
import os
import tarfile

import requests

# Each source: (local filename, [mirror URLs tried in order]).
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


def download(url, dest_path, timeout=120):
    """Stream url to dest_path; True on success, False (and no file) otherwise."""
    try:
        with requests.get(url, stream=True, timeout=timeout) as r:
            if r.status_code != 200:
                print(f"  [skip] {url} -> HTTP {r.status_code}")
                return False
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(1 << 16):
                    f.write(chunk)
        return True
    except requests.RequestException as exc:
        print(f"  [skip] {url} -> {type(exc).__name__}")
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False


def split_mbox(mbox_path, out_dir, prefix):
    """Write each mbox message as <prefix>_<NNNNN>.eml; returns count written."""
    os.makedirs(out_dir, exist_ok=True)
    count = 0
    for i, msg in enumerate(mailbox.mbox(mbox_path)):
        try:
            raw = bytes(msg)
        except Exception:
            continue  # single undecodable message must not kill the corpus
        if not raw.strip():
            continue
        with open(os.path.join(out_dir, f"{prefix}_{i:05}.eml"), "wb") as f:
            f.write(raw)
        count += 1
    return count


def extract_ham_tarball(tar_path, out_dir, prefix):
    """Extract SpamAssassin message files as .eml; returns count.

    Reads members via extractfile (never extracts member paths to disk),
    which also neutralises any path-traversal names in the archive.
    """
    os.makedirs(out_dir, exist_ok=True)
    count = 0
    with tarfile.open(tar_path, "r:bz2") as tar:
        for member in tar.getmembers():
            name = os.path.basename(member.name)
            if not member.isfile() or name == "cmds":
                continue
            fobj = tar.extractfile(member)
            if fobj is None:
                continue
            with open(os.path.join(out_dir, f"{prefix}_{count:05}.eml"), "wb") as f:
                f.write(fobj.read())
            count += 1
    return count


def _fetch(sources, downloads_dir):
    """Yield local paths for each source that exists or downloads successfully."""
    for filename, urls in sources:
        dest = os.path.join(downloads_dir, filename)
        if not os.path.exists(dest):
            print(f"Downloading {filename}...")
            if not any(download(u, dest) for u in urls):
                continue
        yield filename, dest


def main(argv=None):
    p = argparse.ArgumentParser(description="Download evaluation corpora")
    p.add_argument("--force", action="store_true", help="rebuild even if corpus/ is populated")
    args = p.parse_args(argv)

    corpus = os.path.join(ROOT, "corpus")
    downloads = os.path.join(corpus, "downloads")
    phish_dir = os.path.join(corpus, "phish")
    ham_dir = os.path.join(corpus, "ham")
    os.makedirs(downloads, exist_ok=True)

    populated = all(os.path.isdir(d) and os.listdir(d) for d in (phish_dir, ham_dir))
    if populated and not args.force:
        print("corpus/ already populated; use --force to rebuild")
        return 0

    phish_total = sum(split_mbox(path, phish_dir, os.path.splitext(name)[0])
                      for name, path in _fetch(PHISH_SOURCES, downloads))
    ham_total = sum(extract_ham_tarball(path, ham_dir, name.split(".")[0])
                    for name, path in _fetch(HAM_SOURCES, downloads))

    print(f"phish: {phish_total} messages -> {phish_dir}")
    print(f"ham:   {ham_total} messages -> {ham_dir}")
    if phish_total == 0 or ham_total == 0:
        print("ERROR: a class is empty. If mirrors are unreachable, place the "
              "archives in corpus/downloads/ and re-run.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
