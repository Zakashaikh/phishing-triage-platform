import io
import tarfile

from evaluation import download_corpus as dc

MBOX = (b"From a@example.com Mon Jun  1 10:00:00 2026\n"
        b"From: a0@example.com\nSubject: msg 0\n\nbody 0\n"
        b"\nFrom b@example.com Mon Jun  1 10:01:00 2026\n"
        b"From: a1@example.com\nSubject: msg 1\n\nbody 1\n"
        b"\nFrom c@example.com Mon Jun  1 10:02:00 2026\n"
        b"From: a2@example.com\nSubject: msg 2\n\nbody 2\n")


def test_split_mbox_bytes():
    msgs = dc.split_mbox_bytes(MBOX)
    assert len(msgs) == 3
    assert msgs[1].startswith(b"From: a1@example.com")
    assert b"body 1" in msgs[1]


def _make_tar_bz2():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
        for name, content in (("easy_ham/0001.abc", b"From: x@y.com\n\nhello\n"),
                              ("easy_ham/0002.def", b"From: z@y.com\n\nworld\n"),
                              ("easy_ham/cmds", b"not a mail")):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_tarball_messages_skips_cmds():
    msgs = list(dc.tarball_messages(_make_tar_bz2()))
    assert len(msgs) == 2
    assert msgs[0] == b"From: x@y.com\n\nhello\n"


def test_write_and_read_encrypted_zip(tmp_path):
    zip_path = str(tmp_path / "phish.zip")
    n = dc.write_zip([b"raw one", b"raw two"], zip_path, "phish", dc.PASSWORD)
    assert n == 2
    entries = dict(dc.read_zip(zip_path))
    assert entries == {"phish_00000.eml": b"raw one", "phish_00001.eml": b"raw two"}


def test_write_and_read_plain_zip(tmp_path):
    zip_path = str(tmp_path / "ham.zip")
    dc.write_zip([b"legit"], zip_path, "ham")
    assert dict(dc.read_zip(zip_path)) == {"ham_00000.eml": b"legit"}


def test_download_bytes_handles_http_error(monkeypatch):
    class FakeResp:
        status_code = 404
        content = b""
    monkeypatch.setattr(dc.requests, "get", lambda *a, **kw: FakeResp())
    assert dc.download_bytes("http://x/y") is None
