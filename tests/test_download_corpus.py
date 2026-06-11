import mailbox
import tarfile

from evaluation import download_corpus as dc


def _make_mbox(path, count):
    box = mailbox.mbox(str(path))
    for i in range(count):
        box.add(f"From: a{i}@example.com\nSubject: msg {i}\n\nbody {i}\n".encode())
    box.close()


def test_split_mbox(tmp_path):
    mbox_path = tmp_path / "phish.mbox"
    _make_mbox(mbox_path, 3)
    out = tmp_path / "out"
    n = dc.split_mbox(str(mbox_path), str(out), "phish")
    assert n == 3
    files = sorted(p.name for p in out.glob("*.eml"))
    assert files == ["phish_00000.eml", "phish_00001.eml", "phish_00002.eml"]
    assert b"Subject: msg 1" in (out / "phish_00001.eml").read_bytes()


def test_extract_ham_tarball(tmp_path):
    src = tmp_path / "easy_ham"
    src.mkdir()
    (src / "0001.abc").write_bytes(b"From: x@y.com\n\nhello\n")
    (src / "0002.def").write_bytes(b"From: z@y.com\n\nworld\n")
    (src / "cmds").write_bytes(b"not a mail")
    tar_path = tmp_path / "ham.tar.bz2"
    with tarfile.open(tar_path, "w:bz2") as tar:
        tar.add(src, arcname="easy_ham")

    out = tmp_path / "out"
    n = dc.extract_ham_tarball(str(tar_path), str(out), "easy_ham")
    assert n == 2  # cmds skipped
    assert len(list(out.glob("*.eml"))) == 2


def test_download_handles_http_error(tmp_path, monkeypatch):
    class FakeResp:
        status_code = 404
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(dc.requests, "get", lambda *a, **kw: FakeResp())
    assert dc.download("http://x/y", str(tmp_path / "f")) is False
    assert not (tmp_path / "f").exists()
