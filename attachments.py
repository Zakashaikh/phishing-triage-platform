import hashlib
import os
from email.header import decode_header, make_header

from parse import load_message

DANGEROUS_EXTS = {
    ".exe", ".scr", ".js", ".vbs", ".jar", ".bat",
    ".cmd", ".ps1", ".hta", ".iso", ".lnk",
}
MACRO_EXTS = {".docm", ".xlsm", ".pptm"}


def extract_attachments(source):
    """Return attachment metadata dicts; content is hashed, never persisted."""
    out = []
    for part in load_message(source).walk():
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        try:
            filename = str(make_header(decode_header(filename or "unnamed")))
        except Exception:
            filename = filename or "unnamed"
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        ctype = part.get_content_type()
        ext = os.path.splitext(filename.lower())[1]
        out.append({
            "filename": filename,
            "content_type": ctype,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "is_dangerous_ext": ext in DANGEROUS_EXTS,
            "is_macro_doc": ext in MACRO_EXTS
                or (ext in {".doc", ".xls"} and "macroenabled" in ctype.lower()),
        })
    return out
