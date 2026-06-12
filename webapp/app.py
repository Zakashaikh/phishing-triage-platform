"""Local triage dashboard.

Run:  venv\\Scripts\\python.exe webapp\\app.py   ->  http://127.0.0.1:5000
Uploads are analysed entirely in memory and never written to disk.
Offline by default; VirusTotal is opt-in per request (checkbox shown only
when the server has an API key). Localhost-only tool - no auth by design.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)  # allow running as a script

from flask import Flask, jsonify, render_template, request

import enrichment
import ml as ml_mod
from analyser import analyse_email

DEFAULT_MAX_BYTES = 10 * 1024 * 1024


def create_app(max_content_length=DEFAULT_MAX_BYTES):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = max_content_length
    ml_bundle = ml_mod.load_bundle()

    @app.get("/")
    def index():
        return render_template("index.html",
                               vt_available=enrichment.vt_available(),
                               ml_available=ml_bundle is not None)

    @app.post("/analyse")
    def analyse():
        upload = request.files.get("email")
        if upload is None or not upload.filename:
            return jsonify({"error": "no .eml file uploaded"}), 400
        raw = upload.read()
        if not raw:
            return jsonify({"error": "uploaded file is empty"}), 400
        use_vt = request.form.get("use_virustotal") == "on" and enrichment.vt_available()
        try:
            rep = analyse_email(raw, use_api=use_vt, ml_bundle=ml_bundle)
        except Exception as exc:  # malformed beyond what the parser tolerates
            return jsonify({"error": f"could not analyse email: {type(exc).__name__}"}), 400
        return jsonify(rep)

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"error": "file exceeds the 10 MB limit"}), 413

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
