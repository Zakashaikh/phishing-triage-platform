# Phishing Triage Platform — one-command demo
#
#   docker build -t phishing-triage .
#   docker run --rm -p 5000:5000 phishing-triage          # dashboard on http://localhost:5000
#   docker run --rm phishing-triage python -m pytest tests -q   # run the test suite
#   docker run --rm -v %cd%\samples:/data phishing-triage \
#       python analyser.py /data --no-api --extract-iocs        # triage a mounted folder
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
# Bind 0.0.0.0 so the container port is reachable; the container is still
# only exposed wherever you publish it (-p localhost:5000 by default use).
CMD ["python", "-m", "flask", "--app", "webapp.app", "run", "--host", "0.0.0.0", "--port", "5000"]
