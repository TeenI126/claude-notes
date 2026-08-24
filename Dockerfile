# Only needed for the Cloud Build/Cloud Run v2 REST deploy path (no gcloud CLI,
# no local Docker) — the gcloud path builds this same server fine via Buildpacks
# from the Procfile alone, so this file exists purely as a known-good fallback
# for environments where only the REST path is reachable.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV PORT=8080
EXPOSE 8080

CMD ["python", "server.py"]
