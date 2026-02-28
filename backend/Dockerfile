# Multi-stage Dockerfile for X-CloudSentinel Backend
FROM python:3.9-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.9-slim

WORKDIR /app

# Copy only the installed packages from builder
COPY --from=builder /root/.local /root/.local
COPY . .

ENV PATH=/root/.local/bin:$PATH
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV MODEL_PATH=/app/models/X-CloudSentinel-distilbert

EXPOSE 7860

# Start Flask app on port 7860
CMD ["flask", "run", "--host=0.0.0.0", "--port=7860"]

