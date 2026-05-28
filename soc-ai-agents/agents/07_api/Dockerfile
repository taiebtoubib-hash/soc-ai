FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY agents/07_api /app/agents/07_api

ENV PYTHONPATH=/app

# Install curl for healthchecks (used by dashboard)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

CMD ["uvicorn", "agents.07_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
