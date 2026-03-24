FROM python:3.11-slim

WORKDIR /app

COPY agents/ml_classifier/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY agents/ml_classifier /app/agents/ml_classifier

ENV PYTHONPATH=/app

CMD ["python", "agents/ml_classifier/agent.py"]
