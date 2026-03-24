FROM python:3.11-slim

WORKDIR /app

COPY agents/collector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY agents/collector /app/agents/collector

ENV PYTHONPATH=/app

CMD ["python", "agents/collector/agent.py"]
