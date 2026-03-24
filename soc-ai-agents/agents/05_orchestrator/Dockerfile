FROM python:3.11-slim

WORKDIR /app

COPY agents/orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY agents/orchestrator /app/agents/orchestrator

ENV PYTHONPATH=/app

CMD ["python", "agents/orchestrator/agent.py"]
