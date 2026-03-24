FROM python:3.11-slim

WORKDIR /app

COPY agents/response/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY agents/response /app/agents/response

ENV PYTHONPATH=/app

CMD ["python", "agents/response/agent.py"]
