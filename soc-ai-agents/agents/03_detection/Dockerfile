FROM python:3.11-slim

WORKDIR /app

COPY agents/detection/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY agents/detection /app/agents/detection

ENV PYTHONPATH=/app

CMD ["python", "agents/detection/agent.py"]
