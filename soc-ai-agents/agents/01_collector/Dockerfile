FROM python:3.11-slim

WORKDIR /app

# Install project root requirements first (shared dependencies like pydantic, pyjwt etc)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install agent specific dependencies
COPY agents/01_collector/requirements.txt ./agent_reqs.txt
RUN pip install --no-cache-dir -r agent_reqs.txt || true

# Copy shared modules
COPY shared /app/shared

# Copy agent code
COPY agents/01_collector /app/agents/01_collector
COPY scripts/simulate_alerts.py /app/scripts/simulate_alerts.py

ENV PYTHONPATH=/app
CMD ["python", "agents/01_collector/agent.py"]
