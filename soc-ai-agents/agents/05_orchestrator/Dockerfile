FROM python:3.11-slim

WORKDIR /app

# Install project root requirements 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install agent specific dependencies
COPY agents/05_orchestrator/requirements.txt ./agent_reqs.txt
RUN pip install --no-cache-dir -r agent_reqs.txt || true

# Copy shared modules
COPY shared /app/shared

# Copy agent code
COPY agents/05_orchestrator /app/agents/05_orchestrator

ENV PYTHONPATH=/app
CMD ["python", "agents/05_orchestrator/agent.py"]
