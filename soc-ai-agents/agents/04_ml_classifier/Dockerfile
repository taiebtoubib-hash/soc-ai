FROM python:3.11-slim

WORKDIR /app

# Install project root requirements 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install agent specific dependencies
COPY agents/04_ml_classifier/requirements.txt ./agent_reqs.txt
RUN pip install --no-cache-dir -r agent_reqs.txt || true

# Copy shared modules
COPY shared /app/shared

# Copy agent code
COPY agents/04_ml_classifier /app/agents/04_ml_classifier

ENV PYTHONPATH=/app
CMD ["python", "agents/04_ml_classifier/agent.py"]
