FROM python:3.11-slim

WORKDIR /app

# Install project root requirements 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install agent specific dependencies
COPY agents/06_response/requirements.txt ./agent_reqs.txt
RUN pip install --no-cache-dir -r agent_reqs.txt || true

# Copy shared modules
COPY shared /app/shared

# Copy agent code
COPY agents/06_response /app/agents/06_response

ENV PYTHONPATH=/app
CMD ["python", "agents/06_response/agent.py"]
