FROM python:3.11-slim

WORKDIR /app

# Install project root requirements 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install agent specific dependencies (if any)
RUN touch ./agent_reqs.txt
# COPY agents/03_detection/requirements.txt ./agent_reqs.txt
# RUN pip install --no-cache-dir -r agent_reqs.txt || true

# Copy shared modules
COPY shared /app/shared

# Copy agent code
COPY agents/03_detection /app/agents/03_detection

ENV PYTHONPATH=/app
CMD ["python", "agents/03_detection/agent.py"]
