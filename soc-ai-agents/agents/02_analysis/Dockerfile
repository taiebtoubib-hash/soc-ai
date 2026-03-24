FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY agents/02_analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules and the agent package
COPY shared /app/shared
COPY agents/__init__.py /app/agents/__init__.py
COPY agents/02_analysis /app/agents/analysis

ENV PYTHONPATH=/app

CMD ["python", "agents/analysis/agent.py"]
