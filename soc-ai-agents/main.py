"""
main.py
-------
Local Development Runner for SOC AI Agents.

This script launches the agents as standalone Python threads using the in-memory queues.
It is intended ONLY for local development without Docker (when USE_KAFKA=false).

For production or Docker deployments, use `docker-compose up` which orchestrates 
each agent as a fully detached microservice over a Kafka bus.

Usage:
  ENV=development USE_KAFKA=false python main.py
"""

import threading
import time
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from shared.logger import get_logger
from shared.config import settings
from shared.queue_bus import get_queue_sizes

log = get_logger("main")


def monitor_queues():
    """Prints queue sizes every 15s for pipeline health monitoring in local mode."""
    while True:
        sizes = get_queue_sizes()
        log.info(f"📊 Queue sizes: {sizes}")
        time.sleep(15)


def start_agent(name, target):
    """Helper to start an agent thread."""
    t = threading.Thread(target=target, name=name, daemon=True)
    t.start()
    log.info(f"🟢 Started agent thread: {name}")
    return t


def main():
    log.info("=" * 60)
    log.info("                 SOC AI AGENTS")
    log.info("           LOCAL DEVELOPMENT RUNNER")
    log.info("=" * 60)

    if settings.USE_KAFKA:
        log.warning("⚠️ USE_KAFKA is enabled. This runner uses in-memory queues.")
        log.warning("⚠️ It's highly recommended to use docker-compose instead.")
        log.info("To use this local runner, set USE_KAFKA=false in your .env")
        log.info("Proceeding anyway (agents might attempt to connect to Kafka)...")

    log.info(f"Collector Mode: {settings.COLLECTOR_MODE}")
    log.info("-" * 60)

    threads = []

    # ── Queue Monitor ──
    start_agent("queue-monitor", monitor_queues)

    import importlib

    # ── Agent 01: Collector ──
    try:
        collector_mod = importlib.import_module("agents.01_collector.agent")
        collector = collector_mod.CollectorAgent()
        start_agent("01_collector", collector.run)
    except ImportError as e:
        log.error(f"❌ Failed to load 01_collector: {e}")

    # ── Agent 02: Analysis ──
    try:
        analysis_mod = importlib.import_module("agents.02_analysis.agent")
        analysis = analysis_mod.AnalysisAgent()
        start_agent("02_analysis", analysis.run)
    except ImportError as e:
        log.error(f"❌ Failed to load 02_analysis: {e}")

    # ── Placeholder for future agents ──
    # from agents.03_detection.agent import DetectionAgent
    # detection = DetectionAgent()
    # start_agent("03_detection", detection.run)
    
    log.info("-" * 60)
    log.info("✅ All available agents running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("\n⏹  Shutting down local SOC AI runner...")
        sys.exit(0)


if __name__ == "__main__":
    main()
