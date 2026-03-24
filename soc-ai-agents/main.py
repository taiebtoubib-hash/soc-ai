"""
main.py
-------
Entry point for the SOC AI Agents pipeline.
Starts all agents in separate threads.

Current status:
  ✅ Phase 1: Collector (implemented)
  ⬜ Phase 2: Analysis (coming soon)
  ⬜ Phase 3: Detection (coming soon)
  ⬜ Phase 4: ML Classifier (coming soon)
  ⬜ Phase 4b: FP Detector (coming soon)
  ⬜ Phase 5: Orchestrator (coming soon)
  ⬜ Phase 6: Response (coming soon)
  ⬜ Phase 7: Threat Hunter (coming soon)

Usage:
  python main.py
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
    """Prints queue sizes every 30s for pipeline health monitoring."""
    while True:
        sizes = get_queue_sizes()
        log.info(f"Queue sizes: {sizes}")
        time.sleep(30)


def main():
    log.info("=" * 50)
    log.info("  SOC AI AGENTS — STARTING")
    log.info(f"  Mode: {settings.COLLECTOR_MODE}")
    log.info(f"  ENV:  {settings.ENV}")
    log.info("=" * 50)

    threads = []

    # ── Phase 1: Collector ─────────────────────────────
    from agents.collector.agent import CollectorAgent
    collector = CollectorAgent()
    threads.append(threading.Thread(
        target=collector.run,
        name="collector",
        daemon=True
    ))

    # ── Queue monitor ──────────────────────────────────
    threads.append(threading.Thread(
        target=monitor_queues,
        name="queue-monitor",
        daemon=True
    ))

    # ── Start all threads ──────────────────────────────
    for t in threads:
        log.info(f"Starting thread: {t.name}")
        t.start()

    log.info("All agents running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down SOC AI Agents...")


if __name__ == "__main__":
    main()
