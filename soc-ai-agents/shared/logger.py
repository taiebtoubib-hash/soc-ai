"""
shared/logger.py
----------------
Shared Loguru logger configuration.
Every agent imports get_logger() from here.

Usage:
    from shared.logger import get_logger
    log = get_logger("collector")
    log.info("Agent started")
    log.warning("Something looks off")
    log.error("Something broke")
"""

import sys
from pathlib import Path
from loguru import logger

# ── Log directory ──────────────────────────────────────
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

# ── Remove default Loguru handler ──────────────────────
# Done ONCE at module level — not inside get_logger()
# Bug in original: calling logger.remove() every time
# get_logger() is called removes ALL previous handlers
logger.remove()

# ── Console handler ────────────────────────────────────
logger.add(
    sys.stderr,
    format=(
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{extra[agent]}</cyan> | "
        "<level>{message}</level>"
    ),
    level="DEBUG",
    colorize=True,
)

# ── File handler — all logs ────────────────────────────
logger.add(
    LOGS_DIR / "soc_{time:YYYY-MM-DD}.log",
    format=(
        "{time:YYYY-MM-DD HH:mm:ss} | "
        "{level: <8} | "
        "{extra[agent]} | "
        "{message}"
    ),
    level="DEBUG",
    rotation="00:00",       # new file every day at midnight
    retention="30 days",    # keep last 30 days
    compression="zip",      # compress old logs
    encoding="utf-8",
)

# ── File handler — errors only ─────────────────────────
logger.add(
    LOGS_DIR / "errors_{time:YYYY-MM-DD}.log",
    format=(
        "{time:YYYY-MM-DD HH:mm:ss} | "
        "{level: <8} | "
        "{extra[agent]} | "
        "{message}"
    ),
    level="ERROR",
    rotation="00:00",
    retention="90 days",    # keep errors longer
    compression="zip",
    encoding="utf-8",
)


def get_logger(agent_name: str):
    """
    Returns a logger instance bound to a specific agent name.
    All log lines will include the agent name for easy filtering.

    Args:
        agent_name: name of the agent (e.g. "collector", "ml_classifier")

    Returns:
        Loguru logger bound with agent context

    Example:
        log = get_logger("collector")
        log.info("Started")
        log.warning("Reconnecting to Wazuh...")
        log.error("Failed to fetch alerts")
    """
    return logger.bind(agent=agent_name)
