"""
shared/queue_bus.py
-------------------
Shared Queue instances for inter-agent communication.
Every agent imports its input/output queues from here.

PIPELINE FLOW:
  Collector
      ↓ raw_alerts_queue
  Analysis
      ↓ enriched_alerts_queue
  Detection
      ↓ detection_results_queue
  ML Classifier
      ↓ classification_results_queue
  FP Detector
      ↓ true_positive_queue    (confirmed threats → Orchestrator)
      ↓ false_positive_queue   (confirmed FPs → logged + learned)
  Orchestrator
      ↓ orchestration_queue
  Response
      ↓ incident_report_queue  (completed incidents → DB)

"""

from queue import Queue

# ── Main Pipeline ──────────────────────────────────────────────────

# 01 Collector → 02 Analysis
raw_alerts_queue = Queue()

# 02 Analysis → 03 Detection
enriched_alerts_queue = Queue()

# 03 Detection → 04 ML Classifier
detection_results_queue = Queue()

# 04 ML Classifier → 04b FP Detector
classification_results_queue = Queue()

# 04b FP Detector → 05 Orchestrator (confirmed TRUE positives only)
true_positive_queue = Queue()

# 04b FP Detector → DB logger (confirmed FALSE positives for learning)
false_positive_queue = Queue()

# 05 Orchestrator → 06 Response
orchestration_queue = Queue()

# 06 Response → DB (completed incident reports)
incident_report_queue = Queue()


# ── Helper Functions ───────────────────────────────────────────────

from shared.config import settings

# If USE_KAFKA is true, we replace the queues with Kafka topics abstraction.
# But queue.Queue is synchronous and Kafka needs to be wrapped.

def get_queue_sizes() -> dict:
    """
    Returns current size of all queues.
    Useful for monitoring pipeline health.
    If KAFKA is used, this returns dummy values (0) since Kafka topics 
    don't provide instant size without specific AdminClient calls.
    """
    if settings.USE_KAFKA:
        return {
            "raw_alerts": 0, "enriched_alerts": 0, "detection_results": 0,
            "classification_results": 0, "true_positives": 0, "false_positives": 0,
            "orchestration": 0, "incident_reports": 0
        }

    return {
        "raw_alerts":            raw_alerts_queue.qsize(),
        "enriched_alerts":       enriched_alerts_queue.qsize(),
        "detection_results":     detection_results_queue.qsize(),
        "classification_results": classification_results_queue.qsize(),
        "true_positives":        true_positive_queue.qsize(),
        "false_positives":       false_positive_queue.qsize(),
        "orchestration":         orchestration_queue.qsize(),
        "incident_reports":      incident_report_queue.qsize(),
    }


def check_pipeline_health() -> bool:
    """
    Warns if any queue is backing up (> 100 items).
    A backed-up queue means the downstream agent is too slow.

    Returns True if healthy, False if any queue is backed up.
    """
    sizes = get_queue_sizes()
    healthy = True

    for name, size in sizes.items():
        if size > 100:
            print(f"⚠️  WARNING: {name} queue has {size} items — agent may be overloaded")
            healthy = False

    return healthy