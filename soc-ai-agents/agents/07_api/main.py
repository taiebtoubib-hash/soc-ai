"""
agents/07_api/main.py
FastAPI bridge between Kafka and the React dashboard.

GET  /stream        — SSE stream, broadcasts messages from the background consumer
GET  /api/incidents — returns the list of historical incidents (newest first)
POST /api/feedback  — receives analyst feedback, publishes to soc.feedback topic
GET  /api/health    — health check
"""

import asyncio
import json
import logging
from typing import AsyncGenerator, Set
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from confluent_kafka import Consumer, Producer, KafkaError
from shared.config import settings

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("api")


def flatten_incident(report: dict) -> dict:
    """Flatten nested IncidentReport dictionary to matching React dashboard format."""
    classification = report.get("classification") or {}
    detection = classification.get("detection") or {}
    enriched = detection.get("enriched") or {}
    alert = enriched.get("alert") or {}
    
    # Extract actions as a list of string keys
    actions_taken = report.get("actions_taken") or []
    actions = []
    for a in actions_taken:
        if isinstance(a, dict) and a.get("action_type"):
            actions.append(a.get("action_type"))
        elif hasattr(a, "action_type") and getattr(a, "action_type"):
            actions.append(getattr(a, "action_type"))

    # Extract features
    features = enriched.get("features") or {}
    
    # Extract country
    country = enriched.get("src_geo_country") or "unknown"
    
    # Extract llm_analysis
    llm_analysis = (
        report.get("llm_narrative") 
        or detection.get("llm_analysis") 
        or classification.get("explanation") 
        or ""
    )
    
    return {
        "id": report.get("id") or f"INC-{alert.get('id', 'unknown')}",
        "timestamp": alert.get("timestamp") or report.get("timestamp") or "",
        "src_ip": alert.get("src_ip") or "",
        "rule": detection.get("rule_name") or "NONE",
        "attack_type": classification.get("attack_type") or "normal",
        "ml_label": classification.get("ml_label") or "benign",
        "final_score": classification.get("final_score") or 0.0,
        "actions": actions,
        "resolved": report.get("resolved") or False,
        "llm_analysis": llm_analysis,
        "country": country,
        "features": features
    }


# Active SSE client queues & in-memory cache
sse_queues: Set[asyncio.Queue] = set()
incidents_cache = []


def _process_message(msg) -> dict | None:
    """Parse a raw Kafka message into a flattened incident dict. Returns None on error."""
    try:
        raw_val = msg.value().decode("utf-8")
        report = json.loads(raw_val)
        return flatten_incident(report)
    except Exception as e:
        log.error("Error parsing Kafka message: %s", e)
        return None


def _upsert_cache(flat_inc: dict):
    """Insert or update an incident in the in-memory cache (max 100 entries)."""
    for i, existing in enumerate(incidents_cache):
        if existing["id"] == flat_inc["id"]:
            incidents_cache[i] = flat_inc
            return
    incidents_cache.append(flat_inc)
    if len(incidents_cache) > 100:
        incidents_cache.pop(0)


async def kafka_consumer_loop():
    """Continuously consumes from soc.frontend in the background, caching and broadcasting alerts."""
    log.info("Starting background Kafka consumer loop...")
    consumer = None

    # Re-try connection loop in case Kafka is booting up
    while True:
        try:
            consumer = Consumer({
                "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
                "group.id":          "api-background-consumer",
                "auto.offset.reset": "earliest",
                # Never commit offsets so every restart replays full history
                "enable.auto.commit": False,
            })
            consumer.subscribe(["soc.frontend"])
            log.info("Connected to Kafka; subscribed to soc.frontend.")
            break
        except Exception as e:
            log.error("Failed to connect to Kafka at %s: %s. Retrying in 5 seconds...",
                      settings.KAFKA_BOOTSTRAP_SERVERS, e)
            await asyncio.sleep(5)

    try:
        loop = asyncio.get_running_loop()

        # ── Startup replay: drain all existing messages before going live ──
        log.info("Replaying historical soc.frontend messages into cache...")
        consecutive_empty = 0
        while consecutive_empty < 3:
            msg = await loop.run_in_executor(None, consumer.poll, 0.5)
            if msg is None:
                consecutive_empty += 1
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.error("Kafka error during replay: %s", msg.error())
                consecutive_empty += 1
                continue
            consecutive_empty = 0
            flat_inc = _process_message(msg)
            if flat_inc:
                _upsert_cache(flat_inc)

        log.info("Replay complete — %d historical incidents loaded.", len(incidents_cache))

        # ── Live loop: broadcast new events to SSE clients ──
        while True:
            msg = await loop.run_in_executor(None, consumer.poll, 0.5)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.error("Kafka consumer error: %s", msg.error())
                continue

            flat_inc = _process_message(msg)
            if flat_inc:
                _upsert_cache(flat_inc)
                event_data = f"data: {json.dumps(flat_inc)}\n\n"
                for q in list(sse_queues):
                    await q.put(event_data)

    except asyncio.CancelledError:
        log.info("Background consumer loop task cancelled.")
    finally:
        if consumer:
            consumer.close()
        log.info("Background consumer connection closed.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Spawn the background Kafka consumer task
    bg_task = asyncio.create_task(kafka_consumer_loop())
    yield
    # Clean up on shutdown
    bg_task.cancel()
    try:
        await bg_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="SOC AI API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/stream")
async def stream():
    async def sse_generator():
        q = asyncio.Queue()
        sse_queues.add(q)
        try:
            while True:
                data = await q.get()
                yield data
        finally:
            sse_queues.remove(q)
            
    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/incidents")
async def get_incidents():
    """Returns the list of cached incidents, sorted newest first."""
    return list(reversed(incidents_cache))


# ── Feedback endpoint ──────────────────────────────────────────────────

class FeedbackRecord(BaseModel):
    verdict:        str
    note:           str = ""
    correctLabel:   str = ""
    incidentId:     str
    srcIp:          str
    originalLabel:  str
    originalScore:  float
    rule:           str
    features:       dict = {}
    analystTimestamp: str


@app.post("/api/feedback")
async def submit_feedback(record: FeedbackRecord):
    producer = Producer({"bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS})
    producer.produce(
        topic="soc.feedback",
        key=record.incidentId.encode(),
        value=record.model_dump_json().encode(),
    )
    producer.flush()
    log.info("[API] Feedback recorded: %s → %s", record.incidentId, record.verdict)
    return {"status": "ok", "incidentId": record.incidentId}


@app.get("/api/health")
async def health():
    """Health check — also validates Kafka connectivity."""
    kafka_ok = False
    try:
        from confluent_kafka.admin import AdminClient
        admin = AdminClient({"bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS})
        meta = admin.list_topics(timeout=3)
        kafka_ok = meta is not None
    except Exception:
        pass
    return {
        "status": "ok" if kafka_ok else "degraded",
        "kafka": kafka_ok,
        "cached_incidents": len(incidents_cache),
    }