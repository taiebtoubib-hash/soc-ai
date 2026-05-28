"""
shared/kafka_bus.py
-------------------
Kafka-based message bus for inter-agent communication.
Replaces queue_bus.py when USE_KAFKA=true.
Provides the same publish/consume semantics but over Kafka.

Uses confluent-kafka library (same as agents/07_api/main.py) for compatibility.
"""
import json
import logging
from typing import Any, Type, Optional, Callable
from pydantic import BaseModel

log = logging.getLogger("kafka_bus")

from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError
KAFKA_AVAILABLE = True


class KafkaBus:
    def __init__(self, bootstrap_servers: str):
        self.bootstrap_servers = bootstrap_servers
        self.producer: Optional[KafkaProducer] = None

    def _get_producer(self) -> KafkaProducer:
        if not self.producer:
            # kafka-python expects bootstrap_servers as list or string
            self.producer = KafkaProducer(bootstrap_servers=self.bootstrap_servers,
                                          linger_ms=100,
                                          retries=5)
        return self.producer

    def publish(self, topic: str, value: Any, key: Optional[str] = None):
        """
        Publish a Pydantic model (or dict) to a Kafka topic using kafka-python.
        Serializes as JSON bytes and flushes to ensure delivery. Errors are
        logged and re-raised so they surface in container logs.
        """
        producer = self._get_producer()
        try:
            value_bytes = json.dumps(
                value.model_dump() if isinstance(value, BaseModel) else value
            ).encode("utf-8")
            key_bytes = key.encode("utf-8") if key else None

            future = producer.send(topic, key=key_bytes, value=value_bytes)
            producer.flush(timeout=10)
            try:
                # Wait for send result to surface errors
                future.get(timeout=10)
            except Exception as e:
                log.error(f"Error publishing to {topic}: {e}")
                raise
        except Exception as e:
            log.error(f"Error publishing to {topic}: {e}", exc_info=True)
            raise

    def consume(self, topic: str, group_id: str, model_class: Type[BaseModel], callback: Callable[[BaseModel], None]):
        """
        Consume messages from a Kafka topic indefinitely using kafka-python.
        For each message, deserialize to model_class and invoke the callback.
        """
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=group_id,
            auto_offset_reset="earliest",
            enable_auto_commit=True
        )

        log.info(f"Subscribed to {topic} (group: {group_id})")

        try:
            for msg in consumer:
                try:
                    raw_val = msg.value.decode("utf-8") if isinstance(msg.value, (bytes, bytearray)) else msg.value
                    data = json.loads(raw_val)
                    model_instance = model_class(**data)
                    callback(model_instance)
                except Exception as e:
                    log.error(f"Error processing message from {topic}: {e}", exc_info=True)
        finally:
            consumer.close()
