"""
shared/kafka_bus.py
-------------------
Kafka-based message bus for inter-agent communication.
Replaces queue_bus.py when USE_KAFKA=true.
Provides the same publish/consume semantics but over Kafka.
"""

import json
import logging
import uuid
import time
from typing import Any, Type, Optional, Callable
from pydantic import BaseModel

log = logging.getLogger("kafka_bus")

try:
    from kafka import KafkaProducer, KafkaConsumer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False


class KafkaBus:
    def __init__(self, bootstrap_servers: str):
        self.bootstrap_servers = bootstrap_servers
        self.producer = None
        
        # We initialize lazily to avoid connection issues 
        # if this is imported before Kafka is up.

    def _get_producer(self):
        if not self.producer:
            if not KAFKA_AVAILABLE:
                raise ImportError("kafka-python not installed. Cannot use KafkaBus.")
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v.model_dump() if isinstance(v, BaseModel) else v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                retries=5
            )
        return self.producer

    def publish(self, topic: str, value: Any, key: Optional[str] = None):
        """
        Publish a Pydantic model (or dict) to a Kafka topic.
        """
        producer = self._get_producer()
        try:
            future = producer.send(topic, key=key, value=value)
            # Wait for record metadata to ensure it's sent
            future.get(timeout=10)
        except Exception as e:
            log.error(f"Error publishing to {topic}: {e}")
            raise

    def consume(self, topic: str, group_id: str, model_class: Type[BaseModel], callback: Callable[[BaseModel], None]):
        """
        Consume messages from a Kafka topic indefinitely.
        For each message, deserialize to model_class and invoke the callback.
        """
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python not installed. Cannot use KafkaBus.")
            
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=group_id,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        
        log.info(f"Subscribed to {topic} (group: {group_id})")
        
        for message in consumer:
            try:
                data = message.value
                model_instance = model_class(**data)
                callback(model_instance)
            except Exception as e:
                log.error(f"Error processing message from {topic}: {e}", exc_info=True)
