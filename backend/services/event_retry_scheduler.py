"""
PEL (Pending Entries List) Retry Scheduler & Dead Letter Queue (DLQ) Manager
Monitors unacknowledged messages in Redis consumer groups.
Reclaims messages that timed out (e.g. 30s idle time).
Routes persistent failures to Dead Letter Queue ('events:dlq') after 3 delivery attempts.
"""
import os
import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import redis
from sqlalchemy.orm import Session

from schemas.event_envelope import EventEnvelope
from services.event_consumer import EventConsumer, DEFAULT_STREAM_KEY, DEFAULT_GROUP_NAME
from database import SessionLocal

logger = logging.getLogger("PhantomNet.EventRetryScheduler")

DEFAULT_DLQ_STREAM_KEY = "events:dlq"
DEFAULT_IDLE_TIMEOUT_MS = 30_000  # 30 seconds
DEFAULT_MAX_RETRIES = 3


class EventRetryScheduler:
    """
    Manages recovery of orphaned/timed-out messages in Redis Stream PEL and routes to DLQ.
    """
    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        redis_url: Optional[str] = None,
        stream_key: str = DEFAULT_STREAM_KEY,
        group_name: str = DEFAULT_GROUP_NAME,
        dlq_stream_key: str = DEFAULT_DLQ_STREAM_KEY,
        idle_timeout_ms: int = DEFAULT_IDLE_TIMEOUT_MS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        consumer_engine: Optional[EventConsumer] = None,
    ):
        self.stream_key = stream_key
        self.group_name = group_name
        self.dlq_stream_key = dlq_stream_key
        self.idle_timeout_ms = idle_timeout_ms
        self.max_retries = max_retries

        if redis_client is not None:
            self.redis = redis_client
        else:
            url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
            self.redis = redis.Redis.from_url(url, decode_responses=False)

        self.consumer = consumer_engine or EventConsumer(
            redis_client=self.redis,
            stream_key=self.stream_key,
            group_name=self.group_name,
            consumer_name="pel-recovery-worker",
        )

    def scan_and_reclaim(
        self,
        db: Optional[Session] = None,
        count: int = 100,
    ) -> Dict[str, Any]:
        """
        Scans the PEL for messages idle for >= idle_timeout_ms.
        - If delivery count > max_retries: routes to DLQ and XACKs.
        - If delivery count <= max_retries: reclaims message via XCLAIM, attempts re-processing.
        Returns statistics.
        """
        stats = {
            "scanned_pending": 0,
            "reclaimed_count": 0,
            "dlq_routed_count": 0,
            "reprocessed_acked": 0,
            "dlq_message_ids": [],
            "reclaimed_message_ids": [],
        }

        owns_db = False
        if db is None:
            db = SessionLocal()
            owns_db = True

        try:
            # Query pending entries list
            # xpending_range returns list of dicts or tuples:
            # [{'message_id': ..., 'consumer': ..., 'idle_time': ..., 'delivery_count': ...}, ...]
            try:
                pending_entries = self.redis.xpending_range(
                    name=self.stream_key,
                    groupname=self.group_name,
                    min="-",
                    max="+",
                    count=count,
                )
            except redis.ResponseError as e:
                # Key or group might not exist
                logger.debug(f"xpending_range query skipped: {e}")
                return stats

            if not pending_entries:
                return stats

            stats["scanned_pending"] = len(pending_entries)

            for entry in pending_entries:
                # Normalize entry attributes whether dict or tuple
                if isinstance(entry, dict):
                    msg_id = entry.get("message_id")
                    idle_ms = entry.get("idle_time", 0)
                    delivery_count = entry.get("delivery_count", 1)
                elif isinstance(entry, (list, tuple)):
                    # Redis standard tuple: (msg_id, consumer, idle_ms, delivery_count)
                    msg_id = entry[0]
                    idle_ms = entry[2]
                    delivery_count = entry[3]
                else:
                    continue

                msg_id_str = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)

                # Check if idle threshold reached
                if idle_ms < self.idle_timeout_ms:
                    continue

                # Fetch raw message content via xrange
                raw_messages = self.redis.xrange(self.stream_key, min=msg_id, max=msg_id, count=1)
                if not raw_messages:
                    # Message was deleted or already acknowledged
                    continue

                _, message_data = raw_messages[0]

                # If exceeded max retries: Route to DLQ!
                if delivery_count >= self.max_retries:
                    self._route_to_dlq(msg_id, msg_id_str, message_data, delivery_count)
                    stats["dlq_routed_count"] += 1
                    stats["dlq_message_ids"].append(msg_id_str)
                    continue

                # Otherwise: Claim and attempt re-processing
                claimed_messages = self.redis.xclaim(
                    name=self.stream_key,
                    groupname=self.group_name,
                    consumername="pel-recovery-worker",
                    min_idle_time=self.idle_timeout_ms,
                    message_ids=[msg_id],
                )

                if not claimed_messages:
                    continue

                stats["reclaimed_count"] += 1
                stats["reclaimed_message_ids"].append(msg_id_str)

                # Attempt processing
                for c_msg_id, c_fields in claimed_messages:
                    try:
                        envelope = EventEnvelope.from_stream_dict(c_fields)
                        self.consumer.process_envelope(envelope, db)
                        db.commit()
                        self.redis.xack(self.stream_key, self.group_name, c_msg_id)
                        stats["reprocessed_acked"] += 1
                        logger.info(f"Reclaimed message {msg_id_str} re-processed and acknowledged successfully.")
                    except Exception as pe:
                        db.rollback()
                        logger.warning(
                            f"Re-processing attempt failed for reclaimed message {msg_id_str}: {pe}. "
                            f"Will retry or route to DLQ on next cycle."
                        )

            return stats

        finally:
            if owns_db:
                db.close()

    def _route_to_dlq(
        self,
        msg_id: Any,
        msg_id_str: str,
        message_data: Dict[Any, Any],
        delivery_count: int,
        failure_reason: str = "MAX_DELIVERY_ATTEMPTS_EXCEEDED",
    ):
        """
        Appends poisonous/unparseable message to DLQ stream and acknowledges it from main stream.
        """
        # Serialize fields for DLQ
        serialized_fields = {}
        for k, v in message_data.items():
            key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8") if isinstance(v, bytes) else str(v)
            serialized_fields[key] = val

        dlq_entry = {
            "failed_message_id": msg_id_str,
            "original_stream": self.stream_key,
            "delivery_attempts": str(delivery_count),
            "dlq_reason": failure_reason,
            "routed_at": datetime.utcnow().isoformat(),
            "raw_payload": json.dumps(serialized_fields),
        }

        # Write to DLQ stream
        dlq_id = self.redis.xadd(self.dlq_stream_key, dlq_entry)
        dlq_id_str = dlq_id.decode("utf-8") if isinstance(dlq_id, bytes) else str(dlq_id)

        # Acknowledge in original stream to remove from PEL
        self.redis.xack(self.stream_key, self.group_name, msg_id)

        logger.warning(
            f"[DLQ-04] Message {msg_id_str} failed {delivery_count} times. "
            f"Routed to DLQ stream '{self.dlq_stream_key}' as {dlq_id_str} and acknowledged from main stream."
        )
