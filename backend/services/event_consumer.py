"""
Event Consumer & Idempotent Ingestion Worker Engine
Consumes events from Redis Streams ('events:stream') via Consumer Groups ('phantomnet-workers').
Guarantees At-Least-Once delivery with primary UUIDv7 and secondary canonical fingerprint deduplication.
Acknowledges (XACK) only AFTER successful database transaction commit.
"""
import os
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import redis
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from schemas.event_envelope import EventEnvelope, generate_uuidv7
from database import SessionLocal
from database.models import PacketLog
from services.geoip_service import geoip_service

logger = logging.getLogger("PhantomNet.EventConsumer")

DEFAULT_STREAM_KEY = "events:stream"
DEFAULT_GROUP_NAME = "phantomnet-workers"
DEFAULT_BATCH_SIZE = 100
DEFAULT_DEDUP_WINDOW_SECONDS = 60


class EventConsumer:
    """
    Durable stream consumer worker with idempotent persistence and transactional XACK.
    """
    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        redis_url: Optional[str] = None,
        stream_key: str = DEFAULT_STREAM_KEY,
        group_name: str = DEFAULT_GROUP_NAME,
        consumer_name: Optional[str] = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        dedup_window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
    ):
        self.stream_key = stream_key
        self.group_name = group_name
        self.consumer_name = consumer_name or f"worker-{generate_uuidv7()[:8]}"
        self.batch_size = batch_size
        self.dedup_window_seconds = dedup_window_seconds

        if redis_client is not None:
            self.redis = redis_client
        else:
            url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
            self.redis = redis.Redis.from_url(url, decode_responses=False)

        self._ensure_consumer_group()

    def _ensure_consumer_group(self):
        """Creates the consumer group on the stream if it does not already exist."""
        try:
            self.redis.xgroup_create(
                name=self.stream_key,
                groupname=self.group_name,
                id="0",
                mkstream=True,
            )
            logger.info(f"Consumer group '{self.group_name}' created on '{self.stream_key}'.")
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                # Group already exists
                pass
            else:
                logger.warning(f"Error creating consumer group: {e}")

    def process_envelope(
        self,
        envelope: EventEnvelope,
        db: Session,
    ) -> Tuple[bool, str]:
        """
        Idempotently inserts an EventEnvelope into the PacketLog table.
        Returns (was_inserted: bool, outcome: "INSERTED" | "DEDUP_UUID" | "DEDUP_FINGERPRINT").
        """
        # 1. Primary Deduplication: Check UUIDv7 uniqueness
        if envelope.event_id:
            existing_uuid = db.query(PacketLog).filter(PacketLog.event_id == envelope.event_id).first()
            if existing_uuid is not None:
                logger.debug(f"DUR-02 Primary dedup: event_id {envelope.event_id} already exists.")
                return False, "DEDUP_UUID"

        # 2. Secondary Deduplication: Check canonical fingerprint within sliding time window
        if envelope.canonical_fingerprint:
            window_start = datetime.utcnow() - timedelta(seconds=self.dedup_window_seconds)
            existing_fp = (
                db.query(PacketLog)
                .filter(
                    PacketLog.canonical_fingerprint == envelope.canonical_fingerprint,
                    PacketLog.timestamp >= window_start,
                )
                .first()
            )
            if existing_fp is not None:
                logger.debug(
                    f"DUR-02 Secondary dedup: fingerprint {envelope.canonical_fingerprint} "
                    f"seen within {self.dedup_window_seconds}s window."
                )
                return False, "DEDUP_FINGERPRINT"

        # 3. GeoIP Enrichment
        geo = {}
        try:
            geo = geoip_service.lookup(envelope.src_ip)
        except Exception:
            pass

        # 4. Construct PacketLog model
        event_time = (
            datetime.utcfromtimestamp(envelope.timestamp_ns / 1_000_000_000)
            if envelope.timestamp_ns
            else datetime.utcnow()
        )

        packet_log = PacketLog(
            timestamp=event_time,
            src_ip=envelope.src_ip,
            dst_ip=envelope.dst_ip or "127.0.0.1",
            src_port=envelope.src_port or 0,
            dst_port=envelope.dst_port or 0,
            protocol=envelope.protocol.upper() if envelope.protocol else "TCP",
            length=envelope.length or 0,
            is_malicious=envelope.is_malicious,
            threat_score=envelope.threat_score,
            threat_level=envelope.threat_level,
            attack_type=envelope.attack_type or envelope.event_type.upper(),
            event=envelope.event_type,
            event_id=envelope.event_id,
            canonical_fingerprint=envelope.canonical_fingerprint,
            honeypot_id=envelope.honeypot_id,
            raw_payload=json.dumps(envelope.payload) if envelope.payload else None,
            country=geo.get("country"),
            city=geo.get("city"),
            latitude=geo.get("lat"),
            longitude=geo.get("lon"),
        )

        db.add(packet_log)
        return True, "INSERTED"

    def consume_batch(
        self,
        db: Optional[Session] = None,
        count: Optional[int] = None,
        block_ms: int = 100,
    ) -> Dict[str, Any]:
        """
        Reads and processes a batch from the stream using XREADGROUP.
        Only acknowledges (XACK) entries after database transaction commit succeeds.
        """
        batch_limit = count or self.batch_size
        owns_db = False
        if db is None:
            db = SessionLocal()
            owns_db = True

        stats = {
            "read_count": 0,
            "inserted_count": 0,
            "dedup_uuid_count": 0,
            "dedup_fp_count": 0,
            "acked_count": 0,
            "failed_count": 0,
            "message_ids": [],
        }

        try:
            # Read new messages assigned to this consumer group
            response = self.redis.xreadgroup(
                groupname=self.group_name,
                consumername=self.consumer_name,
                streams={self.stream_key: ">"},
                count=batch_limit,
                block=block_ms,
            )

            if not response:
                return stats

            # Response structure: [[stream_name, [[msg_id, {field: val}], ...]]]
            messages = []
            for stream_entry in response:
                stream_name, entries = stream_entry
                messages.extend(entries)

            stats["read_count"] = len(messages)
            if not messages:
                return stats

            acked_ids = []
            for msg_id, raw_fields in messages:
                msg_id_str = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)
                try:
                    envelope = EventEnvelope.from_stream_dict(raw_fields)
                    inserted, outcome = self.process_envelope(envelope, db)
                    if inserted:
                        stats["inserted_count"] += 1
                    elif outcome == "DEDUP_UUID":
                        stats["dedup_uuid_count"] += 1
                    elif outcome == "DEDUP_FINGERPRINT":
                        stats["dedup_fp_count"] += 1
                    
                    # Add to list of messages to be acknowledged upon commit
                    acked_ids.append(msg_id)
                except Exception as e:
                    logger.error(f"Error processing message {msg_id_str}: {e}")
                    stats["failed_count"] += 1
                    # Do not ack; leave in PEL for retry or DLQ routing!

            # Commit database transaction
            if acked_ids:
                try:
                    db.commit()
                    # Acknowledge in Redis ONLY after DB commit!
                    self.redis.xack(self.stream_key, self.group_name, *acked_ids)
                    stats["acked_count"] = len(acked_ids)
                    stats["message_ids"] = [
                        m.decode("utf-8") if isinstance(m, bytes) else str(m)
                        for m in acked_ids
                    ]
                except IntegrityError as ie:
                    db.rollback()
                    logger.warning(f"Integrity conflict during batch commit: {ie}. Retrying individually.")
                    # Retry item-by-item to isolate the conflict
                    self._commit_individually(messages, db, stats)
                except Exception as ce:
                    db.rollback()
                    logger.error(f"Database commit failed: {ce}. Messages will remain in PEL.")
                    # Do not ack; will be retried or claimed by PEL scheduler
                    raise ce

            return stats

        finally:
            if owns_db:
                db.close()

    def _commit_individually(
        self,
        messages: List[Tuple[Any, Dict[str, Any]]],
        db: Session,
        stats: Dict[str, Any],
    ):
        """Fallback to commit entries one-by-one if a batch-level integrity error occurs."""
        for msg_id, raw_fields in messages:
            try:
                envelope = EventEnvelope.from_stream_dict(raw_fields)
                inserted, outcome = self.process_envelope(envelope, db)
                db.commit()
                self.redis.xack(self.stream_key, self.group_name, msg_id)
                stats["acked_count"] += 1
            except Exception as e:
                db.rollback()
                logger.warning(f"Individual commit failed for message {msg_id}: {e}")
