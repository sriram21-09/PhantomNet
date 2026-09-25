"""
Ingestion Gateway Service
Isolated producer-facing gateway service for PhantomNet V3.
CRITICAL CONSTRAINT: This service has ZERO direct access or credentials to PostgreSQL.
It validates HMAC-SHA256 origin provenance, enforces backpressure, and publishes
canonical EventEnvelopes directly to Redis Streams.
"""
import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
import redis
import redis.asyncio as aioredis
from pydantic import ValidationError

from schemas.event_envelope import EventEnvelope
from services.origin_auth import (
    verify_origin_signature,
    verify_event_dict,
    get_honeypot_secret_key,
)

logger = logging.getLogger("PhantomNet.IngestionGateway")

DEFAULT_STREAM_KEY = "events:stream"
DEFAULT_MAX_STREAM_LEN = 100_000
DEFAULT_MAX_BATCH_SIZE = 500


class IngestionBackpressureError(Exception):
    """Raised when Redis stream capacity threshold is reached."""
    def __init__(self, current_len: int, max_len: int):
        super().__init__(f"Queue saturated: depth {current_len} exceeds max {max_len}")
        self.current_len = current_len
        self.max_len = max_len


class IngestionAuthenticationError(Exception):
    """Raised when origin authentication fails."""
    pass


def get_redis_client(redis_url: Optional[str] = None) -> redis.Redis:
    """Returns a Redis client instance configured from environment or URL."""
    url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return redis.Redis.from_url(url, decode_responses=False)


class IngestionGateway:
    """
    High-performance ingestion gateway connecting honeypot producers to Redis Streams.
    Supports non-blocking async Redis operations for maximum event loop concurrency
    while preserving backwards compatibility for synchronous fixtures.
    """
    def __init__(
        self,
        redis_client: Optional[Any] = None,
        async_redis_client: Optional[Any] = None,
        redis_url: Optional[str] = None,
        stream_key: str = DEFAULT_STREAM_KEY,
        max_stream_len: int = DEFAULT_MAX_STREAM_LEN,
        max_batch_size: int = DEFAULT_MAX_BATCH_SIZE,
        secret_key: Optional[str] = None,
    ):
        self.stream_key = stream_key
        self.max_stream_len = max_stream_len
        self.max_batch_size = max_batch_size
        self._secret_key = secret_key
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")

        if redis_client is not None:
            self.redis = redis_client
        else:
            self.redis = redis.Redis.from_url(self.redis_url, decode_responses=False)

        if async_redis_client is not None:
            self.async_redis = async_redis_client
        elif hasattr(self.redis, "xadd") and asyncio.iscoroutinefunction(self.redis.xadd):
            self.async_redis = self.redis
        else:
            try:
                self.async_redis = aioredis.from_url(
                    self.redis_url,
                    decode_responses=False,
                    max_connections=50,
                )
            except Exception as e:
                logger.warning(f"Could not initialize async Redis: {e}")
                self.async_redis = None

    def _get_secret_key(self) -> str:
        return self._secret_key or get_honeypot_secret_key()

    def check_backpressure(self) -> int:
        """
        Inspects stream length synchronously. Raises IngestionBackpressureError if overloaded.
        Returns current queue length.
        """
        try:
            current_len = self.redis.xlen(self.stream_key)
        except redis.ResponseError:
            current_len = 0
        except Exception as e:
            logger.warning(f"Error checking stream length: {e}")
            current_len = 0

        if current_len >= self.max_stream_len:
            raise IngestionBackpressureError(current_len, self.max_stream_len)
        return current_len

    async def check_backpressure_async(self) -> int:
        """
        Inspects stream length asynchronously without blocking the event loop.
        """
        try:
            if self.async_redis is not None and hasattr(self.async_redis, "xlen"):
                current_len = await self.async_redis.xlen(self.stream_key)
            elif hasattr(self.redis, "xlen") and asyncio.iscoroutinefunction(self.redis.xlen):
                current_len = await self.redis.xlen(self.stream_key)
            else:
                current_len = await asyncio.to_thread(self.redis.xlen, self.stream_key)
        except Exception as e:
            logger.warning(f"Error checking async stream length: {e}")
            current_len = 0

        if current_len >= self.max_stream_len:
            raise IngestionBackpressureError(current_len, self.max_stream_len)
        return current_len

    def authenticate_request(
        self,
        body_bytes: bytes,
        signature: Optional[str] = None,
        timestamp: Optional[int] = None,
        parsed_dict: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Validates origin HMAC-SHA256 signature either from headers or embedded _origin_auth envelope.
        """
        secret = self._get_secret_key()

        # Check header-based authentication
        if signature and timestamp is not None:
            if parsed_dict:
                clean_dict = {k: v for k, v in parsed_dict.items() if k != "_origin_auth"}
                canon_bytes = json.dumps(clean_dict, sort_keys=True).encode("utf-8")
                is_valid, reason = verify_origin_signature(
                    payload_bytes=canon_bytes,
                    timestamp=timestamp,
                    signature=signature,
                    secret_key=secret,
                )
                if is_valid:
                    return True

            is_valid, reason = verify_origin_signature(
                payload_bytes=body_bytes,
                timestamp=timestamp,
                signature=signature,
                secret_key=secret,
            )
            if is_valid:
                return True

            if parsed_dict and "_origin_auth" in parsed_dict:
                emb_valid, _ = verify_event_dict(parsed_dict, secret_key=secret)
                if emb_valid:
                    return True

            raise IngestionAuthenticationError(f"Origin signature verification failed: {reason}")

        # Check embedded _origin_auth dict
        if parsed_dict and "_origin_auth" in parsed_dict:
            is_valid, reason = verify_event_dict(parsed_dict, secret_key=secret)
            if not is_valid:
                raise IngestionAuthenticationError(f"Embedded origin auth failed: {reason}")
            return True

        # In production mode (or strict security), require valid credentials
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env in ["production", "prod"]:
            raise IngestionAuthenticationError("Missing required honeypot origin signature headers")

        logger.debug("Ingestion: no signature provided; permitted in non-production mode")
        return True

    async def ingest_event_async(
        self,
        event_data: Dict[str, Any],
        raw_bytes: Optional[bytes] = None,
        signature: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Asynchronously ingests a single event envelope via non-blocking Redis I/O.
        """
        # 1. Authenticate
        body_bytes = raw_bytes or json.dumps(event_data, sort_keys=True).encode("utf-8")
        self.authenticate_request(body_bytes, signature, timestamp, event_data)

        # 2. Validate envelope
        clean_data = {k: v for k, v in event_data.items() if k != "_origin_auth"}
        envelope = EventEnvelope.model_validate(clean_data)

        # 3. Backpressure check
        await self.check_backpressure_async()

        # 4. Stream write via non-blocking async Redis
        stream_payload = envelope.to_stream_dict()
        if self.async_redis is not None and hasattr(self.async_redis, "xadd"):
            msg_id = await self.async_redis.xadd(self.stream_key, stream_payload)
        elif hasattr(self.redis, "xadd") and asyncio.iscoroutinefunction(self.redis.xadd):
            msg_id = await self.redis.xadd(self.stream_key, stream_payload)
        else:
            msg_id = await asyncio.to_thread(self.redis.xadd, self.stream_key, stream_payload)

        msg_id_str = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)
        return {
            "status": "accepted",
            "event_id": envelope.event_id,
            "canonical_fingerprint": envelope.canonical_fingerprint,
            "stream_id": msg_id_str,
            "timestamp_ns": envelope.timestamp_ns,
        }

    def ingest_event(
        self,
        event_data: Dict[str, Any],
        raw_bytes: Optional[bytes] = None,
        signature: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous ingestion method for backwards compatibility with tests.
        """
        body_bytes = raw_bytes or json.dumps(event_data, sort_keys=True).encode("utf-8")
        self.authenticate_request(body_bytes, signature, timestamp, event_data)

        clean_data = {k: v for k, v in event_data.items() if k != "_origin_auth"}
        envelope = EventEnvelope.model_validate(clean_data)

        self.check_backpressure()

        stream_payload = envelope.to_stream_dict()
        msg_id = self.redis.xadd(self.stream_key, stream_payload)
        msg_id_str = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)

        return {
            "status": "accepted",
            "event_id": envelope.event_id,
            "canonical_fingerprint": envelope.canonical_fingerprint,
            "stream_id": msg_id_str,
            "timestamp_ns": envelope.timestamp_ns,
        }

    async def ingest_batch_async(
        self,
        events: List[Dict[str, Any]],
        raw_bytes: Optional[bytes] = None,
        signature: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Asynchronously ingests a batch of event envelopes via Redis Pipeline.
        """
        if not events:
            return {"status": "accepted", "accepted_count": 0, "event_ids": []}

        if len(events) > self.max_batch_size:
            raise ValueError(f"Batch size {len(events)} exceeds maximum allowed {self.max_batch_size}")

        # 1. Authenticate
        body_bytes = raw_bytes or json.dumps(events, sort_keys=True).encode("utf-8")
        self.authenticate_request(body_bytes, signature, timestamp)

        # 2. Validate all envelopes
        validated_envelopes: List[EventEnvelope] = []
        for item in events:
            clean_item = {k: v for k, v in item.items() if k != "_origin_auth"}
            envelope = EventEnvelope.model_validate(clean_item)
            validated_envelopes.append(envelope)

        # 3. Backpressure check
        current_len = await self.check_backpressure_async()
        if current_len + len(validated_envelopes) > self.max_stream_len:
            raise IngestionBackpressureError(current_len, self.max_stream_len)

        # 4. Pipeline write
        if self.async_redis is not None and hasattr(self.async_redis, "pipeline"):
            pipe = self.async_redis.pipeline()
            for env in validated_envelopes:
                pipe.xadd(self.stream_key, env.to_stream_dict())
            redis_ids = await pipe.execute()
        elif hasattr(self.redis, "pipeline") and asyncio.iscoroutinefunction(self.redis.pipeline):
            pipe = self.redis.pipeline()
            for env in validated_envelopes:
                pipe.xadd(self.stream_key, env.to_stream_dict())
            redis_ids = await pipe.execute()
        else:
            def _sync_pipe():
                pipe = self.redis.pipeline()
                for env in validated_envelopes:
                    pipe.xadd(self.stream_key, env.to_stream_dict())
                return pipe.execute()
            redis_ids = await asyncio.to_thread(_sync_pipe)

        accepted_ids = [e.event_id for e in validated_envelopes]
        return {
            "status": "accepted",
            "accepted_count": len(accepted_ids),
            "event_ids": accepted_ids,
            "first_stream_id": str(redis_ids[0]) if redis_ids else None,
            "last_stream_id": str(redis_ids[-1]) if redis_ids else None,
        }

    def ingest_batch(
        self,
        events: List[Dict[str, Any]],
        raw_bytes: Optional[bytes] = None,
        signature: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous batch ingestion method for backwards compatibility with tests.
        """
        if not events:
            return {"status": "accepted", "accepted_count": 0, "event_ids": []}

        if len(events) > self.max_batch_size:
            raise ValueError(f"Batch size {len(events)} exceeds maximum allowed {self.max_batch_size}")

        body_bytes = raw_bytes or json.dumps(events, sort_keys=True).encode("utf-8")
        self.authenticate_request(body_bytes, signature, timestamp)

        validated_envelopes: List[EventEnvelope] = []
        for item in events:
            clean_item = {k: v for k, v in item.items() if k != "_origin_auth"}
            envelope = EventEnvelope.model_validate(clean_item)
            validated_envelopes.append(envelope)

        current_len = self.check_backpressure()
        if current_len + len(validated_envelopes) > self.max_stream_len:
            raise IngestionBackpressureError(current_len, self.max_stream_len)

        pipe = self.redis.pipeline()
        for env in validated_envelopes:
            pipe.xadd(self.stream_key, env.to_stream_dict())
        redis_ids = pipe.execute()

        accepted_ids = [e.event_id for e in validated_envelopes]
        return {
            "status": "accepted",
            "accepted_count": len(accepted_ids),
            "event_ids": accepted_ids,
            "first_stream_id": str(redis_ids[0]) if redis_ids else None,
            "last_stream_id": str(redis_ids[-1]) if redis_ids else None,
        }
