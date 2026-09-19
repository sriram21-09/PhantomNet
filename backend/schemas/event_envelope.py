"""
Event Envelope Schema & RFC 9562 UUIDv7 Generator
Defines the canonical, time-ordered, tamper-evident data structure for all
ingested security events across PhantomNet V3.
"""
import time
import uuid
import secrets
import hashlib
import json
import ipaddress
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


def generate_uuidv7() -> str:
    """
    Generates an RFC 9562 compliant UUIDv7.
    Layout:
      48 bits: Unix epoch timestamp in milliseconds
       4 bits: version 7 (0b0111)
      12 bits: rand_a (random bits / sub-ms entropy)
       2 bits: variant (0b10)
      62 bits: rand_b (random entropy)
    """
    unix_ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    uuid_int = (
        (unix_ts_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (0x2 << 62)
        | rand_b
    )
    return str(uuid.UUID(int=uuid_int))


def compute_canonical_fingerprint(
    honeypot_id: str,
    event_type: str,
    src_ip: str,
    dst_port: int,
    protocol: str,
    payload: Dict[str, Any],
    timestamp_ns: int,
    window_seconds: int = 10,
) -> str:
    """
    Computes a canonical SHA-256 fingerprint for sliding-window deduplication.
    Events with matching origin, source IP, target port, protocol, coarse payload digest,
    and falling within the same time window share the same fingerprint.
    """
    time_window_bucket = int(timestamp_ns // (window_seconds * 1_000_000_000))
    
    # Deterministic payload representation
    payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()[:16]

    canonical_data = {
        "honeypot_id": str(honeypot_id).strip().lower(),
        "event_type": str(event_type).strip().upper(),
        "src_ip": str(src_ip).strip(),
        "dst_port": int(dst_port),
        "protocol": str(protocol).strip().upper(),
        "payload_hash": payload_hash,
        "window": time_window_bucket,
    }
    
    canonical_bytes = json.dumps(canonical_data, sort_keys=True, separators=(',', ':')).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


class EventEnvelope(BaseModel):
    """
    Strict canonical event envelope for at-least-once, idempotent ingestion.
    """
    event_id: str = Field(default_factory=generate_uuidv7, description="RFC 9562 UUIDv7")
    timestamp_ns: int = Field(default_factory=time.time_ns, description="Ingestion nanosecond epoch")
    honeypot_id: str = Field(..., min_length=1, max_length=64)
    verified_source_id: Optional[str] = Field(None, max_length=64)
    event_type: str = Field(..., min_length=1, max_length=64)
    src_ip: str = Field(..., description="Attacker IPv4 or IPv6 address")
    dst_ip: str = Field(default="127.0.0.1", description="Target destination IP")
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    protocol: str = Field(default="TCP", max_length=16)
    length: int = Field(default=0, ge=0)
    is_malicious: bool = False
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    threat_level: Optional[str] = None
    attack_type: Optional[str] = None
    canonical_fingerprint: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    signature: Optional[str] = None
    origin_timestamp: Optional[int] = None

    @field_validator("event_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        try:
            val = uuid.UUID(v)
            return str(val)
        except Exception:
            raise ValueError(f"Invalid UUID string format: {v}")

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

    @model_validator(mode="after")
    def populate_canonical_fingerprint(self) -> "EventEnvelope":
        if not self.canonical_fingerprint:
            self.canonical_fingerprint = compute_canonical_fingerprint(
                honeypot_id=self.honeypot_id,
                event_type=self.event_type,
                src_ip=self.src_ip,
                dst_port=self.dst_port,
                protocol=self.protocol,
                payload=self.payload,
                timestamp_ns=self.timestamp_ns,
            )
        return self

    def to_stream_dict(self) -> Dict[str, str]:
        """
        Serializes envelope to a flat Redis Stream dictionary (field: str -> value: str).
        """
        return {
            "event_id": self.event_id,
            "timestamp_ns": str(self.timestamp_ns),
            "honeypot_id": self.honeypot_id,
            "canonical_fingerprint": self.canonical_fingerprint or "",
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "dst_port": str(self.dst_port),
            "protocol": self.protocol,
            "raw_json": self.model_dump_json(),
        }

    @classmethod
    def from_stream_dict(cls, stream_data: Dict[str, Any]) -> "EventEnvelope":
        """
        Reconstitutes an EventEnvelope from a Redis Stream entry.
        """
        # Redis returns bytes or strings depending on decode_responses
        decoded = {}
        for k, v in stream_data.items():
            key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8") if isinstance(v, bytes) else str(v)
            decoded[key] = val

        if "raw_json" in decoded:
            return cls.model_validate_json(decoded["raw_json"])
        
        # Fallback if raw_json missing
        return cls(
            event_id=decoded.get("event_id", generate_uuidv7()),
            timestamp_ns=int(decoded.get("timestamp_ns", time.time_ns())),
            honeypot_id=decoded.get("honeypot_id", "unknown"),
            canonical_fingerprint=decoded.get("canonical_fingerprint"),
            event_type=decoded.get("event_type", "activity"),
            src_ip=decoded.get("src_ip", "127.0.0.1"),
            dst_port=int(decoded.get("dst_port", 0)),
            protocol=decoded.get("protocol", "TCP"),
        )
