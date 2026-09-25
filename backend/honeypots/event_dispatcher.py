"""
Honeypot Event Dispatcher & Resilience Client
Prepares signed canonical EventEnvelopes and dispatches to Ingestion Gateway.
Automatically falls back to local disk spooling if Gateway is unreachable or backpressured.
Ensures honeypot containers have zero direct PostgreSQL access.
"""
import os
import sys
import time
import json
import logging
from typing import Dict, Any, Optional
import requests

from schemas.event_envelope import EventEnvelope, generate_uuidv7
from services.origin_auth import sign_event_dict, get_honeypot_secret_key
from honeypots.spooler import default_spooler, DiskSpooler

logger = logging.getLogger("PhantomNet.EventDispatcher")


class EventDispatcher:
    """
    Client-side event dispatcher for honeypot services.
    """
    def __init__(
        self,
        gateway_url: Optional[str] = None,
        honeypot_id: Optional[str] = None,
        spooler: Optional[DiskSpooler] = None,
        timeout_seconds: float = 2.0,
    ):
        self.gateway_url = gateway_url or os.getenv("INGESTION_GATEWAY_URL")
        self.honeypot_id = honeypot_id or os.getenv("HONEYPOT_ID", "honeypot-node-01")
        self.spooler = spooler or default_spooler
        self.timeout = timeout_seconds

    def dispatch(
        self,
        protocol: str,
        src_ip: str,
        event_type: str = "activity",
        dst_ip: str = "127.0.0.1",
        src_port: int = 0,
        dst_port: int = 0,
        length: int = 0,
        is_malicious: bool = False,
        threat_score: float = 0.0,
        threat_level: Optional[str] = None,
        attack_type: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Constructs a signed EventEnvelope and transmits to Gateway.
        Falls back to local disk spool on Gateway connection errors or HTTP 429/503.
        """
        # 1. Build envelope
        envelope = EventEnvelope(
            event_id=generate_uuidv7(),
            timestamp_ns=time.time_ns(),
            honeypot_id=self.honeypot_id,
            event_type=event_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol.upper(),
            length=length,
            is_malicious=is_malicious,
            threat_score=threat_score,
            threat_level=threat_level,
            attack_type=attack_type or event_type.upper(),
            payload=payload or {},
        )

        # 2. Sign event dictionary
        raw_dict = envelope.model_dump()
        signed_dict = sign_event_dict(raw_dict, secret_key=get_honeypot_secret_key())

        # 3. If gateway URL is configured, attempt HTTP delivery
        if self.gateway_url:
            try:
                origin_auth = signed_dict.get("_origin_auth", {})
                headers = {
                    "Content-Type": "application/json",
                    "X-Honeypot-Signature": origin_auth.get("signature", ""),
                    "X-Honeypot-Timestamp": str(origin_auth.get("timestamp", "")),
                    "X-Honeypot-ID": self.honeypot_id,
                }
                
                resp = requests.post(
                    self.gateway_url,
                    json=signed_dict,
                    headers=headers,
                    timeout=self.timeout,
                )

                if resp.status_code in (200, 202):
                    logger.debug(f"Event {envelope.event_id} delivered to Gateway successfully.")
                    # Trigger opportunistic spool drain if pending
                    if self.spooler.has_pending_events():
                        self.drain_spool()
                    return True
                else:
                    logger.warning(
                        f"Gateway returned status {resp.status_code}: {resp.text}. Spooling locally."
                    )
            except Exception as e:
                logger.warning(f"Gateway connection error ({e}). Spooling to disk.")

        # 4. Fallback: buffer to local disk spool
        spooled = self.spooler.write_event(signed_dict)
        return spooled

    def drain_spool(self, batch_size: int = 100) -> int:
        """
        Drains pending events from the local disk spool to the Gateway batch endpoint.
        """
        if not self.gateway_url:
            return 0

        batch_url = self.gateway_url.replace("/event", "/batch")

        def _send_batch(batch: list) -> bool:
            try:
                now = int(time.time())
                payload_bytes = json.dumps(batch, sort_keys=True).encode("utf-8")
                from services.origin_auth import generate_origin_signature, get_honeypot_secret_key
                sig = generate_origin_signature(payload_bytes, now, get_honeypot_secret_key())
                headers = {
                    "Content-Type": "application/json",
                    "X-Honeypot-Signature": sig,
                    "X-Honeypot-Timestamp": str(now),
                    "X-Honeypot-ID": self.honeypot_id,
                }
                resp = requests.post(
                    batch_url,
                    data=payload_bytes,
                    headers=headers,
                    timeout=self.timeout * 3,
                )
                return resp.status_code in (200, 202)
            except Exception:
                return False

        return self.spooler.drain(_send_batch, batch_size=batch_size)


# Global default dispatcher instance
default_dispatcher = EventDispatcher()
