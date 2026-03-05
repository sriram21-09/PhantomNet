import json
import time
import logging
from typing import List, Any
import requests

from services.universal_siem_exporter import SIEMExporter, item_to_json

logger = logging.getLogger("splunk_exporter")

# =======================================================================
# Splunk HEC Client
# =======================================================================
class SplunkHECClient:
    """
    Client for interacting with Splunk HTTP Event Collector (HEC).
    Features:
    - Connection pooling via requests.Session
    - Batch event sending
    """
    def __init__(self, url: str, token: str, max_retries: int = 3, retry_delay: float = 2.0):
        self.url = url
        self.token = token
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json"
        })

    def send_batch(self, events: List[dict]) -> bool:
        """
        Sends a batch of events to Splunk HEC.
        The /services/collector/event endpoint expects a concatenated list of JSON objects
        or a single JSON payload with multiple `event` blocks if broken up.
        Actually, standard Splunk HEC format requires each event to be a separate JSON object:
        {"time": 123, "host": "...", "source": "...", "sourcetype": "...", "event": {...}}
        """
        if not events:
            return True

        # HEC accepts newline-delimited JSON objects for batches
        # Format: {"event": <data>, "sourcetype": <type>, ...}
        payload = ""
        for ev in events:
            payload += json.dumps(ev) + "\n"

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.post(self.url, data=payload, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("text") == "Success":
                        logger.info(f"✅ Shipped batch of {len(events)} events to Splunk")
                        return True
                    else:
                        logger.warning(f"⚠️ Splunk HEC returned success code but text: {data.get('text')}")
                else:
                    logger.warning(
                        f"⚠️ Splunk HEC returned HTTP {resp.status_code}: {resp.text} "
                        f"(attempt {attempt}/{self.max_retries})"
                    )
            except requests.exceptions.RequestException as e:
                logger.error(
                    f"❌ Network error while sending to Splunk HEC: {e} "
                    f"(attempt {attempt}/{self.max_retries})"
                )

            if attempt < self.max_retries:
                time.sleep(self.retry_delay * attempt)

        logger.error(f"🔥 Failed to ship batch to Splunk after {self.max_retries} attempts.")
        return False


# =======================================================================
# Splunk Exporter implementation
# =======================================================================
class SplunkExporter(SIEMExporter):
    """
    Splunk implementation of the SIEMExporter.
    Formats logs and uses SplunkHECClient to ship them.
    """
    def __init__(self, hec_url: str, hec_token: str):
        self.client = SplunkHECClient(
            url=hec_url,
            token=hec_token
        )

    def export_events(self, items: List[Any], event_type: str) -> bool:
        if not items:
            return True

        # Transform database objects to base JSON dictionaries
        raw_events = [item_to_json(item, event_type) for item in items]

        # Format events specifically for Splunk HEC schema
        splunk_events = []
        for raw in raw_events:
            # Extract timestamp and other metadata
            timestamp_str = raw.get("timestamp")
            
            # Splunk expects 'time' field as epoch seconds. Attempt to parse if string.
            epoch_time = time.time()
            if timestamp_str and isinstance(timestamp_str, str):
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    epoch_time = dt.timestamp()
                except ValueError:
                    pass

            splunk_events.append({
                "time": epoch_time,
                "host": "phantomnet_ids",
                "source": "phantomnet_honeypot",
                "sourcetype": "phantomnet:event",
                "event": raw
            })

        return self.client.send_batch(splunk_events)

