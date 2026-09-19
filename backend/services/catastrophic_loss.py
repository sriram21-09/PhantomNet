"""
Catastrophic Loss Journaling Engine (DUR-06)
Provides emergency, fail-safe, append-only logging when both Ingestion Gateway and
Local Disk Spool buffers are completely exhausted or failing.
Guarantees ZERO silent event drops.
"""
import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger("PhantomNet.CatastrophicLoss")

DEFAULT_CATASTROPHIC_LOG_PATH = os.getenv(
    "CATASTROPHIC_LOSS_LOG_PATH",
    os.path.join(os.path.dirname(__file__), "..", "logs", "catastrophic_loss.log"),
)

# In-memory counter for real-time observability
_catastrophic_loss_counter = 0


def get_catastrophic_loss_count() -> int:
    global _catastrophic_loss_counter
    return _catastrophic_loss_counter


def reset_catastrophic_loss_count():
    global _catastrophic_loss_counter
    _catastrophic_loss_counter = 0


class CatastrophicLossJournal:
    """
    Emergency append-only loss journal with sync-to-disk and syslog integration.
    """
    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or DEFAULT_CATASTROPHIC_LOG_PATH
        log_dir = os.path.dirname(os.path.abspath(self.log_path))
        os.makedirs(log_dir, exist_ok=True)

    def record_catastrophic_drop(
        self,
        event_dict: Dict[str, Any],
        reason: str,
        buffer_depth: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Appends an emergency journal entry to catastrophic_loss.log with fsync.
        Guarantees that no event is ever discarded silently.
        """
        global _catastrophic_loss_counter
        _catastrophic_loss_counter += 1

        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "drop_counter": _catastrophic_loss_counter,
            "reason": reason,
            "buffer_depth": buffer_depth,
            "event_id": event_dict.get("event_id", "unknown"),
            "honeypot_id": event_dict.get("honeypot_id", "unknown"),
            "event_type": event_dict.get("event_type", "unknown"),
            "src_ip": event_dict.get("src_ip", "unknown"),
            "canonical_fingerprint": event_dict.get("canonical_fingerprint"),
            "raw_summary": str(event_dict)[:512],
        }

        entry_line = json.dumps(record, separators=(',', ':')) + "\n"

        # 1. Append to emergency disk journal with mandatory fsync
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry_line)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            sys.stderr.write(f"[FATAL CATASTROPHIC LOSS FILE WRITE ERROR]: {e}\n")

        # 2. Emit emergency alert to stderr / host syslog
        sys.stderr.write(
            f"[EMERGENCY-CATASTROPHIC-LOSS] Drop #{_catastrophic_loss_counter} | "
            f"Event {record['event_id']} | Reason: {reason} | Buffer: {buffer_depth}\n"
        )
        logger.critical(
            f"CRITICAL CATASTROPHIC EVENT DROP: id={record['event_id']} "
            f"type={record['event_type']} reason={reason}"
        )

        return record

    def read_journal_records(self) -> list[Dict[str, Any]]:
        """Reads all catastrophic loss journal entries."""
        if not os.path.exists(self.log_path):
            return []
        records = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
        return records


# Global default instance
catastrophic_journal = CatastrophicLossJournal()
