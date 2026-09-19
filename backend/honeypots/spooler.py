"""
Honeypot Local Disk Spooler & Outage Resilience Buffer (DUR-05 & DUR-06)
Buffers events to an append-only, fsynced write-ahead log (WAL) on the honeypot node
whenever the Ingestion Gateway is unreachable, backpressured, or failing.
Drains automatically once Gateway connectivity is restored.
Enforces strict 1 GB spool ceiling with Catastrophic Loss Journaling on overflow.
"""
import os
import sys
import glob
import json
import logging
import time
from typing import Dict, Any, List, Optional, Callable

from services.catastrophic_loss import catastrophic_journal

logger = logging.getLogger("PhantomNet.DiskSpooler")

DEFAULT_SPOOL_DIR = os.getenv(
    "HONEYPOT_SPOOL_DIR",
    os.path.join(os.path.dirname(__file__), "..", "data", "spool"),
)
DEFAULT_MAX_SPOOL_BYTES = 1024 * 1024 * 1024  # 1 GB (DUR-05)


class DiskSpooler:
    """
    Append-only local disk buffer with durability fsync and automatic recovery draining.
    """
    def __init__(
        self,
        spool_dir: Optional[str] = None,
        max_spool_bytes: int = DEFAULT_MAX_SPOOL_BYTES,
    ):
        self.spool_dir = spool_dir or DEFAULT_SPOOL_DIR
        self.max_spool_bytes = max_spool_bytes
        os.makedirs(self.spool_dir, exist_ok=True)

    def _get_active_wal_path(self) -> str:
        """Returns the current active WAL file path (bucketed hourly)."""
        time_slot = time.strftime("%Y%m%d_%H")
        return os.path.join(self.spool_dir, f"spool_{time_slot}.wal")

    def get_total_spool_size(self) -> int:
        """Calculates total disk usage of all .wal files in the spool directory."""
        total_size = 0
        for fpath in glob.glob(os.path.join(self.spool_dir, "*.wal")):
            try:
                total_size += os.path.getsize(fpath)
            except OSError:
                pass
        return total_size

    def has_pending_events(self) -> bool:
        """Checks whether any spool files exist with buffered events."""
        files = glob.glob(os.path.join(self.spool_dir, "*.wal"))
        return any(os.path.getsize(f) > 0 for f in files if os.path.exists(f))

    def write_event(self, event_dict: Dict[str, Any]) -> bool:
        """
        Appends an event to the local disk WAL with immediate fsync.
        If spool capacity (1 GB) would be exceeded, records a catastrophic loss entry.
        Returns True if safely spooled, False if dropped due to capacity overflow.
        """
        line_bytes = (json.dumps(event_dict, separators=(',', ':')) + "\n").encode("utf-8")
        entry_size = len(line_bytes)

        current_size = self.get_total_spool_size()
        if current_size + entry_size > self.max_spool_bytes:
            # Sized 1 GB spool ceiling exceeded! Trigger catastrophic loss journaling
            catastrophic_journal.record_catastrophic_drop(
                event_dict=event_dict,
                reason="SPOOL_CAPACITY_EXCEEDED_1GB",
                buffer_depth=current_size,
            )
            return False

        wal_path = self._get_active_wal_path()
        try:
            with open(wal_path, "ab") as f:
                f.write(line_bytes)
                f.flush()
                os.fsync(f.fileno())
            logger.debug(f"Event {event_dict.get('event_id')} safely written to disk spool {wal_path}")
            return True
        except Exception as e:
            logger.critical(f"Disk spool write failure: {e}")
            catastrophic_journal.record_catastrophic_drop(
                event_dict=event_dict,
                reason=f"SPOOL_DISK_IO_ERROR: {e}",
                buffer_depth=current_size,
            )
            return False

    def drain(
        self,
        ingest_callback: Callable[[List[Dict[str, Any]]], bool],
        batch_size: int = 100,
    ) -> int:
        """
        Reads pending spool files in chronological order, delivers batches via callback,
        and atomically deletes completed WAL files upon confirmed delivery.
        Returns total number of events drained.
        """
        wal_files = sorted(glob.glob(os.path.join(self.spool_dir, "*.wal")))
        total_drained = 0

        for wal_file in wal_files:
            if not os.path.exists(wal_file) or os.path.getsize(wal_file) == 0:
                continue

            events_in_file = []
            with open(wal_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events_in_file.append(json.loads(line))
                        except Exception:
                            pass

            if not events_in_file:
                try:
                    os.remove(wal_file)
                except OSError:
                    pass
                continue

            # Process in batches
            all_succeeded = True
            for i in range(0, len(events_in_file), batch_size):
                batch = events_in_file[i:i + batch_size]
                try:
                    ok = ingest_callback(batch)
                    if ok:
                        total_drained += len(batch)
                    else:
                        all_succeeded = False
                        break
                except Exception as e:
                    logger.warning(f"Error during spool drain callback: {e}")
                    all_succeeded = False
                    break

            # If entire file was successfully posted to gateway, safely delete it
            if all_succeeded:
                try:
                    os.remove(wal_file)
                except OSError:
                    pass
            else:
                # Stop draining further files until gateway connection recovers
                break

        return total_drained


# Global default spooler instance
default_spooler = DiskSpooler()
