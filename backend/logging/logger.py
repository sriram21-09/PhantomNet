import json
import logging
import os
import atexit
from datetime import datetime, timezone
from queue import Queue
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener

# ==================================================
# CONFIG
# ==================================================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "phantomnet.log")

MAX_LOG_SIZE = 5 * 1024 * 1024   # 5 MB
BACKUP_COUNT = 5

# ==================================================
# JSON FORMATTER
# ==================================================
class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "honeypot_type": getattr(record, "honeypot_type", "unknown"),
            "source_ip": getattr(record, "source_ip", None),
            "event": getattr(record, "event", record.getMessage()),
            "data": getattr(record, "data", None),
        })

# ==================================================
# ASYNC LOGGING QUEUE
# ==================================================
log_queue = Queue(-1)

# ==================================================
# FILE HANDLER (ROTATION)
# ==================================================
file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=MAX_LOG_SIZE,
    backupCount=BACKUP_COUNT,
    encoding="utf-8"
)
file_handler.setFormatter(JSONFormatter())

# ==================================================
# QUEUE HANDLER (NON-BLOCKING)
# ==================================================
queue_handler = QueueHandler(log_queue)

logger = logging.getLogger("phantomnet")
logger.setLevel(logging.INFO)
logger.addHandler(queue_handler)
logger.propagate = False

# ==================================================
# QUEUE LISTENER (BACKGROUND THREAD)
# ==================================================
listener = QueueListener(log_queue, file_handler)
listener.start()

# ==================================================
# SAFE SHUTDOWN (CRITICAL FIX)
# ==================================================
@atexit.register
def shutdown_logger():
    """
    Ensures all queued logs are flushed before process exits.
    Fixes 'only few logs written' issue in short-lived scripts.
    """
    try:
        listener.stop()
    except Exception:
        pass

# ==================================================
# PUBLIC LOGGING FUNCTION (USE EVERYWHERE)
# ==================================================
def log_event(
    honeypot_type: str,
    event: str,
    level: str,
    source_ip: str = None,
    data: dict = None
):
    extra = {
        "honeypot_type": honeypot_type,
        "event": event,
        "source_ip": source_ip,
        "data": data,
    }

    level = level.upper()

    if level == "INFO":
        logger.info(event, extra=extra)
    elif level == "WARN":
        logger.warning(event, extra=extra)
    elif level == "ERROR":
        logger.error(event, extra=extra)
    else:
        logger.info(event, extra=extra)
