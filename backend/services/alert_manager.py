import logging
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from database.database import SessionLocal
from database.models import Alert

logger = logging.getLogger("alert_manager")


class AlertManager:
    def __init__(self, deduplication_window: int = 300):
        """
        :param deduplication_window: Time in seconds to ignore duplicate alerts (default 5 mins)
        """
        self.deduplication_window = deduplication_window
        self._last_alerts: Dict[str, datetime] = (
            {}
        )  # Key: "type:source_ip", Value: last_timestamp

    def create_alert(
        self,
        level: str,
        alert_type: str,
        description: str,
        source_ip: Optional[str] = None,
        details: Optional[Any] = None,
    ):
        """
        Creates and saves a security alert with deduplication logic.
        """
        if self._is_duplicate(alert_type, source_ip):
            logger.debug(f"Deduplicating alert: {alert_type} from {source_ip}")
            return None

        db: Session = SessionLocal()
        try:
            # Convert details to JSON string if it's a dict/list
            details_str = details
            if isinstance(details, (dict, list)):
                details_str = json.dumps(details)

            new_alert = Alert(
                level=level,
                type=alert_type,
                source_ip=source_ip,
                description=description,
                details=details_str,
                timestamp=datetime.utcnow(),
                is_resolved=False,
            )
            db.add(new_alert)
            db.commit()
            db.refresh(new_alert)

            # Update last alert cache
            self._update_cache(alert_type, source_ip)

            logger.info(
                f"🚨 ALERT [{level}] {alert_type}: {description} (IP: {source_ip})"
            )

            # TRIGGER AUTOMATED RESPONSE
            try:
                from .response_executor import response_executor

                response_executor.execute_response(
                    level, source_ip=source_ip, attack_type=alert_type
                )
            except Exception as e:
                logger.error(f"Failed to execute automated response: {e}")

            return new_alert
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            db.rollback()
            return None
        finally:
            db.close()

    def _is_duplicate(self, alert_type: str, source_ip: Optional[str]) -> bool:
        """
        Checks if a similar alert was recently sent.
        """
        if not source_ip:
            return False

        key = f"{alert_type}:{source_ip}"
        if key in self._last_alerts:
            last_time = self._last_alerts[key]
            if datetime.utcnow() - last_time < timedelta(
                seconds=self.deduplication_window
            ):
                return True
        return False

    def _update_cache(self, alert_type: str, source_ip: Optional[str]):
        """
        Updates the deduplication cache.
        """
        if source_ip:
            key = f"{alert_type}:{source_ip}"
            self._last_alerts[key] = datetime.utcnow()


# Singleton instance
alert_manager = AlertManager()
