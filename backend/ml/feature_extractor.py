from sqlalchemy.orm import Session
from database.models import Event, AttackSession
from datetime import datetime

class FeatureExtractor:
    def __init__(self, db_session: Session):
        self.db = db_session

    def extract_features(self, session_id: int):
        session = self.db.query(AttackSession).filter(AttackSession.id == session_id).first()
        events = self.db.query(Event).filter(Event.session_id == session_id).all()
        
        if not session or not events:
            return {"duration_seconds": 0, "event_count": 0, "unique_ports": 0, "events_per_second": 0}

        start_time = events[-1].timestamp 
        end_time = events[0].timestamp
        duration = (end_time - start_time).total_seconds()
        
        if duration <= 0: duration = 1.0

        unique_ports = len(set(e.src_port for e in events))
        event_count = len(events)
        eps = event_count / duration

        return {
            "duration_seconds": duration,
            "event_count": event_count,
            "unique_ports": unique_ports,
            "events_per_second": eps
        }
