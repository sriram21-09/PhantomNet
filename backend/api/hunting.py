from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import SearchHistory
from services.hunting_service import HuntingService
from pydantic import BaseModel
from typing import List, Optional, Any

router = APIRouter(prefix="/api/v1/hunting", tags=["Threat Hunting"])


class QueryCondition(BaseModel):
    field: str
    operator: str
    value: Any


class AdvancedQuery(BaseModel):
    logic: str = "AND"
    conditions: List[QueryCondition]
    limit: int = 100
    offset: int = 0


class IOCOutput(BaseModel):
    type: str
    value: str


@router.post("/search")
def search_events(query: AdvancedQuery, db: Session = Depends(get_db)):
    service = HuntingService(db)
    return service.search_events(query.dict())


@router.post("/extract-iocs", response_model=List[IOCOutput])
def extract_iocs(payload: dict, db: Session = Depends(get_db)):
    text = payload.get("text", "")
    service = HuntingService(db)
    return service.extract_iocs(text)


@router.get("/related-events")
def get_related_events(
    ip: Optional[str] = None,
    honeypot: Optional[str] = None,
    window: Optional[int] = 1440,
    db: Session = Depends(get_db),
):
    service = HuntingService(db)
    return service.get_related_events(ip, honeypot, window)


@router.get("/history")
def get_search_history(db: Session = Depends(get_db)):
    return (
        db.query(SearchHistory)
        .order_by(SearchHistory.executed_at.desc())
        .limit(20)
        .all()
    )


@router.post("/analyze-patterns")
def analyze_patterns(payload: dict, db: Session = Depends(get_db)):
    text = payload.get("text", "")
    service = HuntingService(db)
    return service.detect_malicious_patterns(text)


@router.get("/templates")
def get_query_templates():
    return [
        {
            "name": "All HIGH threats in 24h",
            "logic": "AND",
            "conditions": [
                {"field": "threat_level", "operator": "equals", "value": "HIGH"},
                {
                    "field": "timestamp",
                    "operator": "greater_than",
                    "value": "24h_ago",
                },  # Note: simplified for example
            ],
        },
        {
            "name": "SSH brute force from China",
            "logic": "AND",
            "conditions": [
                {"field": "protocol", "operator": "equals", "value": "SSH"},
                {
                    "field": "attack_type",
                    "operator": "contains",
                    "value": "Brute Force",
                },
            ],
        },
    ]
