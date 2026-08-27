import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import SearchHistory
from services.hunting_service import HuntingService
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Any

logger = logging.getLogger("api.hunting")
router = APIRouter(prefix="/api/v1/hunting", tags=["Threat Hunting"])

VALID_LOGIC = {"AND", "OR", "NOT"}
VALID_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "starts_with",
    "greater_than",
    "less_than",
    "between",
    "in_list",
}


class QueryCondition(BaseModel):
    field: str = Field(..., min_length=1, max_length=50)
    operator: str = Field(...)
    value: Any

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if v_clean not in VALID_OPERATORS:
            raise ValueError(f"Invalid operator '{v}'. Allowed: {', '.join(sorted(VALID_OPERATORS))}")
        return v_clean


class AdvancedQuery(BaseModel):
    logic: str = "AND"
    conditions: List[QueryCondition] = Field(default=[], max_length=50)
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        v_clean = v.strip().upper()
        if v_clean not in VALID_LOGIC:
            raise ValueError(f"Invalid logic '{v}'. Allowed: {', '.join(sorted(VALID_LOGIC))}")
        return v_clean


class TextPayload(BaseModel):
    text: str = Field(..., max_length=500_000, description="Raw log or text payload")


class IOCOutput(BaseModel):
    type: str
    value: str


@router.post("/search")
def search_events(query: AdvancedQuery, db: Session = Depends(get_db)):
    try:
        service = HuntingService(db)
        return service.search_events(query.dict())
    except Exception as e:
        logger.error("Error executing threat hunting search: %s", e)
        raise HTTPException(status_code=500, detail="Failed to execute search query.")


@router.post("/extract-iocs", response_model=List[IOCOutput])
def extract_iocs(payload: TextPayload, db: Session = Depends(get_db)):
    try:
        service = HuntingService(db)
        return service.extract_iocs(payload.text)
    except Exception as e:
        logger.error("Error extracting IOCs: %s", e)
        raise HTTPException(status_code=500, detail="Failed to extract IOCs from payload.")


@router.get("/related-events")
def get_related_events(
    ip: Optional[str] = Query(None, max_length=50),
    honeypot: Optional[str] = Query(None, max_length=50),
    window: Optional[int] = Query(1440, ge=1, le=43200),
    db: Session = Depends(get_db),
):
    try:
        service = HuntingService(db)
        return service.get_related_events(ip, honeypot, window)
    except Exception as e:
        logger.error("Error retrieving related events: %s", e)
        raise HTTPException(status_code=500, detail="Failed to retrieve related events.")


@router.get("/history")
def get_search_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    return (
        db.query(SearchHistory)
        .order_by(SearchHistory.executed_at.desc())
        .limit(limit)
        .all()
    )


@router.post("/analyze-patterns")
def analyze_patterns(payload: TextPayload, db: Session = Depends(get_db)):
    try:
        service = HuntingService(db)
        return service.detect_malicious_patterns(payload.text)
    except Exception as e:
        logger.error("Error analyzing attack patterns: %s", e)
        raise HTTPException(status_code=500, detail="Failed to analyze attack patterns.")


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
                },
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
