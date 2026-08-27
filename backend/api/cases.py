import logging
from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import InvestigationCase, CaseEvidence, IOC
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime

logger = logging.getLogger("api.cases")
router = APIRouter(prefix="/api/v1/cases", tags=["Case Management"])

VALID_PRIORITIES = {"Low", "Medium", "High", "Critical"}
VALID_STATUSES = {"Open", "In Progress", "Closed"}


class EvidenceCreate(BaseModel):
    event_id: int = Field(..., ge=1)
    event_type: str = Field(..., min_length=1, max_length=50)
    notes: Optional[str] = Field(None, max_length=2000)


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., max_length=5000)
    priority: str = "Medium"
    assigned_to: Optional[str] = Field(None, max_length=100)

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        v_title = v.strip().title()
        if v_title not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{v}'. Allowed: {', '.join(sorted(VALID_PRIORITIES))}")
        return v_title


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = Field(None, max_length=100)

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v_title = v.strip().title()
            if v_title not in VALID_PRIORITIES:
                raise ValueError(f"Invalid priority '{v}'. Allowed: {', '.join(sorted(VALID_PRIORITIES))}")
            return v_title
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v_title = v.strip().title()
            if v_title not in VALID_STATUSES:
                raise ValueError(f"Invalid status '{v}'. Allowed: {', '.join(sorted(VALID_STATUSES))}")
            return v_title
        return v


class CaseResponse(BaseModel):
    id: int
    title: str
    description: str
    status: str
    priority: str
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=List[CaseResponse])
def get_cases(db: Session = Depends(get_db)):
    return db.query(InvestigationCase).order_by(InvestigationCase.created_at.desc()).all()


@router.post("/", response_model=CaseResponse)
def create_case(case_data: CaseCreate, db: Session = Depends(get_db)):
    try:
        data = case_data.dict()
        db_case = InvestigationCase(**data)
        db.add(db_case)
        db.commit()
        db.refresh(db_case)
        return db_case
    except Exception as e:
        db.rollback()
        logger.error("Error creating case: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create investigation case.")


@router.get("/{case_id}", response_model=CaseResponse)
def get_case_details(
    case_id: int = Path(..., ge=1, description="Case database ID"),
    db: Session = Depends(get_db)
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")
    return db_case


@router.put("/{case_id}", response_model=CaseResponse)
def update_case(
    case_id: int = Path(..., ge=1, description="Case database ID"),
    updates: CaseUpdate = ...,
    db: Session = Depends(get_db)
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        for key, value in updates.dict(exclude_unset=True).items():
            setattr(db_case, key, value)

        if updates.status == "Closed":
            db_case.closed_at = datetime.utcnow()

        db_case.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(db_case)
        return db_case
    except Exception as e:
        db.rollback()
        logger.error("Error updating case %d: %s", case_id, e)
        raise HTTPException(status_code=500, detail="Failed to update investigation case.")


@router.post("/{case_id}/evidence")
def add_evidence(
    case_id: int = Path(..., ge=1, description="Case database ID"),
    evidence: EvidenceCreate = ...,
    db: Session = Depends(get_db)
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        db_evidence = CaseEvidence(case_id=case_id, **evidence.dict())
        db.add(db_evidence)
        db.commit()
        return {"status": "success", "message": "Evidence added successfully"}
    except Exception as e:
        db.rollback()
        logger.error("Error adding evidence to case %d: %s", case_id, e)
        raise HTTPException(status_code=500, detail="Failed to attach evidence to case.")
