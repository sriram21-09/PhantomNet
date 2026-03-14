from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import InvestigationCase, CaseEvidence, IOC
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter(prefix="/api/v1/cases", tags=["Case Management"])


class EvidenceCreate(BaseModel):
    event_id: int
    event_type: str
    notes: Optional[str] = None


class CaseCreate(BaseModel):
    title: str
    description: str
    priority: str = "Medium"
    assigned_to: Optional[str] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None


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
    return db.query(InvestigationCase).all()


@router.post("/", response_model=CaseResponse)
def create_case(case_data: CaseCreate, db: Session = Depends(get_db)):
    db_case = InvestigationCase(**case_data.dict())
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    return db_case


@router.get("/{case_id}", response_model=CaseResponse)
def get_case_details(case_id: int, db: Session = Depends(get_db)):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")
    return db_case


@router.put("/{case_id}", response_model=CaseResponse)
def update_case(case_id: int, updates: CaseUpdate, db: Session = Depends(get_db)):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    for key, value in updates.dict(exclude_unset=True).items():
        setattr(db_case, key, value)

    if updates.status == "Closed":
        db_case.closed_at = datetime.utcnow()

    db.commit()
    db.refresh(db_case)
    return db_case


@router.post("/{case_id}/evidence")
def add_evidence(case_id: int, evidence: EvidenceCreate, db: Session = Depends(get_db)):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    db_evidence = CaseEvidence(case_id=case_id, **evidence.dict())
    db.add(db_evidence)
    db.commit()
    return {"message": "Evidence added successfully"}
