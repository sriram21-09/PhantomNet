import logging
from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import InvestigationCase, CaseEvidence, IOC, User, PacketLog
from middleware.auth import get_current_user, require_role
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import List, Optional
from datetime import datetime, timezone

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
            clean = v.strip().lower().replace("_", " ").replace("-", " ")
            if clean in {"in progress", "inprogress"}:
                v_title = "In Progress"
            else:
                v_title = clean.title()
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
    closed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AssigneeResponse(BaseModel):
    id: int
    username: str
    role: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class NoteCreate(BaseModel):
    notes: str = Field(..., min_length=1, max_length=2000)


class EvidenceResponse(BaseModel):
    id: int
    case_id: int
    event_id: Optional[int] = None
    event_type: str
    notes: Optional[str] = None
    added_at: datetime
    event_details: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)


@router.get("/assignees", response_model=List[AssigneeResponse])
def get_eligible_assignees(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return (
        db.query(User)
        .filter(User.status == "active", User.role.in_(["Admin", "Analyst"]))
        .order_by(User.username.asc())
        .all()
    )


@router.get("/", response_model=List[CaseResponse])
def get_cases(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return db.query(InvestigationCase).order_by(InvestigationCase.created_at.desc()).all()


@router.post("/", response_model=CaseResponse)
def create_case(
    case_data: CaseCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    try:
        data = case_data.model_dump()
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
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
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
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        for key, value in updates.model_dump(exclude_unset=True).items():
            setattr(db_case, key, value)

        if updates.status == "Closed":
            db_case.closed_at = datetime.now(timezone.utc)

        db_case.updated_at = datetime.now(timezone.utc)
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
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        db_evidence = CaseEvidence(case_id=case_id, **evidence.model_dump())
        db.add(db_evidence)
        db.commit()
        return {"status": "success", "message": "Evidence added successfully"}
    except Exception as e:
        db.rollback()
        logger.error("Error adding evidence to case %d: %s", case_id, e)
        raise HTTPException(status_code=500, detail="Failed to attach evidence to case.")


@router.get("/{case_id}/evidence", response_model=List[EvidenceResponse])
def get_case_evidence(
    case_id: int = Path(..., ge=1, description="Case database ID"),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_items = (
        db.query(CaseEvidence)
        .filter(CaseEvidence.case_id == case_id)
        .order_by(CaseEvidence.added_at.desc())
        .all()
    )

    # Batch lookup packet logs for efficiency
    packet_ids = [e.event_id for e in evidence_items if e.event_id and e.event_type == "packet_log"]
    packets_by_id = {}
    if packet_ids:
        packets = db.query(PacketLog).filter(PacketLog.id.in_(packet_ids)).all()
        for p in packets:
            packets_by_id[p.id] = {
                "id": p.id,
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "protocol": p.protocol,
                "threat_score": p.threat_score,
                "threat_level": p.threat_level,
                "attack_type": p.attack_type,
                "is_malicious": p.is_malicious,
            }

    results = []
    for e in evidence_items:
        details = packets_by_id.get(e.event_id) if e.event_id else None
        results.append(
            EvidenceResponse(
                id=e.id,
                case_id=e.case_id,
                event_id=e.event_id,
                event_type=e.event_type,
                notes=e.notes,
                added_at=e.added_at,
                event_details=details,
            )
        )
    return results


@router.delete("/{case_id}/evidence/{evidence_id}")
def delete_case_evidence(
    case_id: int = Path(..., ge=1),
    evidence_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    ev = (
        db.query(CaseEvidence)
        .filter(CaseEvidence.id == evidence_id, CaseEvidence.case_id == case_id)
        .first()
    )
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    try:
        db.delete(ev)
        db.commit()
        return {"status": "success", "message": "Evidence removed successfully"}
    except Exception as e:
        db.rollback()
        logger.error("Error removing evidence %d: %s", evidence_id, e)
        raise HTTPException(status_code=500, detail="Failed to remove evidence.")


@router.post("/{case_id}/notes")
def add_case_note(
    case_id: int = Path(..., ge=1),
    payload: NoteCreate = ...,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        author = getattr(_user, "username", "Analyst")
        annotated_note = f"[{author}] {payload.notes.strip()}"
        evidence = CaseEvidence(
            case_id=case_id,
            event_id=None,
            event_type="note",
            notes=annotated_note,
        )
        db.add(evidence)
        db_case.updated_at = datetime.now(timezone.utc)
        db.commit()
        return {"status": "success", "message": "Note added to case successfully"}
    except Exception as e:
        db.rollback()
        logger.error("Error adding note to case %d: %s", case_id, e)
        raise HTTPException(status_code=500, detail="Failed to add note to case.")


@router.delete("/{case_id}")
def delete_case(
    case_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    db_case = (
        db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    )
    if not db_case:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        db.delete(db_case)
        db.commit()
        return {"status": "success", "message": f"Case #{case_id} deleted successfully"}
    except Exception as e:
        db.rollback()
        logger.error("Error deleting case %d: %s", case_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete case.")
