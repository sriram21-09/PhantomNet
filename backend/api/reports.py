import logging
import re
from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import ScheduledReport
from services.report_service import ReportService
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime

logger = logging.getLogger("api.reports")
router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])

VALID_FREQUENCIES = {"daily", "weekly", "monthly"}
VALID_DAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}


class ScheduledReportCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    template_type: str = Field(..., min_length=1, max_length=100)
    frequency: str = Field(...)
    schedule_time: str = Field(..., min_length=1, max_length=10)
    recipients: str = Field(..., min_length=3, max_length=500)
    day_of_week: Optional[str] = "mon"
    filters: Optional[dict] = {}

    @field_validator("frequency")
    @classmethod
    def validate_frequency(cls, v: str) -> str:
        v_lower = v.strip().lower()
        if v_lower not in VALID_FREQUENCIES:
            raise ValueError(f"Invalid frequency '{v}'. Allowed: {', '.join(sorted(VALID_FREQUENCIES))}")
        return v_lower

    @field_validator("day_of_week")
    @classmethod
    def validate_day(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v_lower = v.strip().lower()
            if v_lower not in VALID_DAYS:
                raise ValueError(f"Invalid day_of_week '{v}'. Allowed: {', '.join(sorted(VALID_DAYS))}")
            return v_lower
        return v

    @field_validator("schedule_time")
    @classmethod
    def validate_time(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^([01]?[0-9]|2[0-3]):[0-5][0-9]$", v):
            raise ValueError(f"Invalid schedule_time format '{v}'. Expected HH:MM format.")
        return v


class ScheduledReportResponse(BaseModel):
    id: int
    name: str
    template_type: str
    frequency: str
    schedule_time: str
    recipients: str
    day_of_week: Optional[str]
    is_active: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]

    class Config:
        from_attributes = True


@router.get("/generate", response_model=dict)
def generate_report(
    template_type: str = "Executive Summary",
    date_range: str = "24h",
    honeypot: str = "ALL",
    threat_level: str = "ALL",
    protocol: str = "ALL",
    include_sections: str = "",
    db: Session = Depends(get_db),
):
    try:
        service = ReportService(db)
        filters = {
            "date_range": date_range,
            "honeypot": honeypot,
            "threat_level": threat_level,
            "protocol": protocol,
            "include_sections": include_sections,
        }
        return service.get_report_data(template_type, filters)
    except Exception as e:
        logger.error("Error generating report: %s", e)
        raise HTTPException(status_code=500, detail="Failed to generate report data.")


@router.post("/schedule", response_model=ScheduledReportResponse)
def schedule_report(report_data: ScheduledReportCreate, db: Session = Depends(get_db)):
    try:
        db_report = ScheduledReport(
            name=report_data.name,
            template_type=report_data.template_type,
            frequency=report_data.frequency,
            schedule_time=report_data.schedule_time,
            day_of_week=report_data.day_of_week,
            recipients=report_data.recipients,
            filters=str(report_data.filters),
            is_active=True,
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        return db_report
    except Exception as e:
        db.rollback()
        logger.error("Error scheduling report: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create scheduled report.")


@router.get("/schedules", response_model=List[ScheduledReportResponse])
def get_schedules(db: Session = Depends(get_db)):
    return db.query(ScheduledReport).order_by(ScheduledReport.id.desc()).all()


@router.delete("/schedule/{report_id}")
def delete_schedule(
    report_id: int = Path(..., ge=1, description="Report schedule database ID"),
    db: Session = Depends(get_db)
):
    db_report = (
        db.query(ScheduledReport).filter(ScheduledReport.id == report_id).first()
    )
    if not db_report:
        raise HTTPException(status_code=404, detail="Schedule not found")
    try:
        db.delete(db_report)
        db.commit()
        return {"status": "success", "message": "Schedule deleted"}
    except Exception as e:
        db.rollback()
        logger.error("Error deleting schedule %d: %s", report_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete report schedule.")


@router.put("/schedule/{report_id}", response_model=ScheduledReportResponse)
def update_schedule(
    report_id: int = Path(..., ge=1, description="Report schedule database ID"),
    report_data: ScheduledReportCreate = ...,
    db: Session = Depends(get_db)
):
    db_report = (
        db.query(ScheduledReport).filter(ScheduledReport.id == report_id).first()
    )
    if not db_report:
        raise HTTPException(status_code=404, detail="Schedule not found")

    try:
        db_report.name = report_data.name
        db_report.template_type = report_data.template_type
        db_report.frequency = report_data.frequency
        db_report.schedule_time = report_data.schedule_time
        db_report.day_of_week = report_data.day_of_week
        db_report.recipients = report_data.recipients
        db_report.filters = str(report_data.filters)

        db.commit()
        db.refresh(db_report)
        return db_report
    except Exception as e:
        db.rollback()
        logger.error("Error updating schedule %d: %s", report_id, e)
        raise HTTPException(status_code=500, detail="Failed to update report schedule.")
