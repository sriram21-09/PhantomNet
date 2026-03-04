from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import ScheduledReport
from services.report_service import ReportService
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])

class ScheduledReportCreate(BaseModel):
    name: str
    template_type: str
    frequency: str
    schedule_time: str
    recipients: str
    day_of_week: Optional[str] = "mon"
    filters: Optional[dict] = {}

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
    db: Session = Depends(get_db)
):
    service = ReportService(db)
    filters = {
        "date_range": date_range,
        "honeypot": honeypot,
        "threat_level": threat_level,
        "protocol": protocol,
        "include_sections": include_sections
    }
    return service.get_report_data(template_type, filters)

@router.post("/schedule", response_model=ScheduledReportResponse)
def schedule_report(report_data: ScheduledReportCreate, db: Session = Depends(get_db)):
    db_report = ScheduledReport(
        name=report_data.name,
        template_type=report_data.template_type,
        frequency=report_data.frequency,
        schedule_time=report_data.schedule_time,
        day_of_week=report_data.day_of_week,
        recipients=report_data.recipients,
        filters=str(report_data.filters),
        is_active=True
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report

@router.get("/schedules", response_model=List[ScheduledReportResponse])
def get_schedules(db: Session = Depends(get_db)):
    return db.query(ScheduledReport).all()

@router.delete("/schedule/{report_id}")
def delete_schedule(report_id: int, db: Session = Depends(get_db)):
    db_report = db.query(ScheduledReport).filter(ScheduledReport.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(db_report)
    db.commit()
    return {"message": "Schedule deleted"}

@router.put("/schedule/{report_id}", response_model=ScheduledReportResponse)
def update_schedule(report_id: int, report_data: ScheduledReportCreate, db: Session = Depends(get_db)):
    db_report = db.query(ScheduledReport).filter(ScheduledReport.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
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
