from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session
from database.database import SessionLocal
from database.models import ScheduledReport
from services.report_service import ReportService
from datetime import datetime, timedelta
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

    def load_schedules(self):
        db = SessionLocal()
        try:
            reports = (
                db.query(ScheduledReport)
                .filter(ScheduledReport.is_active == True)
                .all()
            )
            for report in reports:
                self.add_report_job(report)
        finally:
            db.close()

    def add_report_job(self, report):
        trigger = self._get_trigger(
            report.frequency, report.schedule_time, report.day_of_week
        )
        self.scheduler.add_job(
            self.run_scheduled_report,
            trigger=trigger,
            args=[report.id],
            id=f"report_{report.id}",
            replace_existing=True,
        )
        logger.info(
            f"Added job for report {report.id} ({report.name}) at {report.schedule_time}"
        )

    def _get_trigger(self, frequency, schedule_time, day_of_week=None):
        hour, minute = map(int, schedule_time.split(":"))
        if frequency == "Daily":
            return CronTrigger(hour=hour, minute=minute)
        elif frequency == "Weekly":
            return CronTrigger(
                day_of_week=day_of_week or "mon", hour=hour, minute=minute
            )
        elif frequency == "Monthly":
            return CronTrigger(day=1, hour=hour, minute=minute)
        return CronTrigger(hour=hour, minute=minute)

    def run_scheduled_report(self, report_id):
        db = SessionLocal()
        try:
            report = (
                db.query(ScheduledReport)
                .filter(ScheduledReport.id == report_id)
                .first()
            )
            if not report:
                return

            logger.info(f"Running scheduled report: {report.name}")
            service = ReportService(db)
            filters = (
                json.loads(report.filters.replace("'", '"'))
                if isinstance(report.filters, str)
                else report.filters
            )
            data = service.get_report_data(report.template_type, filters)

            # Here we would generate the actual file (PDF/Excel) and email it.
            # For now, we simulation the "sent" status.
            logger.info(f"Simulating report delivery to: {report.recipients}")

            report.last_run = datetime.utcnow()
            # Update next_run if needed (APScheduler handles the next run, but we can store it for UI)
            db.commit()
        except Exception as e:
            logger.error(f"Error running scheduled report {report_id}: {e}")
        finally:
            db.close()


scheduler_service = SchedulerService()
