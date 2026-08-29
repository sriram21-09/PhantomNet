import os
import sys

# Windows UTF-8 console output fix
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure backend modules can be imported
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from database.database import SessionLocal, engine
from database.models import (
    PacketLog,
    Alert,
    Event,
    AttackSession,
    TrafficStats,
    IOC,
    SearchHistory,
    PcapCapture,
    InvestigationCase,
    CaseEvidence,
)
from sentinel.models import SentinelPlaybook, SentinelAuditLog

def clear_active_database():
    print("[*] Connecting to active PhantomNet database...")
    db = SessionLocal()

    models_to_clear = [
        ("Sentinel Audit Logs", SentinelAuditLog),
        ("Sentinel Playbooks", SentinelPlaybook),
        ("Case Evidence", CaseEvidence),
        ("Investigation Cases", InvestigationCase),
        ("PCAP Captures", PcapCapture),
        ("Search History", SearchHistory),
        ("IOCs", IOC),
        ("Events", Event),
        ("Attack Sessions", AttackSession),
        ("Alerts", Alert),
        ("Traffic Stats", TrafficStats),
        ("Packet Logs", PacketLog),
    ]

    total_deleted = 0
    for name, model in models_to_clear:
        try:
            count = db.query(model).delete()
            total_deleted += count
            print(f"  [-] Cleared {count:5d} records from {name}")
        except Exception as e:
            print(f"  [!] Skipping {name}: {e}")

    db.commit()
    db.close()
    print(f"\n[OK] Database cleared completely! (Total records wiped: {total_deleted})")

if __name__ == "__main__":
    clear_active_database()


