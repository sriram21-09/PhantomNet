import os
import time
from datetime import datetime, timedelta
from database import SessionLocal
from app_models import PacketLog
from sqlalchemy import text

# CONFIGURATION
ALERT_THRESHOLD_MINUTES = 5  # Alert if no data in last 5 mins
db = SessionLocal()

print("🩺 STARTING SYSTEM HEALTH CHECK...\n")

# ==========================================
# TASK 1: Confirm Pipeline Liveness (Logging/Monitoring)
# ==========================================
print("[CHECK 1] Verifying Pipeline Heartbeat...")
last_packet = db.query(PacketLog).order_by(PacketLog.timestamp.desc()).first()

if last_packet:
    time_diff = datetime.utcnow() - last_packet.timestamp
    print(f"   ℹ️  Last Packet Received: {last_packet.timestamp} (UTC)")
    print(f"   ℹ️  Time Since Last Event: {time_diff}")

    if time_diff < timedelta(minutes=ALERT_THRESHOLD_MINUTES):
        print("   ✅ STATUS: HEALTHY (Data is flowing)")
    else:
        print(f"   ❌ STATUS: CRITICAL (No data in >{ALERT_THRESHOLD_MINUTES} mins). Check Sniffer!")
else:
    print("   ❌ STATUS: CRITICAL (Database is empty). Pipeline Down.")

# ==========================================
# TASK 2: Check Metrics (Database Performance)
# ==========================================
print("\n[CHECK 2] Measuring Database Latency...")
start = time.time()
db.execute(text("SELECT 1"))
latency = (time.time() - start) * 1000

print(f"   📊 DB Response Time: {latency:.2f}ms")
if latency < 20:
    print("   ✅ Performance: EXCELLENT")
else:
    print("   ⚠️ Performance: SLOW (Optimize connection pool)")

# ==========================================
# TASK 3 & 4: Document Gaps & Proposals (Month 2)
# ==========================================
print("\n[CHECK 3] Generating Month 2 Roadmap...")

roadmap_content = """# 🚀 PhantomNet: Month 2 Roadmap

## 1. Identified Gaps (Month 1 Review)
- [ ] **Centralized Logging:** Logs currently print to console. Need to save to `app.log` file.
- [ ] **Alerting:** No email/SMS triggers when "Threat Score > 0.9".
- [ ] **Retention:** No automated cleanup script for old data.
- [ ] **UI Real-time:** Dashboard polls every 2s. Needs WebSockets for instant updates.

## 2. Month 2 Goals
### Week 1: Advanced Visualization
- Add "Attack Map" (World Map with live pings).
- Add "Protocol Distribution" Pie Chart.

### Week 2: Notification System
- Integrate SMTP (Email) or Twilio (SMS) for high-risk alerts.
- Create Slack/Discord Webhook integration.

### Week 3: Machine Learning V2
- Train model on real dataset (KDD Cup 99 or similar).
- Save/Load trained models to avoid retraining on restart.

### Week 4: Deployment
- Dockerize the application (Frontend + Backend + DB).
- Deploy to Cloud (AWS/DigitalOcean).
"""

filename = "MONTH_2_ROADMAP.md"
with open(filename, "w", encoding="utf-8") as f:
    f.write(roadmap_content)

print(f"   📄 Roadmap generated: {os.path.abspath(filename)}")
print("   ✅ Monitoring & Planning Complete.")

db.close()