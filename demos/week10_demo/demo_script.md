# 🎥 PhantomNet Week 10 Demo Script
## Duration: ~10 minutes

---

## 1. Opening (0:00 – 0:30)
**Screen**: Dashboard landing page

"Welcome to the PhantomNet Week 10 demo. This week we delivered major features across SIEM integration, LSTM predictions, advanced topology, custom reporting, threat hunting, admin panel, and automated playbooks. Let me walk you through each."

---

## 2. SIEM Integration (0:30 – 1:30)
**Screen**: Admin Panel → Configuration → SIEM tab

- Show SIEM type selector (Splunk/Elasticsearch/QRadar/Custom)
- Configure endpoint URL and export frequency
- Save configuration
- Show real-time apply (no restart needed)
- "PhantomNet can push threat events to any SIEM at configurable intervals."

---

## 3. LSTM Threat Predictions (1:30 – 3:00)
**Screen**: Advanced NOC Dashboard → Predictive Analytics panel

- Show live threat forecast chart (historical + predicted)
- Highlight trend direction badge (RISING/FALLING/STABLE)
- Show risk score meter with aggregate threat level
- Show next attack prediction with LSTM-V3 model label
- Demonstrate live countdown timer (T-MINUS)
- "Our LSTM model predicts the next likely attack target with confidence scores."

---

## 4. 11-Honeypot Network Topology (3:00 – 4:00)
**Screen**: Topology page

- Show interactive network graph with all deployed honeypots
- Click nodes to see status, protocol, last activity
- Demonstrate real-time status indicators (online/offline)
- "We've scaled from 4 to 11 honeypot types across the network."

---

## 5. Custom Report Generation (4:00 – 5:30)
**Screen**: Advanced Analytics page

- Show analytics charts: MTTD/MTTR plots, attack trends
- Demonstrate PDF export functionality
- Demonstrate CSV data export
- Show report filtering by date range and threat level
- "Analysts can generate detailed reports for any time window."

---

## 6. Threat Hunting Interface (5:30 – 7:00)
**Screen**: Threat Hunting page

- Show advanced search with filters (IP, protocol, threat level, date range)
- Execute a search query
- Show event investigation — click to expand details
- Demonstrate case management: create a new case, add evidence
- Show IOC extraction from events
- "Full threat hunting workflow: search → investigate → case management."

---

## 7. Admin Panel & RBAC (7:00 – 8:30)
**Screen**: Admin Panel (/admin)

- Login with admin credentials
- **System Overview tab**: Show component status, resource usage, version info
- **User Management tab**: Create a new Analyst user, show role badges
- **Configuration tab**: Toggle auto-response, adjust ML threshold slider
- **Maintenance tab**: Trigger a database backup, show backup history
- "Role-based access control ensures Admins, Analysts, and Viewers see appropriate data."

---

## 8. Real-Time Event Stream (8:30 – 9:15)
**Screen**: Advanced NOC Dashboard

- Show live event stream with auto-scrolling
- Highlight color-coded threat levels (Critical/High/Medium/Low)
- Demonstrate pause/resume and sound toggle
- Show expanded event details with geo information
- "Every packet is scored, enriched, and streamed in under 2 seconds."

---

## 9. Closing (9:15 – 10:00)
**Screen**: Dashboard overview

- Recap all Week 10 features
- Show the improved Navbar with all 11 page links
- Mention upcoming Week 11 goals: multi-tenancy, compliance, mobile-responsive
- "PhantomNet is now a production-grade, AI-driven active defense platform. Thank you!"

---

## Demo Environment Setup

```bash
# Start backend
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload

# Start frontend (separate terminal)
cd frontend-dev/phantomnet-dashboard
npm run dev

# Access
# Dashboard: http://localhost:5173
# Admin:     http://localhost:5173/admin (admin / admin123)
# API Docs:  http://localhost:8000/docs
```

## Key Credentials
| Service | Username | Password |
|---------|----------|----------|
| Admin Panel | admin | admin123 |
