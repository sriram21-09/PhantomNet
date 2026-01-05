# 🚀 PhantomNet: Month 2 Roadmap

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
