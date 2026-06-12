---
milestone: Month 4 – Sentinel Core
version: 4.0.0
updated: 2026-06-12T19:30:00Z
---

# Roadmap

> **Current Phase:** 4 - Sentinel Core Rollout Automation
> **Status:** planning

## Must-Haves (from SPEC)

- [ ] Complete automation of week 14 tasks & issues setup.
- [ ] Ensure 100% synchronization of Project Board fields (Day, Role, Type).
- [ ] Clean isolation of honeypot logs to prevent pollution of production metrics.

---

## Phases

### Phase 1: Deception Layer
**Status:** ✅ Complete
**Objective:** Deception honeypot integration (SSH, HTTP, FTP, SMTP) that record attacker traffic.

---

### Phase 2: ML Engine & Inference
**Status:** ✅ Complete
**Objective:** ML Model inference pipeline (Random Forest, Isolation Forest, LSTM, SHAP explainability) for traffic scoring.

---

### Phase 3: Observability Layer
**Status:** ✅ Complete
**Objective:** Web dashboard UI displaying topology, maps, and event streams.

---

### Phase 4: Sentinel Core Rollout & Automation
**Status:** 🔄 In Progress
**Objective:** Automate weekly sprint issue creation and project board synchronization using a config template and engine.

**Plans:**
- [ ] Plan 4.1: Install GSD Workflows and Map Codebase
- [ ] Plan 4.2: Configure `week14_config.json`
- [ ] Plan 4.3: Execute and Verify Sprint Automation Run

---

## Progress Summary

| Phase | Status | Plans | Complete |
|-------|--------|-------|----------|
| 1 | ✅ | 1/1 | 100% |
| 2 | ✅ | 1/1 | 100% |
| 3 | ✅ | 1/1 | 100% |
| 4 | 🔄 | 0/3 | 33% |

---

## Timeline

| Phase | Started | Completed | Duration |
|-------|---------|-----------|----------|
| 1 | 2026-05-01 | 2026-05-15 | 14 days |
| 2 | 2026-05-16 | 2026-05-30 | 14 days |
| 3 | 2026-06-01 | 2026-06-10 | 10 days |
| 4 | 2026-06-12 | — | — |
