# PhantomNet Risk Log

## Purpose
Track technical and operational risks identified during verification.

---

## Active Risks

### R-001: High Event Volume
- Description: Sniffer generates large number of benign events
- Severity: Medium
- Impact: DB growth, UI load
- Mitigation: Add sampling / demo throttle

---

### R-002: Port Information Missing
- Description: L4 port currently set to 0
- Severity: Low
- Impact: Reduced forensic detail
- Mitigation: Extract TCP/UDP port in Week 4

---

### R-003: Avg Threat Score Not Implemented
- Description: Dashboard avgThreatScore placeholder
- Severity: Low
- Impact: Incomplete dashboard metric
- Mitigation: Aggregate threat_score in StatsService

---

### R-004: No Rate Limiting
- Description: API has no rate limits
- Severity: Medium
- Impact: Abuse risk
- Mitigation: Add rate limiting middleware
