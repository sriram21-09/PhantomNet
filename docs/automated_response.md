# PhantomNet — Automated Response System

**Week 9 | Day 5 — Automated Threat Response**  
**Last Updated:** February 27, 2026

---

## Overview

PhantomNet's automated response system executes defensive actions based on threat level thresholds. The response executor integrates directly with the threat scoring pipeline — when the analyzer scores a packet as HIGH or CRITICAL, it automatically triggers blocking, scaling, and alerting.

```
Threat Analyzer (background loop)
       │ scores packet
       ▼
  ┌─────────────┐
  │ Score HIGH?  │───No──→ Log only
  │ or CRITICAL? │
  └──────┬──────┘
         │ Yes
         ▼
  ResponseExecutor.execute()
         │
    ┌────┼────┬──────────┐
    ▼    ▼    ▼          ▼
  Block  Rate  Scale    Notify
  IP     Limit Honeypots Admin
```

---

## Response Actions Matrix

| Threat Level | Score | Actions | Block Duration |
|-------------|-------|---------|----------------|
| **LOW** | 0–39 | Log | — |
| **MEDIUM** | 40–69 | Log, Alert, Rate Limit | — |
| **HIGH** | 70–89 | Log, Alert, IP Block, Scale Honeypots | 30 min (temp) |
| **CRITICAL** | 90–100 | Log, Alert, IP Block, Scale, Admin Notify | Permanent |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/response/history` | View response audit log |
| `GET` | `/api/response/blocked-ips` | List currently blocked IPs |
| `POST` | `/api/response/unblock/{ip}` | Manual unblock |
| `GET` | `/api/response/policy` | View current policy |
| `PUT` | `/api/response/policy` | Update policy thresholds |
| `GET` | `/api/response/stats` | Response system statistics |

### Example: View Blocked IPs

```json
GET /api/response/blocked-ips

{
  "status": "success",
  "count": 2,
  "blocked_ips": [
    {
      "ip": "192.168.1.100",
      "blocked_at": "2026-02-27T10:30:00",
      "expires_at": "2026-02-27T11:00:00",
      "reason": "Automated: HIGH threat",
      "level": "HIGH"
    }
  ]
}
```

### Example: Update Policy

```json
PUT /api/response/policy
{
  "HIGH": { "block_duration_minutes": 60 },
  "CRITICAL": { "enabled": true }
}
```

---

## IP Blocking (Cross-Platform)

| Platform | Command | Notes |
|----------|---------|-------|
| **Linux** | `sudo iptables -A INPUT -s {ip} -j DROP` | Requires sudo |
| **Windows** | `netsh advfirewall firewall add rule name=... action=block` | Requires admin |

**Auto-expiry:** Temporary blocks are automatically removed by a background cleanup thread that runs every 60 seconds.

**Whitelist:** `127.0.0.1`, `::1`, `10.0.0.1`, `phantomnet_postgres` are never blocked.

---

## Threat Pipeline Integration

The response executor is triggered automatically inside `threat_analyzer.py`:

```python
# In _process_unscored_logs(), after scoring:
if result.threat_level in ["HIGH", "CRITICAL"]:
    response_executor.execute(
        ip=log.src_ip,
        threat_score=result.score * 100,
        threat_level=result.threat_level,
        protocol=log.protocol,
        details=f"Auto-detected: {result.decision}"
    )
```

---

## Files

| File | Type | Purpose |
|------|------|---------|
| `backend/services/response_executor.py` | NEW | Automated response engine |
| `backend/services/threat_analyzer.py` | MODIFIED | Response trigger integration |
| `backend/main.py` | MODIFIED | 6 response management endpoints |
