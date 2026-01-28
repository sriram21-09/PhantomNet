# Honeypot Validation – Week 6

## Objective
Validate all honeypots, ensure log consistency, and prepare ML-ready data.

---

## Honeypot Testing Summary

| Honeypot | Port | Status | Notes |
|--------|------|--------|------|
| SSH | 2222 | ✅ Pass | AsyncSSH logs normalized |
| HTTP | 8080 | ✅ Pass | JSON logs |
| FTP | 2121 | ⚠ Partial | 90% JSON, LIST edge case |
| SMTP | 2525 | ✅ Pass | Full email capture |

---

## Data Quality Results

| Honeypot | Valid JSON % |
|--------|-------------|
| HTTP | 100% |
| SMTP | 100% |
| FTP | 90% |
| SSH | 100% (structured fields) |

---

## Normalization

- Unified schema implemented
- Missing raw_data handled
- Invalid IP and timestamps rejected
- 100/100 events normalized successfully

---

## Dataset Export

- File: data/week6_base_events.csv
- Events: 200
- Fields:
  - event_id
  - honeypot_type
  - src_ip
  - port
  - created_at
  - raw_data

---

## Issues Identified

- FTP LIST passive mode causes stalled connections
- FTP JSON completeness below target
- SSH logs lacked raw_data field (resolved in normalization)

---

## Conclusion

Week 6 objectives completed.
System ready for ML feature engineering.
