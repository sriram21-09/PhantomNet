# PhantomNet – Final Project Summary

## Project Overview
PhantomNet is a multi-protocol honeypot framework designed to
capture, analyze, and log attacker behavior across SSH, HTTP, and FTP
services in a controlled and safe environment.

The project simulates realistic services without exposing real systems
or data.

---

## Implemented Honeypots

### SSH Honeypot
- Password-based authentication
- Realistic Linux shell simulation
- Command logging
- Connection limits and session timeouts

### HTTP Honeypot
- Fake admin portal
- Credential capture
- SQL injection detection
- Rate limiting and method monitoring

### FTP Honeypot
- Authenticated and anonymous access
- Directory and file enumeration simulation
- Exfiltration attempt detection (RETR blocked)
- Stable session handling

---

## Logging & Storage
- Structured JSON logs
- Log ingestion using PostgreSQL
- Deduplication using hash-based logic
- Centralized database: phantomnet_logs

---

## Testing Summary
- Full pytest-based test suite executed
- SSH, HTTP, and FTP tests passed
- Total tests: 13 / 13 PASSED
- Manual and automated performance testing completed

---

## Performance & Stability
- Honeypots ran concurrently without port conflicts
- No crashes or unhandled exceptions observed
- Stable under repeated requests and connections

---

## Security Design Decisions
- Honeypots observe attacker behavior without serving real data
- FTP RETR blocked to prevent exfiltration
- SQL injection attempts logged with high severity
- No real OS or filesystem access exposed

---

## Final Status
Project completed successfully.
PhantomNet is stable, tested, documented, and ready for further
enhancement or deployment in a SOC training environment.
