# PhantomNet Penetration Test Report – Week 8

## Overview
This report documents controlled penetration testing conducted against PhantomNet honeypots to validate attack detection and logging capabilities.

---

## SSH Brute-force Test
- Method: Repeated failed login attempts
- Result: Detected and logged
- Impact: None

## HTTP SQL Injection Test
- Method: Malicious input payloads
- Result: Detected and logged
- Impact: None

## SMTP Spam / Relay Test
- Method: Simulated spam email delivery
- Result: Payload captured, relay blocked
- Impact: None

---

## Conclusion
All simulated attack scenarios were successfully detected by PhantomNet honeypots. The system prevented exploitation, logged attacker behavior, and maintained isolation.

**Status:** Penetration testing completed successfully.
