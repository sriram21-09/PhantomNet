# 📘  HTTP Documentation

## 📍 File: `docs/http_honeypot.md`


```markdown
# HTTP Honeypot Documentation

## File Location
backend/honeypots/http/http_honeypot.py

---

## Purpose
The HTTP honeypot simulates an internal admin portal to:
- Capture credentials
- Detect SQL injection attempts
- Monitor malicious HTTP methods

---

## Available Endpoints
/admin (GET) – Admin login page  
/admin (POST) – Credential capture  
/forgot-password (GET) – Reset page  
/forgot-password (POST) – Email capture  
/admin (PUT) – Returns 403  
/admin (DELETE) – Returns 404  

---

## SQL Injection Detection
Detects patterns like:
- ' OR 1=1--
- UNION SELECT
- --

Logged as:
event: sqli_attempt  
level: ERROR

---

## Logging Example
```json
{
  "timestamp": "2025-01-01T11:05:44Z",
  "source_ip": "192.168.1.20",
  "honeypot_type": "http",
  "event": "login_attempt",
  "method": "POST",
  "path": "/admin",
  "data": {
    "username": "admin",
    "password": "1234"
  },
  "level": "WARN"
}

Security Notes

No real authentication backend

Rate limiting per IP

Clean HTTP responses only