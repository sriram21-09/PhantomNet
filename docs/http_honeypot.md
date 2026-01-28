# 📘  HTTP Documentation

## 📍 File: `docs/http_honeypot.md`


```markdown
# HTTP Honeypot Documentation

## File Location
backend/honeypots/http/http_honeypot.py

```md
# HTTP Honeypot – PhantomNet

## Purpose
The HTTP honeypot simulates a vulnerable web admin panel to capture:
- Credential stuffing
- Unauthorized access attempts
- Unsupported HTTP methods

## Port
- Listens on **port 8080**

## Endpoints
- /admin (fake admin login page)

## Supported Methods
- GET
- POST

## Blocked Methods
- PUT
- PATCH
- DELETE (returns 501)

## Behavior
- Displays realistic admin login page
- Always rejects credentials
- Logs request method, path, headers, and body

## Logged Fields
- timestamp
- honeypot_type: http
- source_ip
- method
- endpoint
- payload
- response_code

## Example Attack
```bash
curl -X POST http://localhost:8080/admin -d "username=admin&password=test"


Why This Matters :- 

Web attacks are the most common entry point.
This honeypot helps detect scanning and credential abuse patterns.