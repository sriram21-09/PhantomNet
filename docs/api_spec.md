# PhantomNet – API Specification

## Base URL
http://localhost:8000/api

yaml
Copy code

## Authentication
- No authentication (Phase 1)
- Public endpoints for controlled lab use

---

## Health Check
**GET** `/health`

Response:
```json
{
  "status": "ok",
  "service": "phantomnet"
}
Submit Attack Log
POST /logs

Request:

json
Copy code
{
  "source_ip": "10.0.0.5",
  "protocol": "SSH",
  "details": "Failed login attempt"
}
Response:

json
Copy code
{
  "message": "log stored successfully"
}
Fetch Logs
GET /logs

Response:

json
Copy code
[
  {
    "id": 1,
    "source_ip": "10.0.0.5",
    "protocol": "SSH",
    "timestamp": "2025-12-13T10:00:00"
  }
]
Error Format (Global)
json
Copy code
{
  "error": "error message"
}

Commit:
```
