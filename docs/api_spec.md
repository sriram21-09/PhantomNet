
# PhantomNet – API Specification

## Base URL

`http://localhost:8000/api`

---

## Authentication

- No authentication in Phase 1
- All endpoints are public for controlled lab / test usage only
- Network access restricted at infrastructure level (not by token yet)

---

## Health Check

### GET `/health`

Basic service liveness probe.

**Response 200 (OK):**

```
{
  "status": "ok",
  "service": "phantomnet"
}
```

---

## Submit Attack Log

### POST `/logs`

Ingest a single attack / event log into the system.

**Request body (JSON):**

```
{
  "source_ip": "10.0.0.5",
  "protocol": "SSH",
  "details": "Failed login attempt"
}
```

- `source_ip` (string, required): Attacker IP address  
- `protocol` (string, required): One of `"SSH"`, `"HTTP"`, `"FTP"`, `"OTHER"`  
- `details` (string, required): Short description of the event  

**Response 201 (Created):**

```
{
  "message": "log stored successfully"
}
```

**Possible error responses:**

```
{
  "error": "invalid payload"
}
```

```
{
  "error": "internal server error"
}
```

---

## Fetch Logs

### GET `/logs`

Return a list of stored logs, optionally limited.

**Query parameters:**

- `limit` (integer, optional, default = 100): Max number of logs to return  
- `protocol` (string, optional): Filter by protocol (`SSH`, `HTTP`, `FTP`, `OTHER`)  

**Response 200 (OK):**

```
[
  {
    "id": 1,
    "source_ip": "10.0.0.5",
    "protocol": "SSH",
    "timestamp": "2025-12-13T10:00:00Z"
  }
]
```

**Possible error response:**

```
{
  "error": "internal server error"
}
```

---

## Global Error Format

All errors follow a common JSON structure:

```
{
  "error": "error message"
}
```

- `error` (string): Human-readable description of what went wrong.
```

You can paste this directly into `docs/api_spec.md` and commit it.
