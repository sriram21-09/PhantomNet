
# PhantomNet API Design

## Base URL
http://localhost:8000

## Authentication
JWT Bearer Token in Authorization header

## Endpoints

### Health Check
- **GET /health**
  Response: `{"status": "healthy"}`

### Events
- **GET /api/events**
  Returns list of all attack events

- **GET /api/events/{id}**
  Returns specific event details

- **POST /api/events**
  Create new event (internal only)

### Statistics
- **GET /api/stats/summary**
  Dashboard statistics

- **GET /api/threat-level**
  Current threat level (0-100)

### Sessions
- **GET /api/sessions**
  List attack sessions

[Continue with all endpoints...]
