# API Requirements – PhantomNet Dashboard

## Dashboard Stats API

### Endpoint
GET /api/stats

### Response
{
  "totalEvents": number,
  "uniqueIPs": number,
  "activeHoneypots": number,
  "avgThreatScore": number,
  "criticalAlerts": number
}

### Usage
Used to populate MetricCards on Dashboard page.

---

## Events API

### Endpoint
GET /api/events

### Response
[
  {
    "time": "ISO timestamp",
    "ip": "string",
    "type": "HTTP | SSH | FTP | TELNET",
    "port": number,
    "details": "string"
  }
]

### Usage
Used in Events page for:
- Filtering
- Threat classification
- Table rendering