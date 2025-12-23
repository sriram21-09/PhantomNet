# PhantomNet Frontend – API Mapping

## Dashboard APIs

GET /api/stats
Used in:
- Dashboard.jsx
Displays:
- Total Events
- Unique IPs
- Active Honeypots
- Avg Threat Score

## Events APIs

GET /api/events
Used in:
- Events.jsx
Fields:
- timestamp
- source_ip
- protocol
- port
- details
- threat_level

## Polling Strategy
- Frontend will fetch data every 10 seconds
- Prevents page reload