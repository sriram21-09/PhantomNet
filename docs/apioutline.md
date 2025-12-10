# PhantomNet API Endpoints

## Health Check
**GET** `/health`

Response:
```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2025-12-10T09:45:30.123456"
}

2. Get Events

GET /events?limit=10&hours=24

Query Parameters:

limit (int, optional, default = 10)

hours (int, optional, default = 24)

Response:
[
  {
    "id": 1,
    "timestamp": "2025-12-10T09:45:30",
    "srcip": "192.168.1.100",
    "dstport": 2222,
    "username": "root",
    "status": "failed",
    "threatscore": 50.0
  }
]

3. Get Statistics

GET /stats

Response:
{
  "total_events": 120,
  "unique_ips": 45,
  "avg_threat": 42.5,
  "max_threat": 97.0
}

4. Get Threat Level

GET /threat-level

Response:
{
  "level": "MEDIUM",
  "color": "yellow"
}

