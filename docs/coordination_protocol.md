# Coordination Protocol — PhantomNet Honeypot Mesh

> **Week 9 · Day 1 Deliverable**
> Distributed coordination system enabling the PhantomNet honeypot mesh to share threat intelligence, maintain peer awareness, and coordinate responses across all protocol nodes.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Message Format Reference](#2-message-format-reference)
3. [Coordinator API Reference](#3-coordinator-api-reference)
4. [Client Usage Guide](#4-client-usage-guide)
5. [Deployment & Configuration](#5-deployment--configuration)
6. [Sequence Diagrams](#6-sequence-diagrams)
7. [Error Handling](#7-error-handling)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│               PhantomNet Coordinator                    │
│            (FastAPI · port 8001)                        │
│  ┌──────────┐ ┌────────────┐ ┌─────────────────────┐   │
│  │  /nodes  │ │  /threats  │ │  /register /event   │   │
│  │  /stats  │ │  blocklist │ │  /heartbeat /alert  │   │
│  └──────────┘ └────────────┘ └─────────────────────┘   │
└───────────────────────┬─────────────────────────────────┘
                        │  HTTP REST (JSON)
          ┌─────────────┼──────────────┐
          ▼             ▼              ▼
   ┌─────────────┐ ┌──────────────┐ ┌───────────────┐
   │  SSH Node   │ │  HTTP Node   │ │   FTP Node    │
   │  port 2222  │ │  port 8080   │ │   port 21     │
   │CoordClient  │ │CoordClient   │ │CoordClient    │
   └─────────────┘ └──────────────┘ └───────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Transport** | HTTP REST | Simple, stateless, firewall-friendly |
| **Message format** | JSON (Pydantic-validated) | Self-documenting, easy to log |
| **State store** | In-memory (dict/list) | Sufficient for honeypot scale; swap for Redis if needed |
| **Auth** | None (isolated network) | Honeypot mesh is inside a trusted private subnet |
| **Blocking** | Automatic on HIGH/CRITICAL alerts | Immediate threat response without manual intervention |

---

## 2. Message Format Reference

All messages are JSON objects sent in HTTP request/response bodies.

### 2.1 RegisterMessage

Sent by a honeypot node **on startup** to join the mesh.

```json
{
  "node_id":  "ssh-node-1",
  "host":     "127.0.0.1",
  "port":     2222,
  "protocol": "SSH",
  "version":  "1.0.0",
  "metadata": { "location": "zone-a" }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `node_id` | string | ✅ | Unique identifier for this node |
| `host` | string | ✅ | IP/hostname of the honeypot |
| `port` | integer (1–65535) | ✅ | Port the honeypot listens on |
| `protocol` | string | ✅ | Protocol served: SSH, HTTP, FTP, SMTP |
| `version` | string | — | Client version (default: `"1.0.0"`) |
| `metadata` | object | — | Optional extra info (location, tags, etc.) |

---

### 2.2 HeartbeatMessage

Sent **every 30 seconds** to signal the node is still alive.

```json
{
  "node_id":     "ssh-node-1",
  "timestamp":   "2026-02-22T10:00:00Z",
  "status":      "active",
  "event_count": 42,
  "cpu_percent": 12.5,
  "memory_mb":   64.0
}
```

| Field | Type | Description |
|---|---|---|
| `node_id` | string | Reporting node |
| `timestamp` | ISO-8601 UTC | Time of this heartbeat |
| `status` | string | `active` \| `degraded` \| `stopping` |
| `event_count` | integer | Cumulative events since startup |
| `cpu_percent` | float | Optional CPU usage |
| `memory_mb` | float | Optional memory usage |

---

### 2.3 EventMessage

Sent whenever the honeypot records **any interaction**.

```json
{
  "node_id":    "ssh-node-1",
  "timestamp":  "2026-02-22T10:01:00Z",
  "src_ip":     "10.0.0.5",
  "src_port":   54321,
  "dst_port":   2222,
  "protocol":   "SSH",
  "event_type": "login_attempt",
  "details": {
    "username": "root",
    "password": "123456"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `node_id` | string | Reporting node |
| `src_ip` | string | Attacker/scanner IP |
| `protocol` | string | Protocol triggered |
| `event_type` | string | `connection` \| `login_attempt` \| `command` \| `scan` |
| `details` | object | Protocol-specific payload |

---

### 2.4 AlertMessage

Sent for **high-severity** detections. HIGH and CRITICAL automatically blocklist `src_ip`.

```json
{
  "node_id":     "ssh-node-1",
  "timestamp":   "2026-02-22T10:02:00Z",
  "severity":    "HIGH",
  "src_ip":      "10.0.0.5",
  "description": "Brute force: 500 attempts in 60s",
  "alert_type":  "brute_force",
  "details": {
    "attempts": 500,
    "window_seconds": 60
  }
}
```

| Field | Type | Description |
|---|---|---|
| `severity` | string | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `alert_type` | string | `brute_force` \| `scan` \| `exploit` \| `anomaly` |
| `description` | string | Human-readable summary |

---

### 2.5 DeregisterMessage

Sent by a node **on graceful shutdown**.

```json
{
  "node_id": "ssh-node-1",
  "reason":  "graceful_shutdown"
}
```

---

## 3. Coordinator API Reference

Base URL: `http://<coordinator_host>:8001`
Interactive docs: `http://<coordinator_host>:8001/docs`

| Endpoint | Method | Description | Auth |
|---|---|---|---|
| `/` | GET | Health check | None |
| `/stats` | GET | Aggregate statistics | None |
| `/register` | POST | Join the mesh | None |
| `/heartbeat` | POST | Signal liveness | None |
| `/event` | POST | Report capture event | None |
| `/alert` | POST | Report high-severity alert | None |
| `/nodes` | GET | List all nodes (`?active_only=true`) | None |
| `/threats` | GET | Get shared threat intel | None |
| `/deregister` | POST | Leave the mesh | None |

### Response: `/threats`

```json
{
  "blocked_ips":       ["10.0.0.5", "192.168.1.99"],
  "high_severity_ips": ["10.0.0.5"],
  "recent_alerts":     [...],
  "total_events":      142,
  "last_updated":      "2026-02-22T10:05:00Z"
}
```

### Response: `/nodes`

```json
{
  "total": 3,
  "nodes": [
    {
      "node_id": "ssh-node-1",
      "host": "127.0.0.1",
      "port": 2222,
      "protocol": "SSH",
      "status": "active",
      "event_count": 42,
      "registered_at": "2026-02-22T09:00:00Z",
      "last_heartbeat": "2026-02-22T10:04:30Z"
    }
  ]
}
```

---

## 4. Client Usage Guide

### 4.1 Async Usage (Recommended)

```python
import asyncio
from honeypots.client import CoordinatorClient

async def run_honeypot():
    async with CoordinatorClient(
        node_id="ssh-node-1",
        host="0.0.0.0",
        port=2222,
        protocol="SSH",
        coordinator_url="http://coordinator:8001",
    ) as client:
        # Start background heartbeat
        client.start_heartbeat_task(interval=30)

        # Report events as they arrive
        await client.report_event(
            src_ip="10.0.0.5",
            event_type="login_attempt",
            details={"username": "root", "password": "qwerty"},
        )

        # Raise an alert for brute force
        await client.report_alert(
            src_ip="10.0.0.5",
            description="Brute force: 100 attempts in 60s",
            severity="HIGH",
            alert_type="brute_force",
        )

        # Poll threat intel & check if an IP is blocked
        threats = await client.get_threats()
        if "10.0.0.5" in threats["blocked_ips"]:
            print("IP is already known-bad — dropping connection")

asyncio.run(run_honeypot())
```

### 4.2 Synchronous Usage (Legacy Honeypots)

```python
from honeypots.client import SyncCoordinatorClient

client = SyncCoordinatorClient(
    node_id="ftp-node-1",
    host="0.0.0.0",
    port=21,
    protocol="FTP",
)
client.register()
client.report_event(src_ip="192.168.1.10", event_type="connection")
client.deregister()
client.close()
```

### 4.3 Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `coordinator_url` | `http://127.0.0.1:8001` | Coordinator base URL |
| `heartbeat_interval` | `30` | Heartbeat frequency (seconds) |
| `max_retries` | `3` | Retry attempts with exponential backoff |
| `timeout` | `10.0` | HTTP request timeout (seconds) |

---

## 5. Deployment & Configuration

### Running the Coordinator

```bash
# Development (auto-reload)
uvicorn backend.services.coordinator:app --host 0.0.0.0 --port 8001 --reload

# Production
uvicorn backend.services.coordinator:app --host 0.0.0.0 --port 8001 --workers 2
```

### Docker (add to docker-compose.yml)

```yaml
coordinator:
  build: ./backend
  command: uvicorn services.coordinator:app --host 0.0.0.0 --port 8001
  ports:
    - "8001:8001"
  environment:
    - PYTHONUNBUFFERED=1
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `COORDINATOR_HOST` | `0.0.0.0` | Bind address |
| `COORDINATOR_PORT` | `8001` | Listen port |
| `HEARTBEAT_TIMEOUT` | `120` | Seconds before node is considered dead |

---

## 6. Sequence Diagrams

### Node Startup

```
Honeypot          Coordinator
   |                   |
   |--- POST /register ->|
   |<-- 201 {node, peers}|
   |                   |
   |  (every 30s)      |
   |--- POST /heartbeat->|
   |<-- 200 {ack}      |
```

### Alert & Threat Sharing

```
Node-A      Coordinator     Node-B
  |              |              |
  |--POST /alert->|              |
  |              | (blocklist IP)|
  |<--201 {blocked}|             |
  |              |              |
  |              |<-GET /threats-|
  |              |--{blocked_ips}->|
  |              |   Node-B drops IP|
```

---

## 7. Error Handling

| Status | Meaning | When |
|---|---|---|
| `201` | Created | Successful register / event / alert |
| `200` | OK | Heartbeat, list, threats, deregister |
| `404` | Not Found | Unknown `node_id` in heartbeat/event/alert/deregister |
| `422` | Validation Error | Malformed JSON or missing required fields |
| `500` | Server Error | Unexpected coordinator failure |

### Client Retry Policy

The `CoordinatorClient` uses **exponential backoff** with up to 3 retries:

| Attempt | Delay before retry |
|---|---|
| 1 | — |
| 2 | 1 s |
| 3 | 2 s |

After 3 failures the exception is re-raised so the honeypot can decide whether to continue capturing or shut down gracefully.
