# 🧠 AI/ML Schema & Pipeline Design (Issue #8)

## 1. New Fields Definition
To support the ML Threat Scoring model, we are adding the following fields to the PostgreSQL schema.

### A. Update `events` Table (Raw Data)
| Field | Type | Description |
| :--- | :--- | :--- |
| **`src_port`** | `Integer` | The source port used by the attacker (e.g., 5555). |
| **`honeypot_type`** | `String` | The specific honeypot service (e.g., "Cowrie", "Dionaea"). |

### B. Update `sessions` Table (ML Targets)
| Field | Type | Description |
| :--- | :--- | :--- |
| **`threat_score`** | `Float` | A score from 0.0 (Safe) to 100.0 (Critical). |
| **`ml_analyzed`** | `Boolean` | Flag indicating if ML inference has run on this session. |

---

## 2. Feature Storage Strategy
We will use a **Hybrid Storage Strategy**:
* **Core Metrics:** Stored as standard columns (`threat_score`).
* **Dynamic Features:** Stored in a JSONB column (`features`) to allow flexible retraining without database migrations.

---

## 3. Ingestion & ML Flow
1.  **Honeypot** sends log payload to `POST /api/logs`.
2.  **API** validates and inserts raw log into `events` table.
3.  **Background Worker** aggregates events into a `Session`.
4.  **ML Engine** polls for un-analyzed sessions, calculates `threat_score`, and updates the DB.